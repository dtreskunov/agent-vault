package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/blindtunnel"
	"github.com/Infisical/agent-vault/internal/headless"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

type managedFixture struct {
	t                    *testing.T
	s                    *Server
	db                   *store.SQLStore
	token, user, library string
}

func newManagedFixture(t *testing.T, baseURLs ...string) *managedFixture {
	t.Helper()
	t.Setenv("AGENT_VAULT_HEADLESS", "true")
	db, err := store.Open(filepath.Join(t.TempDir(), "connections.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	_, session, err := db.CreateAgentWithGrantsAndToken(context.Background(), headless.AgentName, "", "owner", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://127.0.0.1:14321"
	if len(baseURLs) != 0 {
		baseURL = baseURLs[0]
	}
	s := New("127.0.0.1:0", db, make([]byte, 32), notify.New(nil), true, baseURL, slog.New(slog.DiscardHandler))
	f := &managedFixture{t: t, s: s, db: db, token: session.ID}
	w := f.call("PUT", "/v1/managed-users", `{"installation_id":"install","subject":"owner","display_name":"Owner","active":true,"role":"no-access","vault_grants":[{"vault":"group-one","role":"admin"},{"vault":"group-two","role":"admin"}]}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var mapped store.ManagedUserResult
	if err = json.Unmarshal(w.Body.Bytes(), &mapped); err != nil {
		t.Fatal(err)
	}
	f.user, f.library = mapped.ID, mapped.LibraryVault
	return f
}
func (f *managedFixture) call(method, path, body, rev string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+f.token)
	if rev != "" {
		r.Header.Set("If-Match", rev)
	}
	w := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(w, r)
	return w
}
func (f *managedFixture) base() string { return "/v1/managed-users/" + f.user }
func (f *managedFixture) create(body string) *connection {
	f.t.Helper()
	w := f.call("POST", f.base()+"/connections", body, "")
	if w.Code != 201 {
		f.t.Fatal(w.Code, w.Body)
	}
	if strings.Contains(w.Body.String(), "synthetic-") {
		f.t.Fatal("connection revealed credential value")
	}
	var c connection
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		f.t.Fatal(err)
	}
	if c.Revision == "" || w.Header().Get("ETag") != c.Revision {
		f.t.Fatal("missing connection ETag")
	}
	return &c
}

const basicConnection = `{"label":"Basic pair","kind":"static","values":{"USERNAME":"synthetic-user","PASSWORD":"synthetic-password"},"services":[{"name":"basic-api","host":"api.example.com/v1/*","auth":{"type":"basic","username":"USERNAME","password":"PASSWORD"}}]}`

func TestManagedConnectionStaticSharingAndAuthorization(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	c := f.create(basicConnection)
	route := f.base() + "/connections/" + c.ID
	if c.Owner.ID != f.user || c.Status != "ready" || len(c.Credentials) != 2 || len(c.Grants) != 0 {
		t.Fatal("unexpected connection metadata")
	}
	for _, group := range []string{"group-one", "group-two"} {
		w := f.call("PUT", route+"/grants/"+group, `{}`, "")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		v, _ := f.db.GetVault(ctx, group)
		mode, err := f.s.GatewayConnectPolicy(func(context.Context, string, string, int) (blindtunnel.Mode, error) { return blindtunnel.Tunnel, nil })(ctx, v.ID, "api.example.com", 443)
		if err != nil || mode != blindtunnel.MITM {
			t.Fatal("shared binding bypassed TLS interception", mode, err)
		}
		result, err := f.s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/v1/items")
		if err != nil || result.Headers["Authorization"] != "Basic c3ludGhldGljLXVzZXI6c3ludGhldGljLXBhc3N3b3Jk" {
			t.Fatal("shared basic pair not resolved", err)
		}
	}
	if w := f.call("PUT", route+"/grants/group-one", `{}`, ""); w.Code != 409 {
		t.Fatal("create-only grant replay accepted", w.Code)
	}
	c, err := f.s.loadConnection(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.call("PUT", route, `{"values":{"PASSWORD":"synthetic-rotated"}}`, ""); w.Code != 428 {
		t.Fatal("rotation without revision accepted", w.Code)
	}
	if w := f.call("PUT", route, `{"values":{"PASSWORD":"synthetic-rotated"}}`, `"stale"`); w.Code != 412 {
		t.Fatal("stale rotation accepted", w.Code)
	}
	rotated := f.call("PUT", route, `{"values":{"PASSWORD":"synthetic-rotated"}}`, c.Revision)
	if rotated.Code != 200 {
		t.Fatal(rotated.Code, rotated.Body)
	}
	var next connection
	json.Unmarshal(rotated.Body.Bytes(), &next)
	for _, group := range []string{"group-one", "group-two"} {
		v, _ := f.db.GetVault(ctx, group)
		result, err := f.s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/v1/items")
		if err != nil || result.Headers["Authorization"] != "Basic c3ludGhldGljLXVzZXI6c3ludGhldGljLXJvdGF0ZWQ=" {
			t.Fatal("rotation did not affect all references", err)
		}
	}
	// Synchronization with unchanged native memberships must not suspend grants.
	w := f.call("PUT", "/v1/managed-users", `{"installation_id":"install","subject":"owner","email":"renamed@example.com","active":true,"role":"no-access","vault_grants":[{"vault":"group-one","role":"admin"},{"vault":"group-two","role":"admin"}]}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	v, _ := f.db.GetVault(ctx, "group-one")
	if _, err := f.s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/v1/items"); err != nil {
		t.Fatal("idempotent reconciliation suspended grant", err)
	}
	other, err := f.db.ReconcileManagedUser(ctx, store.ManagedUserInput{InstallationID: "install", Subject: "receiver", Active: true, Role: "owner", VaultGrants: []store.ManagedVaultGrant{{Vault: "group-one", Role: "admin"}}})
	if err != nil {
		t.Fatal(err)
	}
	otherRoute := "/v1/managed-users/" + other.ID + "/connections/" + c.ID
	if w = f.call("GET", otherRoute, "", ""); w.Code != 403 {
		t.Fatal("receiver gained owner read", w.Code)
	}
	if w = f.call("PUT", otherRoute, `{"label":"retarget"}`, next.Revision); w.Code != 403 {
		t.Fatal("receiver gained rotation", w.Code)
	}
	if w = f.call("PUT", otherRoute+"/grants/group-one", `{}`, next.Revision); w.Code != 403 {
		t.Fatal("receiver reshared connection", w.Code)
	}
	access := f.call("GET", "/v1/managed-users/"+other.ID+"/vaults/group-one/access", "", "")
	if access.Code != 200 || strings.TrimSpace(access.Body.String()) != `{"grants":[]}` {
		t.Fatal("recipient administrator saw another owner's connection metadata", access.Code, access.Body)
	}
	allowed, err := f.s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/v1/items")
	if err != nil {
		t.Fatal(err)
	}
	if w = f.call("DELETE", "/v1/managed-users/"+other.ID+"/vaults/group-one/access/"+c.ID, "", ""); w.Code != 204 {
		t.Fatal("destination admin could not detach", w.Code, w.Body)
	}
	if err = allowed.Authorize(ctx); err == nil {
		t.Fatal("accepted operation retained revoked authorization")
	}
	if _, err = f.s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/v1/items"); err == nil {
		t.Fatal("revocation fell through to passthrough")
	}
	second, _ := f.db.GetVault(ctx, "group-two")
	if _, err = f.s.CredentialProvider().Inject(ctx, second.ID, "api.example.com", 443, "/v1/items"); err != nil {
		t.Fatal("detach affected another group", err)
	}
	if w = f.call("GET", route, "", ""); w.Code != 200 {
		t.Fatal("detach deleted source connection")
	}
	if w = f.call("DELETE", "/v1/vaults/group-two", "", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w = f.call("GET", route, "", ""); w.Code != 200 {
		t.Fatal("group deletion removed connection")
	}
}

func TestManagedConnectionAccessIsOwnerOnly(t *testing.T) {
	for _, role := range []string{"no-access", "owner"} {
		t.Run(role, func(t *testing.T) {
			f := newManagedFixture(t)
			ctx := context.Background()
			first := f.create(basicConnection)
			if w := f.call("PUT", f.base()+"/connections/"+first.ID+"/grants/group-one", `{}`, ""); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			other, err := f.db.ReconcileManagedUser(ctx, store.ManagedUserInput{
				InstallationID: "install", Subject: "other", Active: true, Role: role,
				VaultGrants: []store.ManagedVaultGrant{{Vault: "group-one", Role: "admin"}},
			})
			if err != nil {
				t.Fatal(err)
			}
			base := "/v1/managed-users/" + other.ID
			body := strings.NewReplacer("Basic pair", "Other private pair", "api.example.com", "other.example.com", "basic-api", "other-api").Replace(basicConnection)
			w := f.call("POST", base+"/connections", body, "")
			if w.Code != 201 {
				t.Fatal(w.Code, w.Body)
			}
			var second connection
			if err := json.Unmarshal(w.Body.Bytes(), &second); err != nil {
				t.Fatal(err)
			}
			if w := f.call("PUT", base+"/connections/"+second.ID+"/grants/group-one", `{}`, ""); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			for _, principal := range []struct{ base, own, hidden string }{
				{f.base(), first.ID, second.ID}, {base, second.ID, first.ID},
			} {
				for _, endpoint := range []string{"/connections", "/vaults/group-one/access"} {
					w := f.call("GET", principal.base+endpoint, "", "")
					if w.Code != 200 || !strings.Contains(w.Body.String(), principal.own) || strings.Contains(w.Body.String(), principal.hidden) {
						t.Fatal("connection metadata escaped its owner", w.Code, w.Body)
					}
				}
			}
			v, err := f.db.GetVault(ctx, "group-one")
			if err != nil {
				t.Fatal(err)
			}
			for _, host := range []string{"api.example.com", "other.example.com"} {
				if _, err := f.s.CredentialProvider().Inject(ctx, v.ID, host, 443, "/v1/items"); err != nil {
					t.Fatal("metadata privacy revoked authorized runtime use", err)
				}
			}
		})
	}
}

func TestManagedConnectionGrantSuspensionConflictAndNativeDisable(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	c := f.create(basicConnection)
	route := f.base() + "/connections/" + c.ID
	if w := f.call("PUT", route+"/grants/group-one", `{}`, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := f.call("PUT", route+"/grants/"+f.library, `{}`, ""); w.Code != 404 {
		t.Fatal("personal library was a grant recipient", w.Code)
	}
	if w := f.call("PUT", route+"/grants/default", `{}`, ""); w.Code != 404 {
		t.Fatal("system vault was a grant recipient", w.Code)
	}
	second := f.create(strings.Replace(basicConnection, `"Basic pair"`, `"Conflicting pair"`, 1))
	if w := f.call("PUT", f.base()+"/connections/"+second.ID+"/grants/group-one", `{}`, ""); w.Code != 409 {
		t.Fatal("overlapping destination accepted", w.Code, w.Body)
	}
	v, _ := f.db.GetVault(ctx, "group-one")
	if err := f.db.GrantVaultRole(ctx, f.user, "user", v.ID, "proxy"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/v1/x"); err == nil {
		t.Fatal("native role downgrade did not revoke use")
	}
	if err := f.db.GrantVaultRole(ctx, f.user, "user", v.ID, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/v1/x"); err == nil {
		t.Fatal("restored membership silently reactivated suspended grant")
	}
	c, err := f.s.loadConnection(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if w := f.call("PUT", route+"/grants/group-one", `{}`, c.Revision); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	c, err = f.s.loadConnection(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Recipients follow the connection's updated destinations without reapproval.
	w := f.call("PUT", route, `{"services":[{"name":"basic-api","host":"other.example.com/v1/*","auth":{"type":"basic","username":"USERNAME","password":"PASSWORD"}}]}`, c.Revision)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if result, err := f.s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/v1/x"); err == nil && result != nil &&
		(len(result.CredentialKeys) > 0 || result.Headers["Authorization"] != "") {
		t.Fatal("removed URL rule still received credentials")
	}
	if _, err := f.s.CredentialProvider().Inject(ctx, v.ID, "other.example.com", 443, "/v1/x"); err != nil {
		t.Fatal("grant did not follow the updated destination", err)
	}
	user, _ := f.db.GetUserByID(ctx, f.user)
	_, err = f.db.ReconcileManagedUser(ctx, store.ManagedUserInput{InstallationID: user.InstallationID, Subject: user.Subject, Active: false, Role: "no-access"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.CredentialProvider().Inject(ctx, v.ID, "other.example.com", 443, "/v1/x"); err == nil {
		t.Fatal("disabled owner remained usable")
	}
	if w = f.call("GET", route, "", ""); w.Code != 403 {
		t.Fatal("disabled user retained management access", w.Code)
	}
}

func TestManagedConnectionConcurrentRevisionAndClosedForkRoutes(t *testing.T) {
	f := newManagedFixture(t)
	c := f.create(basicConnection)
	route := f.base() + "/connections/" + c.ID
	status := make(chan int, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.call("PUT", route, fmt.Sprintf(`{"label":"label-%d"}`, i), c.Revision)
			status <- w.Code
		}()
	}

	wg.Wait()
	close(status)
	counts := map[int]int{}
	for code := range status {
		counts[code]++
	}
	if counts[200] != 1 || counts[412] != 1 {
		t.Fatal("optimistic concurrency lost an update", counts)
	}
	for _, path := range []string{"/v1/credentials", "/v1/vaults/group-one/keys", "/v1/vaults/group-one/key-sets", "/v1/vaults/group-one/mcp-oauth", "/v1/vaults/group-one/oauth-apps", "/v1/vaults/group-one/services"} {
		if w := f.call("GET", path, "", ""); w.Code != 404 {
			t.Fatal("superseded headless management surface remained available", path, w.Code)
		}
	}
	_, other, err := f.db.CreateAgentWithGrantsAndToken(context.Background(), "other-owner", "", "owner", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.token = other.ID
	if w := f.call("GET", route, "", ""); w.Code != 403 {
		t.Fatal("arbitrary instance owner delegated effective user", w.Code)
	}
}
