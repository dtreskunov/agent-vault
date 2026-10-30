package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/gatewaytest"
	"github.com/Infisical/agent-vault/internal/mcpauth"
	"github.com/Infisical/agent-vault/internal/store"
)

type managedOAuthProvider struct {
	mu                     sync.Mutex
	refreshes, revocations int
	block, release         chan struct{}
	cleanupStatus          int
	cleanupBody            string
}

func (p *managedOAuthProvider) serve(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/token":
		if r.Form.Get("grant_type") == "authorization_code" {
			if r.Form.Get("code_verifier") == "" || r.Form.Get("client_secret") != "synthetic-client-secret" {
				w.WriteHeader(400)
				return
			}
			fmt.Fprint(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":3600,"scope":"read"}`)
			return
		}
		p.mu.Lock()
		p.refreshes++
		number := p.refreshes
		block, release := p.block, p.release
		p.mu.Unlock()
		if block != nil {
			close(block)
			<-release
		}
		fmt.Fprintf(w, `{"access_token":"synthetic-refreshed-%d","refresh_token":"synthetic-rotated-%d","token_type":"Bearer","expires_in":3600,"scope":"read"}`, number, number)
	case "/revoke":
		p.mu.Lock()
		p.revocations++
		status, body := p.cleanupStatus, p.cleanupBody
		p.mu.Unlock()
		if status != 0 {
			w.WriteHeader(status)
		}
		fmt.Fprint(w, body)
	default:
		w.WriteHeader(404)
	}
}
func TestManagedOAuthClientNameValidation(t *testing.T) {
	f, _, c, _ := setupManagedOAuth(t)
	before, err := f.s.loadConnection(context.Background(), c.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"line\nbreak", strings.Repeat("x", 101)} {
		body, err := json.Marshal(map[string]any{"client_name": name, "scopes": []string{"changed"}})
		if err != nil {
			t.Fatal(err)
		}
		w := f.call("POST", f.base()+"/connections/"+c.ID+"/oauth/start", string(body), "")
		if w.Code != 400 || !strings.Contains(w.Body.String(), "invalid_client_name") {
			t.Fatal("invalid client name was accepted", w.Code, w.Body)
		}
		latest, err := f.s.loadConnection(context.Background(), c.ID)
		if err != nil || latest.sourceRevision != before.sourceRevision {
			t.Fatal("invalid client name changed connection policy", err)
		}
	}
}

func TestManagedScopeInspectionKeepsStatePrivateAndUnchanged(t *testing.T) {
	f, _, c, _ := setupManagedOAuth(t)
	ctx := context.Background()
	db, _ := f.db.GatewaySQL()
	var before int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM gateway_oauth_records`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	w := f.call("POST", f.base()+"/oauth/scopes", `{"app_id":"test-app"}`, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"source":"not_advertised"`) || strings.Contains(w.Body.String(), "synthetic-") {
		t.Fatal("unsafe or unexpected discovery response", w.Code, w.Body)
	}
	var after int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM gateway_oauth_records`).Scan(&after); err != nil || before != after {
		t.Fatal("scope inspection changed OAuth state", before, after, err)
	}
	other, err := f.db.ReconcileManagedUser(ctx, store.ManagedUserInput{InstallationID: "install", Subject: "other", Active: true, Role: "owner"})
	if err != nil {
		t.Fatal(err)
	}
	w = f.call("POST", "/v1/managed-users/"+other.ID+"/oauth/scopes", `{"app_id":"test-app"}`, "")
	if w.Code == 200 {
		t.Fatal("another user discovered a private app", w.Body)
	}
	beforeConnection, err := f.s.loadConnection(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	w = f.call("POST", f.base()+"/connections/"+c.ID+"/oauth/start", `{"scopes":["read","read"]}`, "")
	afterConnection, readErr := f.s.loadConnection(ctx, c.ID)
	if w.Code != 200 || readErr != nil || beforeConnection.sourceRevision != afterConnection.sourceRevision {
		t.Fatal("equivalent scopes changed connection policy", w.Code, w.Body, readErr)
	}
	w = f.call("POST", f.base()+"/connections/"+c.ID+"/oauth/start", `{"scopes":["invalid scope"]}`, "")
	afterConnection, readErr = f.s.loadConnection(ctx, c.ID)
	if w.Code == 200 || readErr != nil || beforeConnection.sourceRevision != afterConnection.sourceRevision {
		t.Fatal("invalid scopes changed connection policy", w.Code, w.Body, readErr)
	}
}

func setupManagedOAuth(t *testing.T, baseURLs ...string) (*managedFixture, *managedOAuthProvider, *connection, string) {
	t.Helper()
	gatewaytest.UseLoopbackDNS(t)
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "127.0.0.1")
	f := newManagedFixture(t, baseURLs...)
	provider := &managedOAuthProvider{}
	authority := httptest.NewServer(http.HandlerFunc(provider.serve))
	t.Cleanup(authority.Close)
	issuer := strings.Replace(authority.URL, "127.0.0.1", "localhost.localdomain", 1)
	app := fmt.Sprintf(`{"issuer":%q,"client_id":"test-client","client_secret":"synthetic-client-secret","label":"Test app","authorization_endpoint":%q,"token_endpoint":%q,"revocation_endpoint":%q,"api_hosts":["api.example.com"],"default_scopes":["read"],"identity":"none"}`, issuer, issuer+"/authorize", issuer+"/token", issuer+"/revoke")
	w := f.call("PUT", f.base()+"/oauth-apps/test-app?scope=user", app, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"source":"user"`) || strings.Contains(w.Body.String(), "synthetic-") {
		t.Fatal("unsafe or incorrect AppInfo", w.Body)
	}
	if w = f.call("PUT", f.base()+"/oauth-apps/install-app?scope=install", app, ""); w.Code != 403 {
		t.Fatal("transport owner privileges inherited by effective user", w.Code)
	}
	c := f.create(`{"label":"Reusable OAuth account","kind":"oauth_app","app_id":"test-app","scopes":["read"]}`)
	start := f.call("POST", f.base()+"/connections/"+c.ID+"/oauth/start", `{}`, "")
	if start.Code != 200 {
		t.Fatal(start.Code, start.Body)
	}
	var flow mcpauth.Started
	json.Unmarshal(start.Body.Bytes(), &flow)
	if flow.State == "" || !strings.Contains(flow.AuthorizeURL, "code_challenge=") {
		t.Fatal("missing PKCE-bound flow")
	}
	return f, provider, c, flow.State
}
func (f *managedFixture) complete(c *connection, state, user string) *httptest.ResponseRecorder {
	return f.call("POST", "/v1/oauth/complete", fmt.Sprintf(`{"state":%q,"code":"code","user_id":%q}`, state, user), "")
}
func (f *managedFixture) expireOAuth(c *connection) {
	f.t.Helper()
	db, d := f.db.GatewaySQL()
	var ct, nonce []byte
	if err := db.QueryRow(d.Rebind(`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='account' AND record_key=?`), c.library, c.ID).Scan(&ct, &nonce); err != nil {
		// Wire metadata deliberately excludes the storage library.
		loaded, loadErr := f.s.loadConnection(context.Background(), c.ID)
		if loadErr != nil {
			f.t.Fatal(loadErr)
		}
		c.library = loaded.library
		if err = db.QueryRow(d.Rebind(`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='account' AND record_key=?`), c.library, c.ID).Scan(&ct, &nonce); err != nil {
			f.t.Fatal(err)
		}
	}
	raw, err := crypto.Decrypt(ct, nonce, f.s.encKey)
	if err != nil {
		f.t.Fatal(err)
	}
	var account mcpauth.Account
	if err = json.Unmarshal(raw, &account); err != nil {
		f.t.Fatal(err)
	}
	account.ExpiresAt = time.Now().Add(-time.Hour)
	raw, err = json.Marshal(account)
	if err != nil {
		f.t.Fatal(err)
	}
	ct, nonce, err = crypto.Encrypt(raw, f.s.encKey)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err = db.Exec(d.Rebind(`UPDATE gateway_oauth_records SET ciphertext=?,nonce=? WHERE vault_id=? AND kind='account' AND record_key=?`), ct, nonce, c.library, c.ID); err != nil {
		f.t.Fatal(err)
	}
}
func TestManagedConnectionOAuthAppLifecycleAndRevocationDuringRefresh(t *testing.T) {
	f, provider, c, state := setupManagedOAuth(t)
	ctx := context.Background()
	route := f.base() + "/connections/" + c.ID
	if w := f.complete(c, state, "wrong-user"); w.Code != 403 {
		t.Fatal("callback accepted another user", w.Code, w.Body)
	}
	w := f.complete(c, state, f.user)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"connection_id":"`+c.ID+`"`) || strings.Contains(w.Body.String(), `"key"`) {
		t.Fatal("callback lost authoritative connection identity", w.Code, w.Body)
	}
	if w = f.complete(c, state, f.user); w.Code != 400 {
		t.Fatal("callback state replay accepted", w.Code)
	}
	loaded, err := f.s.loadConnection(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	c = loaded
	if c.Status != "ready" || len(c.Services) != 1 || c.Services[0].Auth.Token != c.ID || c.ScopeSource != "provider" {
		t.Fatal("authorized OAuth service not derived from connection")
	}
	service := c.Services[0].Name
	for _, group := range []string{"group-one", "group-two"} {
		w = f.call("PUT", route+"/grants/"+group, fmt.Sprintf(`{"services":[%q]}`, service), "")
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	one, _ := f.db.GetVault(ctx, "group-one")
	two, _ := f.db.GetVault(ctx, "group-two")
	f.expireOAuth(c)
	var wg sync.WaitGroup
	failures := make(chan error, 16)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vault := one.ID
			if i%2 == 0 {
				vault = two.ID
			}
			result, err := f.s.CredentialProvider().Inject(ctx, vault, "api.example.com", 443, "/anything")
			if err == nil && result.Headers["Authorization"] != "Bearer synthetic-refreshed-1" {
				err = fmt.Errorf("incorrect centrally refreshed token")
			}
			failures <- err
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	provider.mu.Lock()
	refreshes := provider.refreshes
	provider.mu.Unlock()
	if refreshes != 1 {
		t.Fatal("shared refresh was duplicated", refreshes)
	}
	bindings, err := f.s.loadBindings(ctx, one.ID)
	if err != nil || len(bindings) != 1 {
		t.Fatal(err)
	}
	access := httptest.NewRequest("GET", "https://api.example.com/anything", nil)
	access.Header.Set("Authorization", "Bearer av-access:"+bindings[0].handle)
	if response, err := f.s.LocalTokenResponse(ctx, two.ID, access); err != nil || response == nil || response.StatusCode != 403 {
		t.Fatal("copied access handle crossed group boundary", err)
	}
	access.Header.Set("Authorization", "Bearer av-access:"+bindings[0].handle)
	if response, err := f.s.LocalTokenResponse(ctx, one.ID, access); err != nil || response != nil {
		t.Fatal("valid group access handle rejected", err)
	}
	f.expireOAuth(c)
	provider.mu.Lock()
	provider.block = make(chan struct{})
	provider.release = make(chan struct{})
	block, release := provider.block, provider.release
	provider.mu.Unlock()
	outcome := make(chan error, 1)
	go func() {
		_, err := f.s.CredentialProvider().Inject(ctx, one.ID, "api.example.com", 443, "/anything")
		outcome <- err
	}()
	select {
	case <-block:
	case <-time.After(5 * time.Second):
		t.Fatal("refresh did not start")
	}
	if w = f.call("DELETE", route+"/grants/group-one", "", ""); w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	close(release)
	if err = <-outcome; err == nil {
		t.Fatal("credential was injected after revocation during refresh")
	}
	provider.mu.Lock()
	provider.block, provider.release = nil, nil
	revocations := provider.revocations
	provider.mu.Unlock()
	if revocations != 0 {
		t.Fatal("group detachment revoked upstream")
	}
	if _, err = f.s.CredentialProvider().Inject(ctx, two.ID, "api.example.com", 443, "/anything"); err != nil {
		t.Fatal("detachment affected other group refresh state", err)
	}
	if w = f.call("DELETE", "/v1/vaults/group-two", "", ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	provider.mu.Lock()
	revocations = provider.revocations
	provider.mu.Unlock()
	if revocations != 0 {
		t.Fatal("group deletion revoked upstream")
	}
	if w = f.call("GET", route, "", ""); w.Code != 200 {
		t.Fatal("group deletion destroyed account")
	}
	provider.mu.Lock()
	provider.cleanupStatus = 503
	provider.mu.Unlock()
	if w = f.call("DELETE", route, "", ""); w.Code != 502 || !strings.Contains(w.Body.String(), "upstream_cleanup_failed") {
		t.Fatal("upstream cleanup failure hidden", w.Code, w.Body)
	}
	current, err := f.s.loadConnection(ctx, c.ID)
	if err != nil || current.Status != "disabled" {
		t.Fatal("failed cleanup did not retain disabled connection")
	}
	provider.mu.Lock()
	provider.cleanupStatus = 200
	provider.mu.Unlock()
	if w = f.call("DELETE", route, "", ""); w.Code != 204 {
		t.Fatal("explicit cleanup retry failed", w.Code, w.Body)
	}
	if w = f.call("GET", route, "", ""); w.Code != 404 {
		t.Fatal("deleted global connection remained visible")
	}
}

func TestManagedConnectionOAuthDeletionRevocationResponses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   int
	}{
		{"already invalid", 400, `{"error":"invalid_token"}`, 204},
		{"invalid client", 400, `{"error":"invalid_client"}`, 502},
		{"unsupported token type", 400, `{"error":"unsupported_token_type"}`, 502},
		{"malformed response", 400, `<html>Bad request</html>`, 502},
		{"unavailable", 503, `{"error":"invalid_token"}`, 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, provider, c, state := setupManagedOAuth(t)
			ctx := context.Background()
			route := f.base() + "/connections/" + c.ID
			if w := f.complete(c, state, f.user); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			c, err := f.s.loadConnection(ctx, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			provider.mu.Lock()
			provider.cleanupStatus, provider.cleanupBody = tc.status, tc.body
			provider.mu.Unlock()
			w := f.call("DELETE", route, "", "")
			if w.Code != tc.want {
				t.Fatal("unexpected deletion result", w.Code, w.Body)
			}
			provider.mu.Lock()
			revocations := provider.revocations
			provider.mu.Unlock()
			if revocations != 2 {
				t.Fatal("did not attempt both token revocations", revocations)
			}
			current, err := f.s.loadConnection(ctx, c.ID)
			account, accountErr := f.s.mcpOAuth.ConnectionAccount(ctx, c.library, c.ID)
			if tc.want == 204 {
				if !errors.Is(err, sql.ErrNoRows) || !errors.Is(accountErr, sql.ErrNoRows) {
					t.Fatal("deleted connection or encrypted account remained", err, accountErr)
				}
			} else if err != nil || current.Status != "disabled" || accountErr != nil || account == nil {
				t.Fatal("failed cleanup did not retain disabled connection and encrypted account", err, accountErr)
			}
		})
	}
}

func TestManagedConnectionOAuthScopeAndAppPolicySuspendGrants(t *testing.T) {
	f, _, c, state := setupManagedOAuth(t)
	ctx := context.Background()
	route := f.base() + "/connections/" + c.ID
	if w := f.complete(c, state, f.user); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	c, err := f.s.loadConnection(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	w := f.call("PUT", route+"/grants/group-one", fmt.Sprintf(`{"services":[%q]}`, c.Services[0].Name), "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	w = f.call("POST", route+"/oauth/start", `{"scopes":["read","write"]}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	one, _ := f.db.GetVault(ctx, "group-one")
	if _, err = f.s.CredentialProvider().Inject(ctx, one.ID, "api.example.com", 443, "/"); err == nil {
		t.Fatal("scope expansion silently broadened existing grant")
	}
	w = f.call("PUT", f.base()+"/oauth-apps/test-app?scope=user", `{"client_id":"changed-client","client_secret":"synthetic-new-secret"}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	c, err = f.s.loadConnection(ctx, c.ID)
	if err != nil || c.Status != "needs_reconnect" || len(c.Grants) != 1 || c.Grants[0].Status != "suspended" {
		t.Fatal("app binding change did not retain and suspend shared account", err)
	}
	if w = f.call("POST", route+"/oauth/start", `{"app_id":"different-app"}`, ""); w.Code != 409 {
		t.Fatal("connection OAuth app identity was retargeted", w.Code)
	}
}
