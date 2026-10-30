package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/oauthrelay"
	"github.com/Infisical/agent-vault/internal/store"
)

func managedMCPFixture(t *testing.T, m *Manager, db *store.SQLStore, id string) (string, string, string) {
	t.Helper()
	ctx := context.Background()
	user, err := db.ReconcileManagedUser(ctx, store.ManagedUserInput{InstallationID: "managed-install", Subject: "managed-subject", Active: true, Role: "no-access", VaultGrants: []store.ManagedVaultGrant{{Vault: "managed-group", Role: "admin"}}})
	if err != nil {
		t.Fatal(err)
	}
	library, err := db.GetVault(ctx, user.LibraryVault)
	if err != nil {
		t.Fatal(err)
	}
	group, err := db.GetVault(ctx, "managed-group")
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.repo.db.ExecContext(ctx, `INSERT INTO connections(id,owner_user_id,library_vault_id,label,kind,status,revision) VALUES (?,?,?,'MCP connection','mcp_oauth','draft','"initial"')`, id, user.ID, library.ID)
	if err != nil {
		t.Fatal(err)
	}
	return user.ID, library.ID, group.ID
}
func completeManagedMCP(t *testing.T, m *Manager, authority *authority, user, library, id string) (*Account, string) {
	t.Helper()
	ctx := context.Background()
	started, err := m.StartConnection(ctx, library, user, id, "mcp_oauth", authority.server.URL+"/mcp", "", "BananaClaw (Denis Treskunov)", []string{"read"})
	if err != nil {
		t.Fatal(err)
	}
	flow, err := m.ConnectionFlow(ctx, started.State)
	if err != nil || flow.ManagedUserID != user || flow.ConnectionID != id || flow.ConnectionRevision != `"initial"` {
		t.Fatal("managed flow identity not pinned", err)
	}
	if _, err = m.Complete(ctx, oauthrelay.Input{State: started.State, Code: "unusable"}, nil); err == nil {
		t.Fatal("managed flow accepted unauthenticated browser completion")
	}
	code, client := authority.code(t, started)
	result, err := m.Complete(ctx, oauthrelay.Input{State: started.State, Code: code, Issuer: authority.server.URL, UserID: user}, func(vault string) error {
		if vault != library {
			return errors.New("wrong library")
		}
		return nil
	})
	if err != nil || result.Status != "connected" || result.ConnectionID != id || result.Key != "" || result.Vault != "" {
		t.Fatal("managed MCP callback returned a vault-owned account", err, result)
	}
	account, err := m.ConnectionAccount(ctx, library, id)
	if err != nil {
		t.Fatal(err)
	}
	return account, client
}
func TestManagedMCPConnectionPinsDCRAndIndependentAuthorizations(t *testing.T) {
	m, db, _ := testManager(t)
	a := newAuthority(t, m)
	ctx := context.Background()
	user, library, group := managedMCPFixture(t, m, db, "CONN_MCPONE")
	first, clientOne := completeManagedMCP(t, m, a, user, library, "CONN_MCPONE")
	_, _, _ = managedMCPFixture(t, m, db, "CONN_MCPTWO")
	second, clientTwo := completeManagedMCP(t, m, a, user, library, "CONN_MCPTWO")
	if clientOne == clientTwo || first.Key == second.Key {
		t.Fatal("separate connections reused a DCR/account lifecycle")
	}
	a.mu.Lock()
	registrationNames := append([]string(nil), a.names...)
	a.mu.Unlock()
	if len(registrationNames) != 2 || registrationNames[0] != "BananaClaw (Denis Treskunov)" || registrationNames[1] != registrationNames[0] {
		t.Fatal("friendly names were lost or used as connection identity", registrationNames)
	}
	accounts, err := m.repo.Accounts(ctx, library)
	if err != nil || len(accounts) != 2 {
		t.Fatal("same-resource authorizations were merged", err)
	}
	cfg, err := db.GetBrokerConfig(ctx, library)
	if err != nil || cfg.ServicesJSON != "[]" {
		t.Fatal("managed OAuth materialized proxyable library services", err)
	}
	services, err := first.services()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(services)
	names := []string{}
	for _, service := range services {
		names = append(names, service.Name)
	}
	selected, _ := json.Marshal(names)
	_, err = m.repo.db.ExecContext(ctx, `INSERT INTO connection_grants(connection_id,vault_id,services_json,bound_services_json,approved_revision,status,creator_user_id,binding_handle)
		VALUES (?,?,?,?,'"initial"','active',?,'BIND_SYNTHETIC_ONE')`, first.Key, group, string(selected), string(raw), user)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(vault string) func(string) (*Account, error) {
		return func(handle string) (*Account, error) {
			var count int
			err := m.repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connection_grants WHERE binding_handle=? AND vault_id=? AND status='active'`, handle, vault).Scan(&count)
			if err != nil {
				return nil, err
			}
			if count != 1 {
				return nil, errors.New("binding unavailable")
			}
			return m.ConnectionAccount(ctx, library, first.Key)
		}
	}
	request := func(endpoint, handle string) *httptest.ResponseRecorder {
		t.Helper()
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {RefreshPlaceholderPrefix + handle}}
		r := httptest.NewRequest("POST", endpoint, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := m.BindingTokenResponse(ctx, r, resolve(group))
		if err != nil || response == nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		w.WriteHeader(response.StatusCode)
		w.Write(body)
		return w
	}
	w := request(a.server.URL+"/token", "BIND_SYNTHETIC_ONE")
	if w.Code != 200 || !strings.Contains(w.Body.String(), AccessPlaceholderPrefix+"BIND_SYNTHETIC_ONE") || strings.Contains(w.Body.String(), first.AccessToken) || strings.Contains(w.Body.String(), first.RefreshToken) {
		t.Fatal("F8 returned account keys or real tokens", w.Code, w.Body)
	}
	if w = request(a.server.URL+"/token", "BIND_OTHER_GROUP"); w.Code != 400 {
		t.Fatal("unknown binding refreshed")
	}
	if w = request(a.server.URL+"/token?different=1", "BIND_SYNTHETIC_ONE"); w.Code != 400 {
		t.Fatal("binding accepted at another token endpoint")
	}
	a.mu.Lock()
	refreshes := a.refreshes
	a.mu.Unlock()
	if refreshes != 0 {
		t.Fatal("synthetic response refreshed upstream")
	}
	first.GrantedScopes = []string{"read", "write"}
	first.ScopeSource = "provider"
	first.Scopes = "read write"
	if err = m.repo.saveAccount(ctx, library, first, false); err != nil {
		t.Fatal(err)
	}
	var status, revision string
	if err = m.repo.db.QueryRow(`SELECT status,approved_revision FROM connection_grants WHERE connection_id=?`, first.Key).Scan(&status, &revision); err != nil || status != "active" {
		t.Fatal("OAuth authority expansion changed credential access", err)
	}
	if w = request(a.server.URL+"/token", "BIND_SYNTHETIC_ONE"); w.Code != 200 {
		t.Fatal("existing credential grant stopped following the connection")
	}
	// Removing a recipient does not revoke tokens or delete registrations.
	if _, err = m.repo.db.Exec(`UPDATE connection_grants SET status='revoked' WHERE connection_id=?`, first.Key); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	revocations, deletions := a.revocations, a.deletions
	a.mu.Unlock()
	if revocations != 0 || deletions != 0 {
		t.Fatal("detachment invoked upstream lifecycle")
	}
	if err = m.DisconnectConnection(ctx, library, first.Key); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Credential(ctx, library, second.Key); err != nil {
		t.Fatal("deleting one connection destroyed another registration", err)
	}
	a.mu.Lock()
	revocations, deletions = a.revocations, a.deletions
	a.mu.Unlock()
	if revocations != 2 || deletions != 1 {
		t.Fatal("connection lifecycle did not revoke exactly its own tokens/client", revocations, deletions)
	}
}

func TestManagedMCPCompletionRechecksDisabledNativeUser(t *testing.T) {
	m, db, _ := testManager(t)
	authority := newAuthority(t, m)
	ctx := context.Background()
	user, library, _ := managedMCPFixture(t, m, db, "CONN_DISABLE")
	start, err := m.StartConnection(ctx, library, user, "CONN_DISABLE", "mcp_oauth", authority.server.URL+"/mcp", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := authority.code(t, start)
	checks := 0
	_, err = m.Complete(ctx, oauthrelay.Input{State: start.State, Code: code, Issuer: authority.server.URL, UserID: user}, func(string) error {
		checks++
		if checks == 2 {
			_, err := db.ReconcileManagedUser(ctx, store.ManagedUserInput{InstallationID: "managed-install", Subject: "managed-subject", Active: false, Role: "no-access"})
			if err != nil {
				t.Fatal(err)
			}
			return fmt.Errorf("native user was disabled during exchange")
		}
		return nil
	})
	if err == nil || checks != 2 {
		t.Fatal("completion did not recheck after network exchange")
	}
	if _, err = m.repo.Account(ctx, library, "CONN_DISABLE"); err == nil {
		t.Fatal("disabled principal acquired an authorization")
	}
}
