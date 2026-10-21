package mcpauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/gatewaytest"
	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
	"github.com/Infisical/agent-vault/internal/store"
)

type authority struct {
	server                                                      *httptest.Server
	mu                                                          sync.Mutex
	registrations, exchanges, refreshes, revocations, deletions int
	invalid                                                     bool
	oidc                                                        bool
	expires                                                     int
	codes                                                       map[string]url.Values
	refresh                                                     map[string]string
	metadata                                                    bool
	register                                                    bool
	secret                                                      bool
}

func newAuthority(t *testing.T, manager *Manager) *authority {
	t.Helper()
	a := &authority{expires: 3600, codes: make(map[string]url.Values), refresh: make(map[string]string), register: true}
	a.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		base := a.server.URL
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+base+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(401)
		case "/public":
			fmt.Fprint(w, `{}`)
		case "/.well-known/oauth-protected-resource/mcp":
			json.NewEncoder(w).Encode(oauthex.ProtectedResourceMetadata{Resource: base + "/mcp", AuthorizationServers: []string{base}, ScopesSupported: []string{"read"}})
		case "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration":
			if a.oidc && r.URL.Path == "/.well-known/oauth-authorization-server" {
				w.WriteHeader(404)
				return
			}
			metadata := oauthex.AuthServerMeta{
				Issuer: base, AuthorizationEndpoint: base + "/authorize", TokenEndpoint: base + "/token",
				CodeChallengeMethodsSupported: []string{"S256"}, RevocationEndpoint: base + "/revoke",
				AuthorizationResponseIssParameterSupported: true, ClientIDMetadataDocumentSupported: a.metadata,
			}
			if a.register {
				metadata.RegistrationEndpoint = base + "/register"
			}
			if a.secret {
				metadata.TokenEndpointAuthMethodsSupported = []string{"client_secret_basic"}
			}
			json.NewEncoder(w).Encode(metadata)
		case "/register":
			a.registrations++
			var input oauthex.ClientRegistrationMetadata
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
				t.Error(err)
			}
			expected := "none"
			if a.secret {
				expected = "client_secret_basic"
			}
			if len(input.RedirectURIs) != 1 || input.TokenEndpointAuthMethod != expected {
				t.Error("incorrect registration metadata")
			}
			registration := &oauthex.ClientRegistrationResponse{
				ClientRegistrationMetadata: input, ClientID: fmt.Sprintf("client-%d", a.registrations),
				RegistrationAccessToken: "synthetic-management-secret", RegistrationClientURI: base + "/client",
			}
			if a.secret {
				registration.ClientSecret = "synthetic-registered-secret"
			}
			json.NewEncoder(w).Encode(registration)
		case "/token":
			r.ParseForm()
			if a.invalid {
				w.WriteHeader(401)
				fmt.Fprint(w, `{"error":"invalid_client","error_description":"must not expose synthetic-secret"}`)
				return
			}
			if r.Form.Get("resource") != base+"/mcp" {
				t.Error("resource missing from token request")
			}
			client := r.Form.Get("client_id")
			if a.secret {
				user, password, ok := r.BasicAuth()
				if !ok || user != client || password != "synthetic-registered-secret" {
					t.Error("confidential MCP client authentication was not retained")
				}
			}
			switch r.Form.Get("grant_type") {
			case "authorization_code":
				a.exchanges++
				code := a.codes[r.Form.Get("code")]
				delete(a.codes, r.Form.Get("code"))
				if code == nil || code.Get("client_id") != client || code.Get("redirect_uri") != r.Form.Get("redirect_uri") ||
					code.Get("code_challenge") != oauth.CodeChallengeS256(r.Form.Get("code_verifier")) {
					t.Error("code exchange lost client, redirect or PKCE binding")
				}
			case "refresh_token":
				a.refreshes++
				if a.refresh[r.Form.Get("refresh_token")] != client {
					t.Error("refresh token rotation or client binding was lost")
				}
				delete(a.refresh, r.Form.Get("refresh_token"))
			default:
				t.Error("unexpected grant")
			}
			ref := fmt.Sprintf("refresh-%s-%d-%d", client, a.exchanges, a.refreshes)
			a.refresh[ref] = client
			json.NewEncoder(w).Encode(map[string]any{"access_token": "access-" + client, "refresh_token": ref, "token_type": "Bearer", "expires_in": a.expires})
		case "/revoke":
			a.revocations++
			fmt.Fprint(w, `{}`)
		case "/client":
			if r.Method != "DELETE" || r.Header.Get("Authorization") != "Bearer synthetic-management-secret" {
				t.Error("RFC 7592 cleanup lost management credentials")
			}
			a.deletions++
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	roots := x509.NewCertPool()
	roots.AddCert(a.server.Certificate())
	manager.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "127.0.0.1"}
	a.server.URL = strings.Replace(a.server.URL, "127.0.0.1", "localhost.localdomain", 1)
	t.Cleanup(a.server.Close)
	return a
}

func (a *authority) code(t *testing.T, started *Started) (string, string) {
	t.Helper()
	u, err := url.Parse(started.AuthorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("resource") != a.server.URL+"/mcp" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("authorize URL lacks resource or PKCE")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	code := fmt.Sprintf("code-%d", len(a.codes)+a.exchanges+1)
	a.codes[code] = u.Query()
	return code, u.Query().Get("client_id")
}

func testManager(t *testing.T) (*Manager, *store.SQLStore, string) {
	t.Helper()
	gatewaytest.UseLoopbackDNS(t)
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "127.0.0.1")
	t.Setenv("AGENT_VAULT_DEV_MODE", "true")
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	vault, err := db.GetVault(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, dialect := db.GatewaySQL()
	manager := New(db, NewRepository(sqlDB, dialect, make([]byte, 32)),
		oauthrelay.Config{RedirectURI: "https://ui.example.com/oauth/callback", MetadataURI: "https://ui.example.com/oauth/client-metadata.json"},
		slog.New(slog.DiscardHandler))
	return manager, db, vault.ID
}

func connect(t *testing.T, manager *Manager, vault string, authority *authority) (*Account, string) {
	t.Helper()
	started, err := manager.Start(context.Background(), vault, authority.server.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	code, client := authority.code(t, started)
	result, err := manager.Complete(context.Background(), oauthrelay.Input{State: started.State, Code: code, Issuer: authority.server.URL},
		func(id string) error {
			if id != vault {
				t.Fatal("cross-vault state")
			}
			return nil
		})
	if err != nil || result.Status != "connected" {
		t.Fatalf("MCP completion failed: %v", err)
	}
	account, err := manager.repo.Account(context.Background(), vault, result.Key)
	if err != nil {
		t.Fatal(err)
	}
	return account, client
}

func TestConfidentialRegistration(t *testing.T) {
	m, _, vault := testManager(t)
	a := newAuthority(t, m)
	a.secret, a.expires = true, 1
	account, _ := connect(t, m, vault, a)
	if account.Client.AuthMethod != "client_secret_basic" || account.Client.Secret == "" {
		t.Fatal("confidential registration did not retain its issued secret")
	}
	if _, err := m.Credential(context.Background(), vault, account.Key); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationWire(t *testing.T) {
	m, _, _ := testManager(t)
	a := newAuthority(t, m)
	_, err := oauthex.RegisterClient(context.Background(), a.server.URL+"/register",
		&oauthex.ClientRegistrationMetadata{RedirectURIs: []string{m.config.RedirectURI}, TokenEndpointAuthMethod: "none"}, m.client)
	if err != nil {
		t.Fatal(strings.ReplaceAll(err.Error(), "synthetic-management-secret", "[redacted]"))
	}
}

func TestVaultRegistrationIsolationCleanupAndServiceBounds(t *testing.T) {
	m, db, first := testManager(t)
	a := newAuthority(t, m)
	second, err := db.CreateVault(context.Background(), "second-group")
	if err != nil {
		t.Fatal(err)
	}
	one, id1 := connect(t, m, first, a)
	two, id2 := connect(t, m, second.ID, a)
	if id1 == id2 || a.registrations != 2 {
		t.Fatal("vaults shared an OAuth registration")
	}
	cfg, _ := db.GetBrokerConfig(context.Background(), first)
	var services []broker.Service
	json.Unmarshal([]byte(cfg.ServicesJSON), &services)
	for i := range services {
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
	}
	u, _ := url.Parse(a.server.URL)
	for _, path := range []string{"/mcp", "/mcp/events"} {
		if service, _ := broker.MatchService(u.Hostname(), mustPort(t, u), path, services); service == nil || service.Auth.Token != one.Key {
			t.Fatal("MCP service prefix missing")
		}
	}
	if service, _ := broker.MatchService(u.Hostname(), mustPort(t, u), "/mcp-other", services); service != nil {
		t.Fatal("MCP service leaks to sibling paths")
	}
	if err := m.Disconnect(context.Background(), first, one.Key); err != nil {
		t.Fatal(err)
	}
	if _, err := m.repo.Account(context.Background(), first, one.Key); err != sql.ErrNoRows {
		t.Fatal("disconnect retained account")
	}
	if _, err := m.Credential(context.Background(), second.ID, two.Key); err != nil {
		t.Fatal("disconnect broke another vault")
	}
	if a.deletions != 1 || a.revocations != 2 {
		t.Fatal("disconnect did not perform remote cleanup")
	}
	if err := m.CleanupVault(context.Background(), second.ID); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteVault(context.Background(), "second-group"); err != nil {
		t.Fatal(err)
	}
	var n int
	m.repo.db.QueryRow(`SELECT COUNT(*) FROM gateway_oauth_records WHERE vault_id=?`, second.ID).Scan(&n)
	if n != 0 || a.deletions != 2 {
		t.Fatal("vault deletion did not clean registration state")
	}
}

func mustPort(t *testing.T, u *url.URL) int {
	t.Helper()
	var port int
	if _, err := fmt.Sscan(u.Port(), &port); err != nil {
		t.Fatal(err)
	}
	return port
}

func TestRefreshRotationDeduplicationAndInvalidClient(t *testing.T) {
	m, db, vault := testManager(t)
	a := newAuthority(t, m)
	a.expires = 1
	account, _ := connect(t, m, vault, a)
	a.mu.Lock()
	a.expires = 3600
	a.mu.Unlock()
	var group sync.WaitGroup
	for i := 0; i < 10; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := m.Credential(context.Background(), vault, account.Key); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if a.refreshes != 1 {
		t.Fatal("concurrent use duplicated refresh")
	}
	info, err := m.List(context.Background(), vault)
	if err != nil || len(info) != 1 || info[0].LastUsedAt == nil {
		t.Fatal("last_used_at not recorded")
	}
	sqlDB, dialect := db.GatewaySQL()
	restarted := New(db, NewRepository(sqlDB, dialect, make([]byte, 32)), m.config, m.logger)
	restarted.client = m.client
	restarted.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, err := restarted.Credential(context.Background(), vault, account.Key); err != nil {
		t.Fatal(err)
	}
	if a.refreshes != 2 {
		t.Fatal("rotated refresh token was not persisted")
	}
	a.mu.Lock()
	a.invalid = true
	a.mu.Unlock()
	if _, err := restarted.Credential(context.Background(), vault, account.Key); err == nil {
		t.Fatal("invalid_client was ignored")
	}
	if a.registrations != 2 {
		t.Fatal("invalid_client did not re-register exactly once")
	}
	for i := 0; i < 2; i++ {
		if _, err := restarted.Credential(context.Background(), vault, account.Key); err == nil {
			t.Fatal("reconnect not required")
		}
	}
	if a.registrations != 2 {
		t.Fatal("reconnect loop kept registering clients")
	}
	info, _ = restarted.List(context.Background(), vault)
	if info[0].Status != "needs_reconnect" {
		t.Fatal("failed account was reported connected")
	}
}

func TestIssuerReplayExpiryAndAtomicRollback(t *testing.T) {
	m, db, vault := testManager(t)
	a := newAuthority(t, m)
	for _, issuer := range []string{"", "https://wrong.example.com"} {
		start, err := m.Start(context.Background(), vault, a.server.URL+"/mcp")
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.Complete(context.Background(), oauthrelay.Input{State: start.State, Code: "unused", Issuer: issuer}, func(string) error { return nil })
		if err != nil || result.Code != "issuer_mismatch" {
			t.Fatal("unbound callback issuer accepted")
		}
	}
	start, _ := m.Start(context.Background(), vault, a.server.URL+"/mcp")
	code, _ := a.code(t, start)
	if _, err := db.SetBrokerConfig(context.Background(), vault, "{"); err != nil {
		t.Fatal(err)
	}
	_, err := m.Complete(context.Background(), oauthrelay.Input{State: start.State, Code: code, Issuer: a.server.URL}, func(string) error { return nil })
	if err == nil {
		t.Fatal("invalid service snapshot did not fail completion")
	}
	if _, err := db.GetCredential(context.Background(), vault, accountKey(a.server.URL+"/mcp")); err != sql.ErrNoRows {
		t.Fatal("failed atomic update left a credential")
	}
	if items, _ := m.List(context.Background(), vault); len(items) != 0 {
		t.Fatal("failed atomic update left an account")
	}
	if _, err := db.SetBrokerConfig(context.Background(), vault, "[]"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Complete(context.Background(), oauthrelay.Input{State: start.State, Code: code, Issuer: a.server.URL}, func(string) error { return nil }); err == nil {
		t.Fatal("state replay accepted")
	}
	start, _ = m.Start(context.Background(), vault, a.server.URL+"/mcp")
	m.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if _, err := m.Complete(context.Background(), oauthrelay.Input{State: start.State, Code: "unused", Issuer: a.server.URL}, func(string) error { return nil }); err == nil {
		t.Fatal("expired state accepted")
	}
}

func TestDiscoveryOIDCFallbackAndMetadataClient(t *testing.T) {
	m, _, vault := testManager(t)
	a := newAuthority(t, m)
	a.oidc = true
	a.register = false
	a.metadata = true
	probe, err := m.Probe(context.Background(), vault, a.server.URL+"/mcp")
	if err != nil || probe.Client != "metadata" || a.registrations != 0 {
		t.Fatal("probe did not use OIDC/CIMD without registering")
	}
	_, id := connect(t, m, vault, a)
	if id != m.config.MetadataURI {
		t.Fatal("CIMD URL was not the client ID")
	}
	probe, err = m.Probe(context.Background(), vault, a.server.URL+"/public")
	if err != nil || probe.OAuth {
		t.Fatal("public resource was reported OAuth-protected")
	}
}

func TestCatalogAppPreferenceAndUnsupportedProvider(t *testing.T) {
	m, _, vault := testManager(t)
	discovery := &Discovery{Server: oauthex.AuthServerMeta{Issuer: "https://github.com/login/oauth", ClientIDMetadataDocumentSupported: false}}
	if _, err := m.chooseClient(context.Background(), vault, discovery, false); err == nil {
		t.Fatal("missing app did not fail")
	} else if unsupported, ok := err.(*Failure); !ok || unsupported.Code != "registration_unsupported" || unsupported.Provider != "github" {
		t.Fatal("missing catalog provider hint")
	}
	if err := m.StoreApp(context.Background(), "", Client{Issuer: discovery.Server.Issuer, ID: "install-client", Secret: "synthetic-install-secret"}); err != nil {
		t.Fatal(err)
	}
	client, err := m.chooseClient(context.Background(), vault, discovery, true)
	if err != nil || client.ID != "install-client" || client.Source != "install" {
		t.Fatal("install app fallback failed")
	}
	if err := m.StoreApp(context.Background(), vault, Client{Issuer: discovery.Server.Issuer, ID: "vault-client", Secret: "synthetic-vault-secret"}); err != nil {
		t.Fatal(err)
	}
	client, err = m.chooseClient(context.Background(), vault, discovery, true)
	if err != nil || client.ID != "vault-client" || client.Source != "vault" {
		t.Fatal("vault app did not override install app")
	}
	discovery.Server.Issuer = "https://unknown.example.com"
	if _, err := m.chooseClient(context.Background(), vault, discovery, false); err == nil {
		t.Fatal("unknown non-registering issuer accepted")
	}
}

func TestChallengeFilteringAndEncryptedStorage(t *testing.T) {
	m, _, vault := testManager(t)
	a := newAuthority(t, m)
	account, _ := connect(t, m, vault, a)
	headers := http.Header{"Www-Authenticate": {`Bearer error="invalid_token", resource_metadata="https://example.com/meta", scope="read"`}}
	if err := m.FilterChallenge(context.Background(), vault, []string{account.Key}, headers); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(headers.Get("WWW-Authenticate"), "resource_metadata") || !strings.Contains(headers.Get("WWW-Authenticate"), "invalid_token") {
		t.Fatal("MCP challenge filtering failed")
	}
	var ct, nonce []byte
	m.repo.db.QueryRow(`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='client'`, vault).Scan(&ct, &nonce)
	if strings.Contains(string(ct), "synthetic-management-secret") {
		t.Fatal("registration persisted in plaintext")
	}
	var saved Client
	plaintext, err := crypto.Decrypt(ct, nonce, m.repo.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(plaintext, &saved); err != nil || saved.ManagementToken != "synthetic-management-secret" {
		t.Fatal("registration management token was not retained")
	}
}
