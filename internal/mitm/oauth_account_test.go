package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/gatewaytest"
	"github.com/Infisical/agent-vault/internal/mcpauth"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
	"github.com/Infisical/agent-vault/internal/store"
)

type accountCredentialStore struct {
	*store.SQLStore
	manager *mcpauth.Manager
}

func (s accountCredentialStore) GetCredential(ctx context.Context, vault, key string) (*store.Credential, error) {
	return s.manager.Credential(ctx, vault, key)
}

func (s accountCredentialStore) UnmatchedHostPolicy(context.Context, string) (brokercore.UnmatchedHostPolicy, error) {
	return brokercore.PolicyPassthrough, nil
}

func TestOAuthAccountIdentityThroughScopedProxy(t *testing.T) {
	gatewaytest.UseLoopbackDNS(t)
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "127.0.0.1")
	t.Setenv("AGENT_VAULT_DEV_MODE", "true")
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := db.GetVault(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	var authenticated, unrelatedCalls atomic.Int32
	const token = "synthetic-private-account-token"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("supported API request did not receive the account credential")
			w.WriteHeader(401)
			return
		}
		for _, name := range []string{"Proxy-Authorization", "X-Vault", "X-Agent-Vault-Token"} {
			if r.Header.Get(name) != "" {
				t.Error("broker identity leaked to API upstream")
			}
		}
		authenticated.Add(1)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"login":"verified-fixture"}`)
	}))
	defer upstream.Close()
	upstreamURL := strings.Replace(upstream.URL, "127.0.0.1", "localhost.localdomain", 1)
	unrelated := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		unrelatedCalls.Add(1)
		if strings.Contains(r.Header.Get("Authorization"), token) || r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Vault") != "" {
			t.Error("credential or broker identity leaked to an unrelated destination")
		}
		io.WriteString(w, `{"public":true}`)
	}))
	defer unrelated.Close()
	authority := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Method != "POST" || r.Form.Get("code_verifier") == "" || r.Form.Get("client_secret") != "synthetic-app-secret" {
			t.Error("generic OAuth exchange lost its client or PKCE binding")
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": token, "refresh_token": "synthetic-refresh", "expires_in": 3600, "token_type": "Bearer", "scope": "repo"})
	}))
	defer authority.Close()
	key := make([]byte, 32)
	sqlDB, dialect := db.GatewaySQL()
	manager := mcpauth.New(db, mcpauth.NewRepository(sqlDB, dialect, key), oauthrelay.Config{
		RedirectURI: "https://ui.example/oauth/callback",
	}, slog.New(slog.DiscardHandler))
	if err := manager.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	issuer, authorize, tokenEndpoint := authority.URL, authority.URL+"/authorize", authority.URL+"/token"
	hosts, scopes, secret := []string{strings.TrimPrefix(upstreamURL, "https://")}, []string{"repo"}, "synthetic-app-secret"
	if _, err := manager.PutApp(ctx, "", "custom-github", mcpauth.AppInput{Issuer: &issuer, ClientID: "test-client", ClientSecret: &secret,
		AuthorizationEndpoint: &authorize, TokenEndpoint: &tokenEndpoint, APIHosts: &hosts, DefaultScopes: &scopes}); err != nil {
		t.Fatal(err)
	}
	start, err := manager.StartAccount(ctx, vault.ID, "custom-github", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	result, err := manager.Complete(ctx, oauthrelay.Input{State: start.State, Code: "fixture-code"}, nil)
	if err != nil || result.Status != "connected" {
		t.Fatal("generic API account did not connect", err)
	}
	session, err := db.CreateScopedSession(ctx, store.CreateScopedSessionParams{VaultID: vault.ID, VaultRole: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	cp := brokercore.NewStoreCredentialProvider(accountCredentialStore{db, manager}, key)
	proxyURL, roots, proxy := setupProxy(t, brokercore.NewStoreSessionResolver(db), cp, func(options *Options) {
		options.BoundToken = session.ID
	})
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	upstreamRoots.AddCert(unrelated.Certificate())
	proxy.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots, ServerName: "127.0.0.1"}
	client := newTrustingClient(proxyURL, url.User("forged-client-identity"), roots)
	defer client.Transport.(*http.Transport).CloseIdleConnections()
	for _, path := range []string{"/user", "/user/", "/user/repos?page=2&per_page=10", "/search/repositories?q=fixture&page=2", "/repos/owner/repo/branches", "/search/code?q=test", "/arbitrary-api-route"} {
		req, _ := http.NewRequest("GET", upstreamURL+path, nil)
		req.Header.Set("Authorization", "Bearer "+mcpauth.AccessPlaceholderPrefix+result.Key)
		req.Header.Set("X-Vault", "forged-other-vault")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != 200 || !strings.Contains(string(body), "verified-fixture") {
			t.Fatalf("supported account request failed: status=%d error=%v", response.StatusCode, err)
		}
		if strings.Contains(string(body), token) || strings.Contains(fmtHeaders(response.Header), token) || strings.Contains(string(body), session.ID) {
			t.Fatal("proxy returned a credential or session identity to its caller")
		}
	}
	response, err := client.Get(unrelated.URL + "/user")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 200 || unrelatedCalls.Load() != 1 {
		t.Fatal("unrelated destination passthrough failed")
	}
	before := authenticated.Load()
	response, err = client.Get(strings.Replace(upstreamURL, "https://", "http://", 1) + "/user")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, response.Body)
	response.Body.Close()
	if response.StatusCode != 403 || authenticated.Load() != before {
		t.Fatal("HTTPS-only account credential was sent over plaintext")
	}
}

func fmtHeaders(headers http.Header) string {
	var builder strings.Builder
	headers.Write(&builder)
	return builder.String()
}
