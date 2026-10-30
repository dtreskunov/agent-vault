package mcpauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestScopeDiscoveryMCPIsReadOnly(t *testing.T) {
	m, _, library := testManager(t)
	a := newAuthority(t, m)
	options, err := m.DiscoverScopes(context.Background(), library, a.server.URL+"/mcp", "", "")
	if err != nil || options.Source != "resource" || !reflect.DeepEqual(options.Scopes, []string{"read"}) || !options.OAuth {
		t.Fatal("incorrect resource scope options", options, err)
	}
	a.mu.Lock()
	registrations, exchanges := a.registrations, a.exchanges
	a.mu.Unlock()
	if registrations != 0 || exchanges != 0 {
		t.Fatal("scope inspection started authorization", registrations, exchanges)
	}
	var states int
	if err := m.repo.db.QueryRow(`SELECT COUNT(*) FROM gateway_oauth_records WHERE kind='state'`).Scan(&states); err != nil || states != 0 {
		t.Fatal("scope inspection created consent state", states, err)
	}
	public, err := m.DiscoverScopes(context.Background(), library, a.server.URL+"/public", "", "")
	if err != nil || public.OAuth || public.Source != "not_advertised" || len(public.Scopes) != 0 {
		t.Fatal("public resource was treated as OAuth", public, err)
	}
}

func TestScopeDiscoveryIssuerMetadata(t *testing.T) {
	for _, mode := range []string{"supported", "missing", "mismatch", "malformed", "failure", "invalid-scope", "oidc", "scopes-in-oidc"} {
		t.Run(mode, func(t *testing.T) {
			m, _, library := testManager(t)
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" {
					t.Error("scope discovery sent credentials or a non-GET request")
				}
				if mode == "missing" || (mode == "oidc" && r.URL.Path == "/.well-known/oauth-authorization-server") {
					w.WriteHeader(404)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if mode == "scopes-in-oidc" && r.URL.Path == "/.well-known/oauth-authorization-server" {
					json.NewEncoder(w).Encode(map[string]any{"issuer": server.URL})
					return
				}
				if mode == "failure" {
					w.WriteHeader(503)
					return
				}
				if mode == "malformed" {
					w.Write([]byte(`not json`))
					return
				}
				issuer := server.URL
				if mode == "mismatch" {
					issuer = "https://other.example.com"
				}
				scopes := []string{"write", "read", "read"}
				if mode == "invalid-scope" {
					scopes = []string{"not a scope"}
				}
				// Scope inspection does not require PKCE fields in otherwise
				// valid provider metadata; MCP authorization still does.
				json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "scopes_supported": scopes})
			}))
			defer server.Close()
			m.client = server.Client()
			options, err := m.DiscoverScopes(context.Background(), library, "", "", server.URL)
			if mode == "mismatch" || mode == "malformed" || mode == "failure" || mode == "invalid-scope" {
				if err == nil {
					t.Fatal("invalid provider metadata was accepted", options)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "missing" {
				if options.Source != "not_advertised" || len(options.Scopes) != 0 {
					t.Fatal("missing discovery was treated as an empty permission policy", options)
				}
			} else if options.Source != "authorization_server" || !reflect.DeepEqual(options.Scopes, []string{"read", "write"}) {
				t.Fatal("provider scopes were not normalized", options)
			}
		})
	}
}

func TestScopeDiscoveryConfiguredAppUsesItsIssuer(t *testing.T) {
	m, _, library := testManager(t)
	a := newAuthority(t, m)
	if err := m.StoreApp(context.Background(), library, Client{AppID: "private-app", Issuer: a.server.URL, ID: "client", Secret: "synthetic-client-secret"}); err != nil {
		t.Fatal(err)
	}
	options, err := m.DiscoverScopes(context.Background(), library, "", "private-app", "")
	if err != nil || options.Issuer != a.server.URL || options.Source != "not_advertised" {
		t.Fatal("configured app metadata was not inspected", options, err)
	}
	if _, err := m.DiscoverScopes(context.Background(), library, "", "missing", ""); err == nil {
		t.Fatal("unknown private app was accepted")
	}
}

func TestCanonicalScopesRetainsDefaultSemantics(t *testing.T) {
	unspecified, err := CanonicalScopes(nil)
	if err != nil || unspecified != nil {
		t.Fatal("unspecified scopes lost default semantics")
	}
	empty, err := CanonicalScopes([]string{})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("explicit empty scopes lost their semantics")
	}
	actual, err := CanonicalScopes([]string{"write", "read", "write", "repo,read:user"})
	if err != nil || !reflect.DeepEqual(actual, []string{"read", "repo,read:user", "write"}) {
		t.Fatal("scope values were not treated as an opaque set", actual, err)
	}
	if _, err := CanonicalScopes([]string{"bad scope"}); err == nil {
		t.Fatal("invalid scope was accepted")
	}
}
