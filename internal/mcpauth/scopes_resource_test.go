package mcpauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestScopeDiscoveryPrefersResourceAndFallsBackToIssuer(t *testing.T) {
	for _, resourceAdvertises := range []bool{false, true} {
		t.Run(map[bool]string{false: "issuer-fallback", true: "resource-preferred"}[resourceAdvertises], func(t *testing.T) {
			m, _, library := testManager(t)
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/mcp":
					w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/resource"`)
					w.WriteHeader(401)
				case "/resource":
					metadata := map[string]any{"resource": server.URL + "/mcp", "authorization_servers": []string{server.URL}}
					if resourceAdvertises {
						metadata["scopes_supported"] = []string{"resource:read"}
					}
					json.NewEncoder(w).Encode(metadata)
				case "/.well-known/oauth-authorization-server":
					json.NewEncoder(w).Encode(map[string]any{
						"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize", "token_endpoint": server.URL + "/token",
						"code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"issuer:read", "issuer:write"},
					})
				default:
					t.Error("scope discovery attempted an unexpected endpoint", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			m.client = server.Client()
			result, err := m.DiscoverScopes(context.Background(), library, server.URL+"/mcp", "", "")
			if err != nil {
				t.Fatal(err)
			}
			expected, source := []string{"issuer:read", "issuer:write"}, "authorization_server"
			if resourceAdvertises {
				expected, source = []string{"resource:read"}, "resource"
			}
			if result.Source != source || !reflect.DeepEqual(result.Scopes, expected) {
				t.Fatal("scope sources were mixed or precedence was ignored", result)
			}
		})
	}
}
