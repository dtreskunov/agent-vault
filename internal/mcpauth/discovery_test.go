package mcpauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const publicInitialization = `{"jsonrpc":"2.0","id":"agent-vault-discovery","result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"public-mcp","version":"1"}}}`

func TestDiscoveryValidatesPublicMCP(t *testing.T) {
	for _, test := range []struct {
		name, contentType, body, message string
		public                           bool
	}{
		{name: "json", contentType: "application/json", body: publicInitialization, public: true},
		{name: "sse", contentType: "text/event-stream", body: "event: message\ndata: " + publicInitialization + "\n\n", public: true},
		{name: "sse-crlf", contentType: "text/event-stream", body: "event: message\r\ndata: " + publicInitialization + "\r\n\r\n", public: true},
		{name: "sse-multiline", contentType: "text/event-stream", body: "data: " + strings.Replace(publicInitialization, `"result":`, "\ndata: \"result\":", 1) + "\n\n", public: true},
		{name: "sse-notifications", contentType: "text/event-stream", body: ": keepalive\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\"}\n\ndata: " + publicInitialization + "\n\n", public: true},
		{name: "empty", contentType: "application/json", message: "empty response"},
		{name: "html", contentType: "text/html", body: "<html>synthetic-secret</html>", message: "valid MCP"},
		{name: "arbitrary-json", contentType: "application/json", body: `{}`, message: "valid MCP"},
		{name: "malformed-json", contentType: "application/json", body: `not json synthetic-secret`, message: "valid MCP"},
		{name: "wrong-id", contentType: "application/json", body: strings.Replace(publicInitialization, "agent-vault-discovery", "another-request", 1), message: "valid MCP"},
		{name: "missing-capabilities", contentType: "application/json", body: strings.Replace(publicInitialization, `"capabilities":{},`, "", 1), message: "valid MCP"},
		{name: "invalid-capabilities", contentType: "application/json", body: strings.Replace(publicInitialization, `"capabilities":{}`, `"capabilities":[]`, 1), message: "valid MCP"},
		{name: "rpc-error", contentType: "application/json", body: `{"jsonrpc":"2.0","id":"agent-vault-discovery","error":{"code":-32601,"message":"synthetic-secret"}}`, message: "valid MCP"},
		{name: "empty-sse", contentType: "text/event-stream", message: "empty response"},
		{name: "non-mcp-sse", contentType: "text/event-stream", body: "data: {}\n\n", message: "valid MCP"},
		{name: "oversized-json", contentType: "application/json", body: strings.Repeat(" ", 65537) + publicInitialization, message: "valid MCP"},
		{name: "oversized-sse", contentType: "text/event-stream", body: "data: " + strings.Repeat(" ", 65537) + publicInitialization + "\n\n", message: "valid MCP"},
		{name: "json-at-limit", contentType: "application/json", body: strings.Repeat(" ", 65536-len(publicInitialization)) + publicInitialization, public: true},
		{name: "json-over-limit", contentType: "application/json", body: strings.Repeat(" ", 65537-len(publicInitialization)) + publicInitialization, message: "valid MCP"},
		{name: "sse-at-limit", contentType: "text/event-stream", body: "data: " + strings.Repeat(" ", 65536-len(publicInitialization)-8) + publicInitialization + "\n\n", public: true},
		{name: "sse-over-limit", contentType: "text/event-stream", body: "data: " + strings.Repeat(" ", 65537-len(publicInitialization)-8) + publicInitialization + "\n\n", message: "valid MCP"},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, _, library := testManager(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
					t.Error("initialization must be an unauthenticated POST")
				}
				if r.Header.Get("Content-Type") != "application/json" ||
					r.Header.Get("Accept") != "application/json, text/event-stream" {
					t.Error("missing MCP request content negotiation")
				}
				var request struct {
					JSONRPC string         `json:"jsonrpc"`
					ID      string         `json:"id"`
					Method  string         `json:"method"`
					Params  map[string]any `json:"params"`
				}
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil ||
					request.JSONRPC != "2.0" || request.ID != "agent-vault-discovery" || request.Method != "initialize" ||
					request.Params["protocolVersion"] != "2025-03-26" {
					t.Error("invalid MCP initialization request", err)
				}
				w.Header().Set("Content-Type", test.contentType)
				fmt.Fprint(w, test.body)
			}))
			defer server.Close()
			m.client = server.Client()
			probe, err := m.Probe(context.Background(), library, server.URL+"/mcp")
			if test.public {
				if err != nil || probe.OAuth {
					t.Fatal("valid public MCP was not recognized", probe, err)
				}
				_, err = m.Start(context.Background(), library, server.URL+"/mcp")
				var failure *Failure
				if !errors.As(err, &failure) || failure.Code != "oauth_not_required" ||
					!strings.Contains(failure.Error(), "without authentication") {
					t.Fatal("public MCP sign-in did not explain that OAuth is unnecessary", err)
				}
			} else {
				var failure *Failure
				if !errors.As(err, &failure) || failure.Code != "invalid_mcp_response" ||
					!strings.Contains(failure.Error(), test.message) || !strings.Contains(failure.Error(), "HTTP 200") ||
					!strings.Contains(failure.Error(), "endpoint") || strings.Contains(failure.Error(), "synthetic-secret") {
					t.Fatal("invalid endpoint was not distinguished safely", probe, err)
				}
				if _, err := m.DiscoverScopes(context.Background(), library, server.URL+"/mcp", "", ""); err == nil {
					t.Fatal("invalid endpoint was presented as successful scope discovery")
				}
			}
			var states int
			if err := m.repo.db.QueryRow(`SELECT COUNT(*) FROM gateway_oauth_records`).Scan(&states); err != nil || states != 0 {
				t.Fatal("public or invalid discovery changed OAuth state", states, err)
			}
		})
	}
}

func TestDiscoveryClosesPublicSSEAfterInitialization(t *testing.T) {
	m, _, library := testManager(t)
	closed := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: "+publicInitialization+"\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(closed)
	}))
	defer server.Close()
	m.client = server.Client()
	m.client.Timeout = time.Second
	if probe, err := m.Probe(context.Background(), library, server.URL+"/mcp"); err != nil || probe.OAuth {
		t.Fatal("public SSE discovery waited for the stream to finish", probe, err)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("discovery left an SSE stream open")
	}
}

func TestDiscoveryLegacySSEFallback(t *testing.T) {
	for _, mode := range []string{"public", "protected", "non-mcp"} {
		t.Run(mode, func(t *testing.T) {
			m, _, library := testManager(t)
			initialized := make(chan struct{}, 1)
			var server *httptest.Server
			server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					t.Error("legacy discovery sent credentials")
				}
				switch r.URL.Path {
				case "/sse":
					if r.Method == http.MethodPost {
						w.WriteHeader(http.StatusMethodNotAllowed)
						return
					}
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "event: endpoint\ndata: /messages?session=synthetic\n\n")
					w.(http.Flusher).Flush()
					select {
					case <-initialized:
						result := publicInitialization
						if mode == "non-mcp" {
							result = `{"synthetic-secret":"not an MCP response"}`
						}
						fmt.Fprint(w, "event: message\ndata: "+result+"\n\n")
					case <-r.Context().Done():
					}
				case "/messages":
					if r.Method != http.MethodPost || r.URL.Query().Get("session") != "synthetic" {
						t.Error("legacy initialization lost endpoint or method")
					}
					if mode == "protected" {
						w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+server.URL+`/.well-known/oauth-protected-resource/sse"`)
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					w.WriteHeader(http.StatusAccepted)
					initialized <- struct{}{}
				case "/.well-known/oauth-protected-resource/sse":
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]any{
						"resource": server.URL + "/sse", "authorization_servers": []string{server.URL},
					})
				case "/.well-known/oauth-authorization-server":
					w.Header().Set("Content-Type", "application/json")
					json.NewEncoder(w).Encode(map[string]any{
						"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
						"token_endpoint": server.URL + "/token", "code_challenge_methods_supported": []string{"S256"},
					})
				default:
					t.Error("unexpected discovery endpoint", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			m.client = server.Client()
			m.client.Timeout = time.Second
			probe, err := m.Probe(context.Background(), library, server.URL+"/sse")
			if mode == "non-mcp" {
				var failure *Failure
				if !errors.As(err, &failure) || failure.Code != "invalid_mcp_response" ||
					strings.Contains(failure.Error(), "synthetic-secret") {
					t.Fatal("legacy endpoint event was accepted without a valid initialization", probe, err)
				}
			} else if err != nil || probe.OAuth != (mode == "protected") {
				t.Fatal("legacy initialization did not determine authentication correctly", probe, err)
			}
		})
	}
}

func TestDiscoveryTerminatesTemporarySessions(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
		valid  bool
	}{
		{"successful", http.StatusOK, publicInitialization, true},
		{"delete-unsupported", http.StatusMethodNotAllowed, publicInitialization, true},
		{"invalid-response", http.StatusOK, "", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, _, library := testManager(t)
			deleted := make(chan struct{}, 1)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					version := "2024-11-05"
					if !test.valid {
						version = "2025-03-26"
					}
					if r.Header.Get("Mcp-Session-Id") != "synthetic-session" ||
						r.Header.Get("MCP-Protocol-Version") != version || r.Header.Get("Authorization") != "" {
						t.Error("cleanup lost the temporary session/version or sent credentials")
					}
					deleted <- struct{}{}
					w.WriteHeader(test.status)
					return
				}
				w.Header().Set("Mcp-Session-Id", "synthetic-session")
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, strings.Replace(test.body, "2025-03-26", "2024-11-05", 1))
			}))
			defer server.Close()
			m.client = server.Client()
			probe, err := m.Probe(context.Background(), library, server.URL+"/mcp")
			select {
			case <-deleted:
			default:
				t.Fatal("temporary session cleanup was skipped", probe, err)
			}
			if (err == nil) != test.valid {
				t.Fatal("temporary session cleanup changed discovery", probe, err)
			}
		})
	}
}

func TestDiscoverySessionCleanupIsBounded(t *testing.T) {
	m, _, library := testManager(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			<-r.Context().Done()
			return
		}
		w.Header().Set("Mcp-Session-Id", "synthetic-session")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, publicInitialization)
	}))
	defer server.Close()
	m.client = server.Client()
	started := time.Now()
	probe, err := m.Probe(context.Background(), library, server.URL+"/mcp")
	if err != nil || probe.OAuth || time.Since(started) > 3*time.Second {
		t.Fatal("cleanup failure blocked or changed public discovery", probe, err)
	}
}
