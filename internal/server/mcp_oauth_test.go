package server

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/gatewaytest"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestMCPOAuthAPIAndVaultSocket(t *testing.T) {
	gatewaytest.UseLoopbackDNS(t)
	t.Setenv("AGENT_VAULT_OAUTH_REDIRECT_URL", "https://ui.example.com/oauth/callback")
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "true")
	t.Setenv("AGENT_VAULT_HEADLESS", "true")
	t.Setenv("AGENT_VAULT_DEV_MODE", "true")
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "127.0.0.1")
	root, err := os.MkdirTemp("", "av-mcp-api-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	db, err := store.Open(filepath.Join(root, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	vault1, err := db.CreateVault(ctx, "first-group")
	if err != nil {
		t.Fatal(err)
	}
	vault2, err := db.CreateVault(ctx, "second-group")
	if err != nil {
		t.Fatal(err)
	}
	_, host, err := db.CreateAgentWithGrantsAndToken(ctx, "host", "", "owner", []store.AgentVaultGrantSpec{
		{VaultID: vault1.ID, Role: "admin"}, {VaultID: vault2.ID, Role: "admin"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := db.CreateAgentWithGrantsAndToken(ctx, "other", "", "member", []store.AgentVaultGrantSpec{
		{VaultID: vault2.ID, Role: "member"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var registered, revoked, deleted atomic.Int32
	var authority *httptest.Server
	var issuer, resource string
	authority = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/mcp":
			if r.Header.Get("Authorization") != "" && r.URL.Query().Get("deny") == "" {
				if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer synthetic-token-client-") || r.Header.Get("Proxy-Authorization") != "" {
					t.Error("socket injection lost bound identity")
				}
				fmt.Fprint(w, `{"egress":"authenticated"}`)
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", resource_metadata="`+issuer+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(401)
		case "/.well-known/oauth-protected-resource/mcp":
			json.NewEncoder(w).Encode(map[string]any{"resource": resource, "authorization_servers": []string{issuer}, "scopes_supported": []string{"read"}})
		case "/.well-known/oauth-authorization-server":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token",
				"registration_endpoint": issuer + "/register", "revocation_endpoint": issuer + "/revoke",
				"code_challenge_methods_supported": []string{"S256"}, "authorization_response_iss_parameter_supported": true,
			})
		case "/register":
			n := registered.Add(1)
			json.NewEncoder(w).Encode(map[string]any{"client_id": fmt.Sprintf("client-%d", n), "token_endpoint_auth_method": "none",
				"registration_client_uri": issuer + "/client", "registration_access_token": "synthetic-management"})
		case "/token":
			r.ParseForm()
			if r.Form.Get("resource") != resource || r.Form.Get("redirect_uri") != "https://ui.example.com/oauth/callback" {
				t.Error("MCP exchange lost resource or redirect")
			}
			json.NewEncoder(w).Encode(map[string]any{"access_token": "synthetic-token-" + r.Form.Get("client_id"),
				"refresh_token": "synthetic-refresh", "expires_in": 3600, "token_type": "Bearer"})
		case "/revoke":
			revoked.Add(1)
			fmt.Fprint(w, `{}`)
		case "/client":
			deleted.Add(1)
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer authority.Close()
	issuer = strings.Replace(authority.URL, "127.0.0.1", "localhost", 1)
	resource = strings.Replace(authority.URL, "127.0.0.1", "localhost.localdomain", 1) + "/mcp"
	key := make([]byte, 32)
	logger := slog.New(slog.DiscardHandler)
	srv := New("127.0.0.1:0", db, key, notify.New(nil), true, "http://127.0.0.1:12345", logger)
	provider, err := ca.New(key, ca.Options{Dir: filepath.Join(root, "ca")})
	if err != nil {
		t.Fatal(err)
	}
	proxy := mitm.New("", mitm.Options{CA: provider, Sessions: srv.SessionResolver(), Credentials: srv.CredentialProvider(),
		Logger: logger, FilterResponse: srv.FilterMCPResponse})
	srv.AttachMITM(proxy)
	socketRoot := filepath.Join(root, "sessions")
	if err := srv.AttachSocketSessions(socketRoot); err != nil {
		t.Fatal(err)
	}
	defer srv.socketSessions.Close()
	api := func(method, path string, body any, token string) *httptest.ResponseRecorder {
		data, _ := json.Marshal(body)
		request := httptest.NewRequest(method, path, strings.NewReader(string(data)))
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, request)
		for _, secret := range []string{"synthetic-token-", "synthetic-refresh", "synthetic-management"} {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("MCP API revealed credentials")
			}
		}
		return w
	}
	if w := api("POST", "/v1/vaults/first-group/mcp-oauth/probe", map[string]string{"resource_url": resource}, host.ID); w.Code != 200 || registered.Load() != 0 {
		t.Fatal("probe registered a client")
	}
	var keys, clients, sockets []string
	for _, vault := range []string{"first-group", "second-group"} {
		w := api("POST", "/v1/vaults/"+vault+"/mcp-oauth/start", map[string]string{"resource_url": resource}, host.ID)
		var started struct {
			State        string
			AuthorizeURL string `json:"authorize_url"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil || w.Code != 200 {
			t.Fatalf("start returned %d", w.Code)
		}
		u, _ := url.Parse(started.AuthorizeURL)
		clients = append(clients, u.Query().Get("client_id"))
		if vault == "first-group" {
			w := api("POST", "/v1/oauth/complete", map[string]string{"state": started.State, "code": "synthetic-code", "iss": issuer}, other.ID)
			if w.Code != 403 {
				t.Fatal("different vault completed a sign-in")
			}
		}
		w = api("POST", "/v1/oauth/complete", map[string]string{"state": started.State, "code": "synthetic-code", "iss": issuer}, host.ID)
		var result struct{ Status, Key string }
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || result.Status != "connected" {
			t.Fatalf("completion returned %d", w.Code)
		}
		keys = append(keys, result.Key)
		dir := filepath.Join(socketRoot, vault)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		w = api("POST", "/v1/socket-sessions", map[string]string{"vault": vault, "label": "mcp-test", "dir": dir}, host.ID)
		var item struct {
			SocketPath string `json:"socket_path"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil || w.Code != 201 {
			t.Fatal("socket session failed")
		}
		sockets = append(sockets, item.SocketPath)
	}
	if clients[0] == clients[1] {
		t.Fatal("vaults shared a client ID")
	}
	viaSocket := func(path, target string, websocket ...bool) *http.Response {
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		headers := "Connection: close\r\n"
		if len(websocket) != 0 && websocket[0] {
			headers = "Connection: Upgrade\r\nUpgrade: websocket\r\n"
		}
		fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: ignored.example\r\nProxy-Authorization: rubbish\r\n%s\r\n", target, headers)
		response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "GET"})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { response.Body.Close() })
		return response
	}
	response := viaSocket(sockets[0], resource)
	if response.StatusCode != 200 {
		t.Fatalf("MCP socket request returned %d", response.StatusCode)
	}
	io.Copy(io.Discard, response.Body)
	response = viaSocket(sockets[0], resource+"?deny=1")
	if response.StatusCode != 401 || strings.Contains(response.Header.Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatal("MCP challenge escaped to container")
	}
	response = viaSocket(sockets[0], resource+"?deny=1", true)
	if response.StatusCode != 401 || strings.Contains(response.Header.Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatal("MCP challenge escaped through a WebSocket handshake")
	}
	w := api("GET", "/v1/vaults/first-group/mcp-oauth", nil, host.ID)
	var listed []struct {
		LastUsedAt *string `json:"last_used_at"`
		Status     string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listed); err != nil || w.Code != 200 || len(listed) != 1 || listed[0].LastUsedAt == nil {
		t.Fatal("MCP account usage was not recorded")
	}
	if w := api("POST", "/v1/credentials", map[string]any{"vault": "first-group", "credentials": map[string]string{keys[0]: "replacement"}}, host.ID); w.Code != 409 {
		t.Fatal("generic update overwrote managed MCP credentials")
	}
	if w := api("DELETE", "/v1/vaults/first-group/mcp-oauth/"+keys[0], nil, host.ID); w.Code != 204 {
		t.Fatal("disconnect failed")
	}
	response = viaSocket(sockets[1], resource)
	if response.StatusCode != 200 {
		t.Fatal("disconnect broke the other vault's socket")
	}
	io.Copy(io.Discard, response.Body)
	if w := api("DELETE", "/v1/vaults/second-group", nil, host.ID); w.Code != 200 {
		t.Fatal("MCP vault deletion failed")
	}
	if deleted.Load() != 2 || revoked.Load() != 4 {
		t.Fatal("disconnect or vault delete skipped remote cleanup")
	}
}
