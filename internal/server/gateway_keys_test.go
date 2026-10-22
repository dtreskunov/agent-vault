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

	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestStaticKeyAPIAndManagedServiceProtection(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	v, _ := db.GetVault(ctx, "default")
	_, token, err := db.CreateAgentWithGrantsAndToken(ctx, "key-owner", "", "owner", []store.AgentVaultGrantSpec{{VaultID: v.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New("127.0.0.1:0", db, make([]byte, 32), notify.New(nil), true, "http://127.0.0.1:12345", slog.New(slog.DiscardHandler))
	call := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token.ID)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if _, err := db.SetBrokerConfig(ctx, v.ID, `[{"name":"mcp-owned","host":"mcp.example.com","auth":{"type":"passthrough"}}]`); err != nil {
		t.Fatal(err)
	}
	body := `{"value":"synthetic-value","service":{"name":"test-key","host":"api.example.com","auth":{"type":"bearer","token":"TEST_KEY"}}}`
	if w := call("PUT", "/v1/vaults/default/keys/TEST_KEY", body); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	provider := s.CredentialProvider()
	if _, err := provider.Inject(ctx, v.ID, "api.example.com", 443, "/"); err != nil {
		t.Fatal(err)
	}
	w := call("GET", "/v1/credentials?vault=default", "")
	var list struct {
		Credentials []struct {
			Key        string
			UpdatedAt  string  `json:"updated_at"`
			LastUsedAt *string `json:"last_used_at"`
		}
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil || len(list.Credentials) != 1 || list.Credentials[0].LastUsedAt == nil || list.Credentials[0].UpdatedAt == "" {
		t.Fatal("static timestamps unavailable")
	}
	for _, test := range []struct{ method, path, body string }{
		{"DELETE", "/v1/vaults/default/services/mcp-owned", ""},
		{"PUT", "/v1/vaults/default/services/mcp-owned", `{"host":"evil.example.com","auth":{"type":"passthrough"}}`},
		{"PATCH", "/v1/vaults/default/services/mcp-owned", `{"enabled":false}`},
		{"PUT", "/v1/vaults/default/services", `{"services":[]}`},
		{"POST", "/v1/vaults/default/services", `{"services":[{"name":"mcp-owned","host":"evil.example.com","auth":{"type":"passthrough"}}]}`},
		{"DELETE", "/v1/vaults/default/services", ""},
	} {
		if w := call(test.method, test.path, test.body); w.Code != 409 {
			t.Fatalf("managed mutation %s returned %d", test.method, w.Code)
		}
	}
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			body := fmt.Sprintf(`{"host":"api-%d.example.com","auth":{"type":"passthrough"}}`, i)
			if w := call("PUT", fmt.Sprintf("/v1/vaults/default/services/parallel-%d", i), body); w.Code != 200 {
				t.Errorf("upsert failed %d", w.Code)
			}
		}(i)
	}
	group.Wait()
	services, err := s.loadServices(ctx, v.ID)
	if err != nil || len(services) != 10 {
		t.Fatal("concurrent upserts lost services")
	}
	if w := call("DELETE", "/v1/vaults/default/keys/TEST_KEY", ""); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := call("DELETE", "/v1/vaults/default/services/parallel-0", ""); w.Code != 200 {
		t.Fatal(w.Code)
	}
}
