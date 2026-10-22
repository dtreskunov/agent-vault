package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestOAuthAppsAPIWriteOnlyAndRoles(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	vault, _ := db.GetVault(ctx, "default")
	_, owner, err := db.CreateAgentWithGrantsAndToken(ctx, "app-owner", "", "owner", []store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, member, err := db.CreateAgentWithGrantsAndToken(ctx, "app-member", "", "member", []store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New("127.0.0.1:0", db, make([]byte, 32), notify.New(nil), true, "http://127.0.0.1:12345", slog.New(slog.DiscardHandler))
	call := func(method, path, body, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "synthetic-secret") {
			t.Fatal("app secret returned")
		}
		return w
	}
	if w := call("PUT", "/v1/oauth-apps/google", `{"client_id":"id","client_secret":"synthetic-secret"}`, member.ID); w.Code != 403 {
		t.Fatal("non-owner set install app")
	}
	if w := call("PUT", "/v1/oauth-apps/google", `{"client_id":"id"}`, owner.ID); w.Code != 400 {
		t.Fatal("missing first secret accepted")
	}
	if w := call("PUT", "/v1/oauth-apps/google", `{"client_id":"id","client_secret":"synthetic-secret"}`, owner.ID); w.Code != 200 {
		t.Fatal(w.Code)
	}
	w := call("GET", "/v1/oauth-apps/google", "", owner.ID)
	var info map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &info); err != nil || info["client_id"] != "id" || info["accounts_all_vaults"] != float64(0) {
		t.Fatal("install app metadata shape")
	}
	if w := call("PUT", "/v1/vaults/default/oauth-apps/google", `{"client_id":"local","client_secret":"synthetic-secret"}`, member.ID); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := call("DELETE", "/v1/vaults/default/oauth-apps/google", "", member.ID); w.Code != 204 {
		t.Fatal(w.Code)
	}
	if w := call("GET", "/v1/oauth/providers", "", owner.ID); w.Code != 200 || !strings.Contains(w.Body.String(), "gmail-read") {
		t.Fatal("catalog missing")
	}
}
