package blindtunnel_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestVaultSettingsAPI(t *testing.T) {
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "tunnel")
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := db.GetVault(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := db.CreateAgentWithGrantsAndToken(context.Background(), "host", "", "owner",
		[]store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New("127.0.0.1:0", db, make([]byte, 32), notify.New(nil), true, "http://localhost", slog.New(slog.DiscardHandler))
	for _, test := range []struct {
		method, body string
		code         int
		mode         string
	}{
		{"GET", "", 200, "tunnel"},
		{"PATCH", `{"unmatched_host_mode":"deny"}`, 200, "deny"},
		{"GET", "", 200, "deny"},
		{"PATCH", `{"unmatched_host_mode":"bogus"}`, 400, ""},
		{"GET", "", 200, "deny"},
		{"PATCH", `{"unmatched_host_mode":""}`, 200, "tunnel"},
		{"PATCH", `{"unmatched_host_mode":"deny","unmatched_host_policy":"deny"}`, 400, ""},
	} {
		r := httptest.NewRequest(test.method, "/v1/vaults/default/settings", strings.NewReader(test.body))
		r.Header.Set("Authorization", "Bearer "+token.ID)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if w.Code != test.code {
			t.Fatalf("%s settings: got %d, want %d", test.method, w.Code, test.code)
		}
		if test.mode != "" {
			var result map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result["unmatched_host_mode"] != test.mode {
				t.Fatal("mode missing from settings response")
			}
		}
	}
}
