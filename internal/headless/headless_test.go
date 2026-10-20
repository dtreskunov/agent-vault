package headless_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/headless"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestBootstrapAndRecovery(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "host-token")
	t.Setenv("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE", path)
	db, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := headless.Bootstrap(ctx, db); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("token file is not private")
	}
	agent, err := db.GetAgentByName(ctx, headless.AgentName)
	if err != nil || agent.Role != "owner" || len(agent.Vaults) != 1 || agent.Vaults[0].Role != "admin" {
		t.Fatal("bootstrap owner or default grant missing")
	}
	if n, err := db.CountUsers(ctx); err != nil || n != 0 {
		t.Fatal("bootstrap created a human account")
	}
	if err := headless.Bootstrap(ctx, db); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if string(first) != string(second) {
		t.Fatal("bootstrap silently rotated the token")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := headless.Bootstrap(ctx, db); err == nil || !strings.Contains(err.Error(), "agent rotate nanoclaw-host") {
		t.Fatal("missing token file did not require explicit recovery")
	}
	if err := headless.Rotate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if sess, _ := db.GetSession(ctx, strings.TrimSpace(string(first))); sess != nil {
		t.Fatal("old token survived rotation")
	}
	if err := headless.Bootstrap(ctx, db); err != nil {
		t.Fatal(err)
	}
}

func TestHeadlessHTTP(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "true")
	t.Setenv("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE", filepath.Join(t.TempDir(), "host-token"))
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := headless.Bootstrap(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(os.Getenv("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE"))
	token := strings.TrimSpace(string(data))
	srv := server.New("127.0.0.1:0", db, make([]byte, 32), notify.New(nil), true, "http://localhost", slog.New(slog.DiscardHandler))
	for _, path := range []string{"/", "/assets/app.js", "/login", "/v1/auth/register", "/v1/auth/login",
		"/v1/auth/reset-password", "/v1/users/invites", "/v1/vaults/default/users", "/v1/admin/email/test"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", path, strings.NewReader("{}"))
		r.Header.Set("Authorization", "Bearer "+token)
		srv.Handler().ServeHTTP(w, r)
		if w.Code != 404 {
			t.Errorf("%s: got %d, want 404", path, w.Code)
		}
	}
	r := httptest.NewRequest("POST", "/v1/vaults", strings.NewReader(`{"name":"ag-1780956116163-prz9h2"}`))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("host vault creation: %d", w.Code)
	}
	agent, _ := db.GetAgentByName(context.Background(), headless.AgentName)
	vault, _ := db.GetVault(context.Background(), "ag-1780956116163-prz9h2")
	if role, err := db.GetVaultRole(context.Background(), agent.ID, vault.ID); err != nil || role != "admin" {
		t.Fatal("host did not become vault admin")
	}
	r = httptest.NewRequest("GET", "/v1/vaults", nil)
	r.AddCookie(&http.Cookie{Name: "av_session", Value: token})
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("cookie auth remained enabled: %d", w.Code)
	}
}
