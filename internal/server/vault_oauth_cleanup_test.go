package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mcpauth"
	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestVaultDeletionCleansProviderAccountsAndOverridesOnly(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "127.0.0.1")
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	removed, err := db.CreateVault(ctx, "removed-group")
	if err != nil {
		t.Fatal(err)
	}
	kept, err := db.CreateVault(ctx, "kept-group")
	if err != nil {
		t.Fatal(err)
	}
	_, owner, err := db.CreateAgentWithGrantsAndToken(ctx, "cleanup-owner", "", "owner", []store.AgentVaultGrantSpec{
		{VaultID: removed.ID, Role: "admin"}, {VaultID: kept.ID, Role: "admin"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var revoked atomic.Int32
	revocation := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if !strings.HasPrefix(r.Form.Get("token"), "removed-") {
			t.Error("another vault's token was revoked")
		}
		revoked.Add(1)
		io.WriteString(w, "{}")
	}))
	defer revocation.Close()
	key := make([]byte, 32)
	s := New("127.0.0.1:0", db, key, notify.New(nil), true, "http://127.0.0.1:12345", slog.New(slog.DiscardHandler))
	secret := "synthetic"
	for _, vault := range []string{"", removed.ID, kept.ID} {
		if _, err := s.mcpOAuth.PutApp(ctx, vault, "google", mcpauth.AppInput{Issuer: new("https://accounts.google.com"), ClientID: "client-" + vault, ClientSecret: &secret}); err != nil {
			t.Fatal(err)
		}
	}
	sqlDB, _ := db.GatewaySQL()
	seed := func(v *store.Vault, prefix string) {
		for _, name := range []string{"OAUTH_TEST", "MCP_TEST"} {
			account := mcpauth.Account{Key: name, Issuer: "https://accounts.google.com",
				AccessToken: prefix + "access", RefreshToken: prefix + "refresh",
				Metadata: oauthex.AuthServerMeta{RevocationEndpoint: revocation.URL},
				Client:   mcpauth.Client{Kind: "app", ID: "client-" + v.ID, Secret: secret, Source: "vault"}}
			kind := "mcp_oauth"
			if strings.HasPrefix(name, "OAUTH_") {
				account.AppID = "google"
				kind = "oauth_app"
			}
			data, err := json.Marshal(account)
			if err != nil {
				t.Fatal(err)
			}
			ct, nonce, err := crypto.Encrypt(data, key)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := sqlDB.Exec(`INSERT INTO gateway_oauth_records(vault_id,kind,record_key,ciphertext,nonce) VALUES (?,'account',?,?,?)`, v.ID, name, ct, nonce); err != nil {
				t.Fatal(err)
			}
			if _, err := db.SetCredential(ctx, v.ID, name, ct, nonce); err != nil {
				t.Fatal(err)
			}
			if _, err := sqlDB.Exec(`UPDATE credentials SET type=? WHERE vault_id=? AND key=?`, kind, v.ID, name); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.SetBrokerConfig(ctx, v.ID, `[{"name":"oauth-test-a","host":"gmail.googleapis.com","auth":{"type":"bearer","token":"OAUTH_TEST"}},{"name":"mcp-test","host":"mcp.example.com","auth":{"type":"bearer","token":"MCP_TEST"}}]`); err != nil {
			t.Fatal(err)
		}
	}
	seed(removed, "removed-")
	seed(kept, "kept-")
	request := httptest.NewRequest("DELETE", "/v1/vaults/removed-group", nil)
	request.Header.Set("Authorization", "Bearer "+owner.ID)
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, request)
	if w.Code != 200 {
		t.Fatalf("vault deletion returned %d", w.Code)
	}
	if revoked.Load() != 4 {
		t.Fatalf("provider/MCP access+refresh tokens not all revoked: %d", revoked.Load())
	}
	for _, table := range []string{"gateway_oauth_records", "credentials", "broker_configs"} {
		var count int
		if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE vault_id=?`, removed.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("deleted vault retained %s records", table)
		}
	}
	if app, err := s.mcpOAuth.GetApp(ctx, "", "google"); err != nil || app.ClientID != "client-" {
		t.Fatal("install app removed")
	}
	if app, err := s.mcpOAuth.GetApp(ctx, kept.ID, "google"); err != nil || app.ClientID != "client-"+kept.ID {
		t.Fatal("other vault override removed")
	}
	accounts, err := s.mcpOAuth.List(ctx, kept.ID)
	if err != nil || len(accounts) != 2 {
		t.Fatal("other vault accounts removed")
	}
	cfg, err := db.GetBrokerConfig(ctx, kept.ID)
	if err != nil || !strings.Contains(cfg.ServicesJSON, "oauth-test-a") {
		t.Fatal("other vault services removed")
	}
}
