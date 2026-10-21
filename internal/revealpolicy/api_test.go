package revealpolicy_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/revealpolicy"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestAllRolesHaveWriteOnlyCredentials(t *testing.T) {
	ctx := context.Background()
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "true")
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := revealpolicy.Configure(ctx, db); err != nil {
		t.Fatal(err)
	}
	vault, err := db.GetVault(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	secrets := []string{"synthetic-static-value", "synthetic-access-token", "synthetic-refresh-token", "synthetic-client-secret"}
	encrypt := func(value string) ([]byte, []byte) {
		ct, nonce, err := crypto.Encrypt([]byte(value), key)
		if err != nil {
			t.Fatal(err)
		}
		return ct, nonce
	}
	ct, nonce := encrypt(secrets[0])
	if _, err := db.SetCredential(ctx, vault.ID, "STATIC_KEY", ct, nonce); err != nil {
		t.Fatal(err)
	}
	cs, csNonce := encrypt(secrets[3])
	if err := db.SetCredentialOAuth(ctx, &store.CredentialOAuth{
		VaultID: vault.ID, CredentialKey: "OAUTH_KEY", ClientID: "public-client",
		TokenURL: "https://auth.example.com/token", ClientSecretCT: cs, ClientSecretNonce: csNonce,
	}); err != nil {
		t.Fatal(err)
	}
	access, accessNonce := encrypt(secrets[1])
	refresh, refreshNonce := encrypt(secrets[2])
	if err := db.UpdateCredentialOAuthTokens(ctx, vault.ID, "OAUTH_KEY", access, accessNonce, refresh, refreshNonce, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetCredential(ctx, vault.ID, "BROKEN_KEY", []byte("invalid-ciphertext"), []byte("invalid-nonce")); err != nil {
		t.Fatal(err)
	}
	srv := server.New("127.0.0.1:0", db, key, notify.New(nil), true, "http://localhost", slog.New(slog.DiscardHandler))
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		for _, secret := range secrets {
			if strings.Contains(w.Body.String(), secret) {
				t.Fatal("credential value escaped through the API")
			}
		}
		return w
	}
	var ownerToken string
	for i, role := range []string{"admin", "member", "proxy"} {
		for _, kind := range []string{"agent", "user", "scoped"} {
			var sess *store.Session
			switch kind {
			case "agent":
				instanceRole := "member"
				if role == "admin" {
					instanceRole = "owner"
				}
				_, sess, err = db.CreateAgentWithGrantsAndToken(ctx, fmt.Sprintf("agent-%d", i), "", instanceRole,
					[]store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: role}}, nil)
				if role == "admin" && err == nil {
					ownerToken = sess.ID
				}
			case "user":
				var user *store.User
				user, err = db.CreateUser(ctx, fmt.Sprintf("user-%d@example.com", i), []byte("hash"), []byte("salt"), "member", 1, 1024, 1)
				if err == nil {
					err = db.GrantVaultRole(ctx, user.ID, "user", vault.ID, role)
				}
				if err == nil {
					sess, err = db.CreateUserSession(ctx, store.CreateUserSessionParams{UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)})
				}
			case "scoped":
				sess, err = db.CreateScopedSession(ctx, store.CreateScopedSessionParams{VaultID: vault.ID, VaultRole: role})
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, suffix := range []string{"", "&key=STATIC_KEY", "&key=OAUTH_KEY", "&key=DYNAMIC_KEY", "&key=BROKEN_KEY"} {
				w := request("GET", "/v1/credentials?vault=default&reveal=true"+suffix, sess.ID, "")
				if w.Code != 403 || !strings.Contains(w.Body.String(), "credential_reveal_disabled") {
					t.Fatalf("%s/%s reveal was not denied by instance policy: %d", kind, role, w.Code)
				}
			}
			w := request("GET", "/v1/credentials?vault=default", sess.ID, "")
			if w.Code != 200 {
				t.Fatalf("%s/%s metadata listing returned %d", kind, role, w.Code)
			}
			if role != "proxy" {
				if w := request("GET", "/v1/credentials/oauth/status?vault=default&key=OAUTH_KEY", sess.ID, ""); w.Code != 200 {
					t.Fatalf("OAuth status returned %d", w.Code)
				}
			}
		}
	}
	w := request("GET", "/v1/admin/settings", ownerToken, "")
	var settings map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &settings); err != nil || w.Code != 200 || settings["reveal_disabled"] != true {
		t.Fatal("owner cannot read effective reveal_disabled setting")
	}
	if w := request("PUT", "/v1/admin/settings", ownerToken, `{"reveal_disabled":false}`); w.Code != 403 {
		t.Fatal("owner API downgraded write-only protection")
	}
	if w := request("POST", "/v1/credentials", ownerToken, `{"vault":"default","credentials":{"STATIC_KEY":"replacement"}}`); w.Code != 200 {
		t.Fatal("write-only credentials could not be updated")
	}
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "")
	restarted := server.New("127.0.0.1:0", db, key, notify.New(nil), true, "http://localhost", slog.New(slog.DiscardHandler))
	r := httptest.NewRequest("GET", "/v1/credentials?vault=default&reveal=true&key=STATIC_KEY", nil)
	r.Header.Set("Authorization", "Bearer "+ownerToken)
	w = httptest.NewRecorder()
	restarted.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("clearing the environment bypassed the persisted policy")
	}
}

type failingPolicyStore struct{ store.Store }

func (failingPolicyStore) GetSetting(context.Context, string) (string, error) {
	return "", errors.New("test policy lookup failed")
}

func TestRevealFailsClosedOnPolicyFailure(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := db.GetVault(context.Background(), "default")
	_, token, err := db.CreateAgentWithGrantsAndToken(context.Background(), "owner", "", "owner",
		[]store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	srv := server.New("127.0.0.1:0", failingPolicyStore{db}, make([]byte, 32), notify.New(nil), true, "http://localhost", slog.New(slog.DiscardHandler))
	r := httptest.NewRequest("GET", "/v1/credentials?vault=default&reveal=true", nil)
	r.Header.Set("Authorization", "Bearer "+token.ID)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	if w.Code != 500 {
		t.Fatal("policy lookup failure did not fail closed")
	}
}
