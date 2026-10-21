package oauthrelay_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
	"github.com/Infisical/agent-vault/internal/server"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestConfiguration(t *testing.T) {
	for _, value := range []string{"https://ui.example.com/oauth/callback", "http://127.0.0.1:12345/callback"} {
		t.Setenv("AGENT_VAULT_OAUTH_REDIRECT_URL", value)
		cfg, err := oauthrelay.Configuration("http://127.0.0.1:14321")
		if err != nil || cfg.RedirectURI != value || !strings.HasSuffix(cfg.MetadataURI, "/oauth/client-metadata.json") {
			t.Fatal("valid public relay configuration rejected")
		}
	}
	for _, value := range []string{"http://public.example.com/callback", "/relative", "https://user:pass@example.com/callback", "https://ui.example.com/callback?x=1"} {
		t.Setenv("AGENT_VAULT_OAUTH_REDIRECT_URL", value)
		if _, err := oauthrelay.Configuration(""); err == nil {
			t.Fatal("unsafe redirect configuration accepted")
		}
	}
	t.Setenv("AGENT_VAULT_OAUTH_REDIRECT_URL", "")
	cfg, err := oauthrelay.Configuration("http://127.0.0.1:14321")
	if err != nil || cfg.RedirectURI != "http://127.0.0.1:14321/v1/oauth/callback" {
		t.Fatal("upstream callback fallback changed")
	}
}

func TestRelayCompletionAndReplay(t *testing.T) {
	ctx := context.Background()
	t.Setenv("AGENT_VAULT_OAUTH_REDIRECT_URL", "https://ui.example.com/oauth/callback")
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	previousClient := oauth.TokenClient
	t.Cleanup(func() { oauth.TokenClient = previousClient })
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, _ := db.GetVault(ctx, "default")
	_, token, err := db.CreateAgentWithGrantsAndToken(ctx, "host", "", "owner", []store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var exchanges atomic.Int32
	var verifier atomic.Value
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("redirect_uri") != "https://ui.example.com/oauth/callback" || r.Form.Get("code_verifier") == "" {
			t.Error("redirect relay or PKCE verifier missing")
		}
		verifier.Store(r.Form.Get("code_verifier"))
		io.WriteString(w, `{"access_token":"synthetic-relay-access","refresh_token":"synthetic-relay-refresh","expires_in":3600}`)
	}))
	defer tokenServer.Close()
	key := make([]byte, 32)
	srv := server.New("127.0.0.1:0", db, key, notify.New(nil), true, "http://127.0.0.1:12345", slog.New(slog.DiscardHandler))
	request := func(method, path, body, bearer string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), "synthetic-relay-access") || strings.Contains(w.Body.String(), "synthetic-relay-refresh") {
			t.Error("relay exposed token values")
		}
		return w
	}
	input, _ := json.Marshal(map[string]string{
		"vault": "default", "key": "RELAY_KEY", "authorization_url": "https://auth.example.com/authorize",
		"token_url": tokenServer.URL, "client_id": "synthetic-client",
	})
	w := request("POST", "/v1/credentials/oauth/connect", string(input), token.ID)
	var started map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &started); err != nil || w.Code != 200 {
		t.Fatal("failed to start upstream-compatible OAuth flow")
	}
	authorize, _ := url.Parse(started["authorization_url"])
	state := authorize.Query().Get("state")
	if state == "" || authorize.Query().Get("redirect_uri") != "https://ui.example.com/oauth/callback" {
		t.Fatal("authorize URL did not use the public relay")
	}
	complete, _ := json.Marshal(oauthrelay.Input{State: state, Code: "synthetic-code"})
	if got := request("POST", "/v1/oauth/complete", string(complete), ""); got.Code != 401 {
		t.Fatal("unauthenticated completion accepted")
	}
	var group sync.WaitGroup
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			statuses <- request("POST", "/v1/oauth/complete", string(complete), token.ID).Code
		}()
	}
	group.Wait()
	close(statuses)
	var success, replay int
	for status := range statuses {
		if status == 200 {
			success++
		} else if status == 400 {
			replay++
		}
	}
	if success != 1 || replay != 1 || exchanges.Load() != 1 {
		t.Fatal("OAuth state was not consumed exactly once")
	}
	if oauth.CodeChallengeS256(verifier.Load().(string)) != authorize.Query().Get("code_challenge") {
		t.Fatal("PKCE challenge did not match the exchanged verifier")
	}
	cred, err := db.GetCredential(ctx, vault.ID, "RELAY_KEY")
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, key)
	if err != nil || string(plaintext) != "synthetic-relay-access" {
		t.Fatal("relay did not store the encrypted access token")
	}
	metadata := request("GET", "/v1/oauth/client-metadata", "", "")
	var document map[string]any
	if err := json.Unmarshal(metadata.Body.Bytes(), &document); err != nil || document["client_id"] != "https://ui.example.com/oauth/client-metadata.json" {
		t.Fatal("CIMD document is incorrect")
	}
	if err := db.CreateCredentialOAuthState(ctx, &store.CredentialOAuthState{
		ID: "expired-state", StateHash: oauthrelay.Hash("expired"), VaultID: vault.ID, CredentialKey: "RELAY_KEY",
		CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if got := request("POST", "/v1/oauth/complete", `{"state":"expired","code":"unused"}`, token.ID); got.Code != 400 {
		t.Fatal("expired state accepted")
	}
}
