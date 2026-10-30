package mcpauth

import (
	"context"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

func TestManagedReconnectNeverGuessesRefreshTokenIdentity(t *testing.T) {
	m, db, _ := testManager(t)
	ctx := context.Background()
	user, library, _ := managedMCPFixture(t, m, db, "CONN_UNUSED")
	transport := &providerTransport{t: t}
	m.client.Transport = transport
	issuer, authorize, endpoint, secret := "https://issuer.example", "https://issuer.example/authorize", "https://oauth2.googleapis.com/token", "synthetic-secret"
	hosts := []string{"api.example.com"}
	if _, err := m.PutApp(ctx, library, "test-app", AppInput{Issuer: &issuer, ClientID: "client", ClientSecret: &secret, AuthorizationEndpoint: &authorize, TokenEndpoint: &endpoint, APIHosts: &hosts}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.repo.db.Exec(`INSERT INTO connections(id,owner_user_id,library_vault_id,label,kind,status,revision,app_id) VALUES ('CONN_RECONNECT',?,?,'API','oauth_app','draft','"initial"','test-app')`, user, library); err != nil {
		t.Fatal(err)
	}
	signIn := func() {
		t.Helper()
		start, err := m.StartConnection(ctx, library, user, "CONN_RECONNECT", "oauth_app", "", "test-app", "", []string{"read"})
		if err != nil {
			t.Fatal(err)
		}
		if result, err := m.Complete(ctx, oauthrelay.Input{State: start.State, Code: "code", UserID: user}, func(string) error { return nil }); err != nil || result.Status != "connected" {
			t.Fatal("managed sign-in failed", err)
		}
	}
	signIn()
	transport.omitRefresh = true
	signIn()
	account, err := m.ConnectionAccount(ctx, library, "CONN_RECONNECT")
	if err != nil {
		t.Fatal(err)
	}
	if account.RefreshToken != "" {
		t.Fatal("managed reconnect reused a refresh token without a verified matching subject")
	}
	account.ExpiresAt = time.Now().Add(-time.Hour)
	if err = m.repo.saveAccount(ctx, library, account, false); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Credential(ctx, library, account.Key); err == nil {
		t.Fatal("expired token without verified refresh remained usable")
	}
	var status string
	if err = m.repo.db.QueryRow(`SELECT status FROM connections WHERE id=?`, account.Key).Scan(&status); err != nil || status != "needs_reconnect" {
		t.Fatal("expired token did not update canonical connection status", err)
	}
}
