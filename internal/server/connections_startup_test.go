package server

import (
	"context"
	"log/slog"
	"testing"

	"github.com/Infisical/agent-vault/internal/notify"
)

func TestManagedInvalidOAuthConfigurationCannotSkipStartupValidation(t *testing.T) {
	f := newManagedFixture(t)
	t.Setenv("AGENT_VAULT_OAUTH_REDIRECT_URL", "http://not-loopback.invalid/callback")
	f.s = New("127.0.0.1:0", f.db, make([]byte, 32), notify.New(nil), true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler))
	if err := f.s.PrepareGateway(context.Background()); err == nil {
		t.Fatal("invalid OAuth configuration skipped canonical startup validation")
	}
}
