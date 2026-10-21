package revealpolicy

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestPersistedPolicyCannotBeDowngraded(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "")
	if disabled, err := Disabled(ctx, db); err != nil || disabled {
		t.Fatal("non-headless upstream default changed")
	}
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "true")
	if err := Configure(ctx, db); err != nil {
		t.Fatal(err)
	}
	for _, env := range []string{"", "false", "true"} {
		t.Setenv("AGENT_VAULT_REVEAL_DISABLED", env)
		if disabled, err := Disabled(ctx, db); err != nil || !disabled {
			t.Fatal("persisted write-only boundary was downgraded")
		}
	}
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "invalid")
	if err := Configure(ctx, db); err == nil {
		t.Fatal("invalid environment value accepted")
	}
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "")
	if err := db.SetSetting(ctx, setting, "invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := Disabled(ctx, db); err == nil {
		t.Fatal("invalid database value failed open")
	}
}

type failingStore struct{ Store }

func (failingStore) GetSetting(context.Context, string) (string, error) {
	return "", errors.New("test database error")
}

func TestReadFailure(t *testing.T) {
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "true")
	if _, err := Disabled(context.Background(), failingStore{}); err == nil {
		t.Fatal("policy read failure was ignored")
	}
}
