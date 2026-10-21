// Package revealpolicy enforces the gateway's instance-wide write-only boundary.
package revealpolicy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
)

const setting = "reveal_disabled"

type Store interface {
	GetSetting(context.Context, string) (string, error)
	SetSetting(context.Context, string, string) error
}

func Environment() (bool, error) {
	switch os.Getenv("AGENT_VAULT_REVEAL_DISABLED") {
	case "", "false":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("AGENT_VAULT_REVEAL_DISABLED must be true or false")
	}
}

// Disabled cannot be downgraded by API callers or by clearing the environment.
func Disabled(ctx context.Context, db Store) (bool, error) {
	env, err := Environment()
	if err != nil {
		return false, err
	}
	raw, err := db.GetSetting(ctx, setting)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, fmt.Errorf("reading reveal policy: %w", err)
	}
	switch raw {
	case "", "false":
		return env, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("invalid persisted reveal_disabled setting")
	}
}

func Configure(ctx context.Context, db Store) error {
	disabled, err := Disabled(ctx, db)
	if err != nil {
		return err
	}
	if disabled {
		return db.SetSetting(ctx, setting, "true")
	}
	return nil
}
