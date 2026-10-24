//go:build noinfisical

package infisical

import (
	"context"
	"errors"
	"log/slog"
	"testing"
)

func TestExcludedClientReportsExplicitError(t *testing.T) {
	t.Setenv("INFISICAL_URL", "https://infisical.example.com")
	if _, err := NewClient(context.Background(), slog.New(slog.DiscardHandler)); !errors.Is(err, ErrDisabled) {
		t.Fatal("excluded client was not rejected explicitly")
	}
	client := &Client{}
	if _, err := client.FetchSecrets(context.Background(), VaultConfig{}); !errors.Is(err, ErrDisabled) {
		t.Fatal("excluded secret read did not fail")
	}
	t.Setenv("INFISICAL_URL", "")
	if _, err := NewClient(context.Background(), slog.New(slog.DiscardHandler)); !errors.Is(err, ErrNotConfigured) {
		t.Fatal("unset client configuration changed")
	}
}
