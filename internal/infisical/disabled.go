//go:build noinfisical

package infisical

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"
)

var ErrDisabled = errors.New("Infisical integration is excluded from this gateway build")

type Client struct{}

func NewClient(context.Context, *slog.Logger) (*Client, error) {
	if os.Getenv("INFISICAL_URL") == "" {
		return nil, ErrNotConfigured
	}
	return nil, ErrDisabled
}
func (*Client) AuthMethod() AuthMethod                                      { return "" }
func (*Client) FetchSecrets(context.Context, VaultConfig) ([]Secret, error) { return nil, ErrDisabled }
func (*Client) ListDynamicSecrets(context.Context, VaultConfig) ([]DynamicSecretInfo, error) {
	return nil, ErrDisabled
}
func (*Client) CreateLease(context.Context, VaultConfig, string) (DynamicLease, error) {
	return DynamicLease{}, ErrDisabled
}
func (*Client) RenewLease(context.Context, VaultConfig, string) (time.Time, error) {
	return time.Time{}, ErrDisabled
}
func (*Client) RevokeLease(context.Context, VaultConfig, string) error { return ErrDisabled }
