package infisical

import (
	"context"
	"time"
)

type SecretsFetcher interface {
	FetchSecrets(context.Context, VaultConfig) ([]Secret, error)
	AuthMethod() AuthMethod
}

type DynamicSecretInfo struct{ Name string }
type DynamicLease struct {
	LeaseID  string
	Fields   map[string]string
	ExpireAt time.Time
}
type DynamicFetcher interface {
	ListDynamicSecrets(context.Context, VaultConfig) ([]DynamicSecretInfo, error)
	CreateLease(context.Context, VaultConfig, string) (DynamicLease, error)
	RenewLease(context.Context, VaultConfig, string) (time.Time, error)
	RevokeLease(context.Context, VaultConfig, string) error
}
