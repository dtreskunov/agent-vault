package blindtunnel

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestPolicy(t *testing.T) {
	ctx := context.Background()
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "tunnel")
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	vault, err := db.GetVault(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	cfg := `[
		{"name":"api","host":"api.example.com:443/private/*","auth":{"type":"passthrough"}},
		{"name":"wildcard","host":"*.example.org/path","auth":{"type":"passthrough"}},
		{"name":"disabled","host":"disabled.example.com/path","enabled":false,"auth":{"type":"passthrough"}}
	]`
	if _, err := db.SetBrokerConfig(ctx, vault.ID, cfg); err != nil {
		t.Fatal(err)
	}
	policy := Policy{Store: db}
	for _, test := range []struct {
		host string
		port int
		want Mode
	}{
		{"api.example.com", 443, MITM}, {"API.EXAMPLE.COM", 443, MITM},
		{"api.example.com", 8443, Tunnel}, {"one.example.org", 443, MITM},
		{"two.one.example.org", 443, Tunnel}, {"disabled.example.com", 443, MITM},
		{"unknown.example.com", 443, Tunnel},
	} {
		mode, err := policy.Decide(ctx, vault.ID, test.host, test.port)
		if err != nil || mode != test.want {
			t.Errorf("%s:%d = %s, %v; want %s", test.host, test.port, mode, err, test.want)
		}
	}
	for _, want := range []Mode{Deny, MITM, Tunnel} {
		if mode, err := Update(ctx, db, vault.ID, string(want)); err != nil || mode != want {
			t.Fatal("could not set mode")
		}
		if mode, err := policy.Decide(ctx, vault.ID, "unknown.test", 443); err != nil || mode != want {
			t.Fatal("per-vault override was ignored")
		}
	}
	if _, err := Update(ctx, db, vault.ID, "invalid"); !errors.Is(err, ErrInvalidMode) {
		t.Fatal("invalid setting accepted")
	}
	if mode, err := Update(ctx, db, vault.ID, ""); err != nil || mode != Tunnel {
		t.Fatal("could not reset to instance default")
	}
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "")
	if mode, err := Read(ctx, db, vault.ID); err != nil || mode != MITM {
		t.Fatal("upstream default was not preserved")
	}
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "invalid")
	if _, err := Default(); !errors.Is(err, ErrInvalidMode) {
		t.Fatal("invalid environment default accepted")
	}
	if _, err := db.SetBrokerConfig(ctx, vault.ID, "{"); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Decide(ctx, vault.ID, "unknown.test", 443); err == nil {
		t.Fatal("malformed services failed open")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Decide(ctx, vault.ID, "unknown.test", 443); err == nil {
		t.Fatal("store failure failed open")
	}
}
