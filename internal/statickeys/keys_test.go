package statickeys

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestAtomicKeyRollbackPreservationAndUsage(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	vault, _ := db.GetVault(ctx, "default")
	sqlDB, d := db.GatewaySQL()
	r := New(sqlDB, d, make([]byte, 32))
	initial := `[{"name":"mcp-owned","host":"mcp.example.com","auth":{"type":"bearer","token":"MCP_TEST"}}]`
	if _, err := db.SetBrokerConfig(ctx, vault.ID, initial); err != nil {
		t.Fatal(err)
	}
	value := "synthetic-value"
	service := broker.Service{Name: "static-one", Host: "api.example.com", Auth: broker.Auth{Type: "bearer", Token: "TEST_KEY"}}
	if err := r.Put(ctx, vault.ID, "TEST_KEY", &value, service); err != nil {
		t.Fatal(err)
	}
	cred, _ := db.GetCredential(ctx, vault.ID, "TEST_KEY")
	clear, err := crypto.Decrypt(cred.Ciphertext, cred.Nonce, make([]byte, 32))
	if err != nil || string(clear) != value {
		t.Fatal("key value not stored")
	}
	if err := r.Touch(ctx, cred); err != nil {
		t.Fatal(err)
	}
	if err := r.Touch(ctx, cred); err != nil {
		t.Fatal(err)
	}
	usage, err := r.Usage(ctx, vault.ID)
	if err != nil || usage["TEST_KEY"] == nil {
		t.Fatal("usage not persisted")
	}
	service.Name = "static-renamed"
	service.Host = "new.example.com"
	if err := r.Put(ctx, vault.ID, "TEST_KEY", nil, service); err != nil {
		t.Fatal(err)
	}
	cfg, _ := db.GetBrokerConfig(ctx, vault.ID)
	var services []broker.Service
	json.Unmarshal([]byte(cfg.ServicesJSON), &services)
	if len(services) != 2 || services[0].Name != "mcp-owned" || services[1].Name != "static-renamed" {
		t.Fatal("atomic edit lost managed services or retained old destination")
	}
	// Abort the final statement, after the credential update, to prove rollback.
	if _, err := sqlDB.Exec(`CREATE TRIGGER fail_service_update BEFORE UPDATE ON broker_configs BEGIN SELECT RAISE(ABORT,'test failure'); END`); err != nil {
		t.Fatal(err)
	}
	bad := "must-not-persist"
	if err := r.Put(ctx, vault.ID, "TEST_KEY", &bad, service); err == nil {
		t.Fatal("forced rollback reported success")
	}
	cred, _ = db.GetCredential(ctx, vault.ID, "TEST_KEY")
	clear, _ = crypto.Decrypt(cred.Ciphertext, cred.Nonce, make([]byte, 32))
	if string(clear) != value {
		t.Fatal("failure left a half update")
	}
	if _, err := sqlDB.Exec(`DROP TRIGGER fail_service_update`); err != nil {
		t.Fatal(err)
	}
	service.Name = "mcp-forbidden"
	if err := r.Put(ctx, vault.ID, "TEST_KEY", nil, service); !errors.Is(err, ErrManaged) {
		t.Fatal("managed service overwritten")
	}
	if err := r.Delete(ctx, vault.ID, "TEST_KEY"); err != nil {
		t.Fatal(err)
	}
	usage, _ = r.Usage(ctx, vault.ID)
	if len(usage) != 0 {
		t.Fatal("deleted credential usage survived cascade")
	}
}
