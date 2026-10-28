package statickeys

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

func setFixture(t *testing.T) (*store.SQLStore, *Repository, string) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "sets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	v, err := db.GetVault(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, dialect := db.GatewaySQL()
	return db, New(sqlDB, dialect, make([]byte, 32)), v.ID
}

func composite() broker.Service {
	return broker.Service{Name: "combined-key", Host: "api.example.com",
		Auth: broker.Auth{Type: "custom", Headers: map[string]string{
			"Authorization": "Bearer {{ BEARER_KEY }}", "x-api-key": "{{ API_KEY }}",
		}}}
}

func TestKeySetCreateOnlyAndConditionalLifecycle(t *testing.T) {
	db, repo, vault := setFixture(t)
	ctx := context.Background()
	sqlDB, _ := db.GatewaySQL()
	// New vaults need not already have a broker config row.
	if _, err := sqlDB.Exec(`DELETE FROM broker_configs WHERE vault_id=?`, vault); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"BEARER_KEY": "synthetic-bearer", "API_KEY": "synthetic-api"}
	info, err := repo.PutSet(ctx, vault, composite(), values, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Service.HTTPSOnly || !slices.Equal(info.Keys, []string{"API_KEY", "BEARER_KEY"}) || len(info.Revision) != 66 {
		t.Fatal("unsafe or incomplete metadata")
	}
	encoded, _ := json.Marshal(info)
	for _, value := range values {
		if strings.Contains(string(encoded), value) {
			t.Fatal("value exposed in set metadata")
		}
	}
	before, _ := db.GetCredential(ctx, vault, "API_KEY")
	if _, err := repo.PutSet(ctx, vault, composite(), map[string]string{"API_KEY": "must-not-replace", "BEARER_KEY": "other"}, true, ""); !errors.Is(err, ErrPrecondition) {
		t.Fatal("create-only replaced an existing set")
	}
	after, _ := db.GetCredential(ctx, vault, "API_KEY")
	if string(before.Ciphertext) != string(after.Ciphertext) {
		t.Fatal("create conflict changed ciphertext")
	}
	changed := composite()
	changed.Host = "other.example.com"
	updated, err := repo.PutSet(ctx, vault, changed, nil, false, info.Revision)
	if err != nil || updated.Revision == info.Revision {
		t.Fatal("service edit did not advance revision", err)
	}
	after, _ = db.GetCredential(ctx, vault, "API_KEY")
	if string(before.Ciphertext) != string(after.Ciphertext) {
		t.Fatal("metadata edit changed a preserved value")
	}
	if _, err := repo.PutSet(ctx, vault, changed, map[string]string{"API_KEY": "stale"}, false, info.Revision); !errors.Is(err, ErrPrecondition) {
		t.Fatal("stale edit accepted")
	}
	if err := repo.DeleteSet(ctx, vault, changed.Name, info.Revision); !errors.Is(err, ErrPrecondition) {
		t.Fatal("stale delete accepted")
	}
	updated, err = repo.PutSet(ctx, vault, changed, map[string]string{"API_KEY": "synthetic-new"}, false, updated.Revision)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := db.GetCredential(ctx, vault, "API_KEY")
	plaintext, _ := crypto.Decrypt(credential.Ciphertext, credential.Nonce, make([]byte, 32))
	if string(plaintext) != "synthetic-new" {
		t.Fatal("value edit did not persist")
	}
	if err := repo.Touch(ctx, credential); err != nil {
		t.Fatal(err)
	}
	read, err := repo.GetSet(ctx, vault, changed.Name)
	if err != nil || read.Revision != updated.Revision {
		t.Fatal("usage incorrectly invalidated revision")
	}
	if err := repo.DeleteSet(ctx, vault, changed.Name, updated.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetCredential(ctx, vault, "API_KEY"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("deleted key survived")
	}
	if _, err := repo.GetSet(ctx, vault, changed.Name); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("deleted service survived")
	}
}

func TestKeySetNoOverwriteNoShadowAndManagedProtection(t *testing.T) {
	db, repo, vault := setFixture(t)
	ctx := context.Background()
	service := composite()
	value := "synthetic-existing"
	if err := repo.Put(ctx, vault, "API_KEY", &value, broker.Service{Name: "existing", Host: "existing.example", Auth: broker.Auth{Type: "bearer", Token: "API_KEY"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.PutSet(ctx, vault, service, map[string]string{"API_KEY": "new", "BEARER_KEY": "new"}, true, ""); !errors.Is(err, ErrPrecondition) {
		t.Fatal("existing credential overwritten")
	}
	if _, err := db.GetCredential(ctx, vault, "BEARER_KEY"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("partial credential survived conflict")
	}
	for _, existing := range []string{
		`[{"name":"orphan-template","host":"unrelated.example","auth":{"type":"bearer","token":"NEW_KEY"}}]`,
		`[{"name":"mcp-owned","host":"api.example.com/mcp","auth":{"type":"passthrough"}}]`,
		`[{"name":"static-owned","host":"*.example.com","auth":{"type":"passthrough"}}]`,
	} {
		if _, err := db.SetBrokerConfig(ctx, vault, existing); err != nil {
			t.Fatal(err)
		}
		input := broker.Service{Name: "new-key-set", Host: "api.example.com", Auth: broker.Auth{Type: "bearer", Token: "NEW_KEY"}}
		if _, err := repo.PutSet(ctx, vault, input, map[string]string{"NEW_KEY": "new"}, true, ""); !errors.Is(err, ErrConflict) {
			t.Fatal("foreign references/recipients were shadowed", err)
		}
		if _, err := db.GetCredential(ctx, vault, "NEW_KEY"); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("failed collision left a value")
		}
	}
	for _, key := range []string{"MCP_TEST", "OAUTH_TEST"} {
		input := broker.Service{Name: "new-set", Host: "new.example", Auth: broker.Auth{Type: "bearer", Token: key}}
		if _, err := repo.PutSet(ctx, vault, input, map[string]string{key: "synthetic"}, true, ""); !errors.Is(err, ErrManaged) {
			t.Fatal("managed credential namespace accepted")
		}
	}
}

func TestKeySetRollbackAndForeignReferences(t *testing.T) {
	db, repo, vault := setFixture(t)
	ctx := context.Background()
	if _, err := db.SetBrokerConfig(ctx, vault, `[{"name":"mcp-existing","host":"mcp.example","auth":{"type":"passthrough"}}]`); err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.GatewaySQL()
	if _, err := sqlDB.Exec(`CREATE TRIGGER fail_set BEFORE UPDATE ON broker_configs BEGIN SELECT RAISE(ABORT,'forced'); END`); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"API_KEY": "synthetic-api", "BEARER_KEY": "synthetic-bearer"}
	if _, err := repo.PutSet(ctx, vault, composite(), values, true, ""); err == nil {
		t.Fatal("forced transaction failure succeeded")
	}
	for key := range values {
		if _, err := db.GetCredential(ctx, vault, key); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("transaction left a partial value")
		}
	}
	if _, err := sqlDB.Exec(`DROP TRIGGER fail_set`); err != nil {
		t.Fatal(err)
	}
	info, err := repo.PutSet(ctx, vault, composite(), values, true, "")
	if err != nil {
		t.Fatal(err)
	}
	// Legacy edits outside this API invalidate the opaque revision.
	if _, err := sqlDB.Exec(`UPDATE credentials SET nonce=? WHERE vault_id=? AND key='API_KEY'`, []byte("changed"), vault); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteSet(ctx, vault, info.Service.Name, info.Revision); !errors.Is(err, ErrPrecondition) {
		t.Fatal("external value update did not invalidate revision")
	}
	config, _ := db.GetBrokerConfig(ctx, vault)
	var services []broker.Service
	if err := json.Unmarshal([]byte(config.ServicesJSON), &services); err != nil {
		t.Fatal(err)
	}
	services = append(services, broker.Service{Name: "foreign-reference", Host: "other.example", Auth: broker.Auth{Type: "bearer", Token: "API_KEY"}})
	encoded, _ := json.Marshal(services)
	if _, err := db.SetBrokerConfig(ctx, vault, string(encoded)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetSet(ctx, vault, info.Service.Name); !errors.Is(err, ErrConflict) {
		t.Fatal("foreign shared-key ownership ignored")
	}
}

func TestKeySetRejectsInvalidValuesWithoutEcho(t *testing.T) {
	_, repo, vault := setFixture(t)
	ctx := context.Background()
	for _, values := range []map[string]string{
		{}, {"API_KEY": "only-one"},
		{"API_KEY": "", "BEARER_KEY": "other"},
		{"API_KEY": "DO_NOT_ECHO\ninvalid", "BEARER_KEY": "other"},
		{"API_KEY": "valid", "BEARER_KEY": "other", "UNEXPECTED": "DO_NOT_ECHO"},
	} {
		_, err := repo.PutSet(ctx, vault, composite(), values, true, "")
		if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "DO_NOT_ECHO") {
			t.Fatal("invalid values accepted or exposed", err)
		}
	}
}
