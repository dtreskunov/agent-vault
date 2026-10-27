package mcpauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

type Repository struct {
	db      *sql.DB
	dialect store.Dialect
	key     []byte
}

func NewRepository(db *sql.DB, dialect store.Dialect, key []byte) *Repository {
	return &Repository{db: db, dialect: dialect, key: key}
}

type executor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func (r *Repository) put(ctx context.Context, exec executor, vault, kind, id string, value any, expires int64) error {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(plaintext)
	ct, nonce, err := crypto.Encrypt(plaintext, r.key)
	if err != nil {
		return err
	}
	accountKey := ""
	if flow, ok := value.(*Flow); ok {
		accountKey = flow.Account.Key
	}
	_, err = exec.ExecContext(ctx, r.dialect.Rebind(`INSERT INTO gateway_oauth_records
		(vault_id,kind,record_key,ciphertext,nonce,expires_at,account_key) VALUES (?,?,?,?,?,?,?)
		ON CONFLICT(vault_id,kind,record_key) DO UPDATE SET
		ciphertext=excluded.ciphertext,nonce=excluded.nonce,expires_at=excluded.expires_at,account_key=excluded.account_key`),
		vault, kind, id, ct, nonce, expires, accountKey)
	return err
}

func (r *Repository) decode(ct, nonce []byte, value any) error {
	if len(nonce) != 12 {
		return fmt.Errorf("invalid encrypted MCP record nonce")
	}
	plaintext, err := crypto.Decrypt(ct, nonce, r.key)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(plaintext)
	return json.Unmarshal(plaintext, value)
}

func (r *Repository) get(ctx context.Context, vault, kind, id string, value any) error {
	var ct, nonce []byte
	err := r.db.QueryRowContext(ctx, r.dialect.Rebind(
		`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind=? AND record_key=?`),
		vault, kind, id).Scan(&ct, &nonce)
	if err != nil {
		return err
	}
	return r.decode(ct, nonce, value)
}

func (r *Repository) Account(ctx context.Context, vault, key string) (*Account, error) {
	var account Account
	if err := r.get(ctx, vault, "account", key, &account); err != nil {
		return nil, err
	}
	if account.Key != key {
		return nil, fmt.Errorf("MCP account key mismatch")
	}
	return &account, nil
}

func (r *Repository) Accounts(ctx context.Context, vault string) ([]Account, error) {
	rows, err := r.db.QueryContext(ctx, r.dialect.Rebind(
		`SELECT record_key,ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='account' ORDER BY record_key`), vault)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := make([]Account, 0)
	for rows.Next() {
		var ct, nonce []byte
		var key string
		var account Account
		if err := rows.Scan(&key, &ct, &nonce); err != nil {
			return nil, err
		}
		if err := r.decode(ct, nonce, &account); err != nil {
			return nil, err
		}
		if account.Key != key {
			return nil, fmt.Errorf("MCP account key mismatch")
		}
		accounts = append(accounts, account)
	}
	return accounts, rows.Err()
}

func (r *Repository) Flow(ctx context.Context, state string) (*Flow, error) {
	var flow Flow
	var ct, nonce []byte
	err := r.db.QueryRowContext(ctx, r.dialect.Rebind(
		`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE kind='state' AND record_key=?`), digest(state)).Scan(&ct, &nonce)
	if err != nil {
		return nil, err
	}
	if err := r.decode(ct, nonce, &flow); err != nil {
		return nil, err
	}
	return &flow, nil
}

func (r *Repository) consume(ctx context.Context, vault, state string) error {
	result, err := r.db.ExecContext(ctx, r.dialect.Rebind(
		`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='state' AND record_key=?`), vault, digest(state))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return failure("invalid_state", "OAuth state has already been consumed")
	}
	return err
}

func (r *Repository) saveAccount(ctx context.Context, vault string, a *Account, connect bool) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := r.writeAccount(ctx, tx, vault, a, connect); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) writeAccount(ctx context.Context, tx *sql.Tx, vault string, a *Account, connect bool) error {
	if err := r.put(ctx, tx, vault, "account", a.Key, a, 0); err != nil {
		return err
	}
	ct, nonce, err := crypto.Encrypt([]byte(a.AccessToken), r.key)
	if err != nil {
		return err
	}
	now := r.dialect.FormatTime(a.UpdatedAt)
	result, err := tx.ExecContext(ctx, r.dialect.Rebind(`INSERT INTO credentials
		(id,vault_id,key,type,ciphertext,nonce,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)
		ON CONFLICT(vault_id,key) DO UPDATE SET ciphertext=excluded.ciphertext,nonce=excluded.nonce,
		type=excluded.type,updated_at=excluded.updated_at WHERE credentials.type=excluded.type`), rand.Text(), vault, a.Key, accountType(*a), ct, nonce, now, now)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return failure("credential_conflict", "MCP credential key was assigned to another credential while sign-in was pending")
	}
	if connect {
		if err := r.updateServices(ctx, tx, vault, a, false); err != nil {
			return err
		}
	}
	return r.rememberTokenAuthority(ctx, tx, a.Metadata.TokenEndpoint)
}

func (r *Repository) services(ctx context.Context, tx *sql.Tx, vault string) ([]broker.Service, error) {
	var raw string
	err := tx.QueryRowContext(ctx, r.dialect.Rebind(`SELECT services_json FROM broker_configs WHERE vault_id=?`), vault).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	services := make([]broker.Service, 0)
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &services); err != nil {
			return nil, err
		}
	}
	for i := range services {
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
	}
	return services, nil
}

func generatedName(a Account, name string) bool {
	prefix := servicePrefix(a)
	if accountType(a) == "mcp_oauth" {
		return name == prefix || name == prefix+"-children"
	}
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	suffix := strings.TrimPrefix(name, prefix)
	if len(suffix) == 1 && suffix[0] >= 'a' && suffix[0] <= 'z' {
		return true
	}
	index, err := strconv.Atoi(suffix)
	return err == nil && index >= 0 && strconv.Itoa(index) == suffix
}

func accountOwns(a Account, service broker.Service) (bool, error) {
	if !generatedName(a, service.Name) {
		return false, nil
	}
	if !reflect.DeepEqual(service.Auth, broker.Auth{Type: "bearer", Token: a.Key}) || len(service.Substitutions) != 0 {
		return false, failure("service_conflict", "Generated OAuth service name is owned by a different credential or configuration")
	}
	return true, nil
}

func (r *Repository) updateServices(ctx context.Context, tx *sql.Tx, vault string, account *Account, remove bool) error {
	services, err := r.services(ctx, tx, vault)
	if err != nil {
		return err
	}
	kept := services[:0]
	var enabled *bool
	sawOwned := false
	for _, service := range services {
		owned, err := accountOwns(*account, service)
		if err != nil {
			return err
		}
		if !owned {
			kept = append(kept, service)
		} else if !remove {
			if sawOwned && (enabled == nil || *enabled) != service.IsEnabled() {
				return failure("service_conflict", "Generated OAuth services have inconsistent enabled states")
			}
			enabled, sawOwned = service.Enabled, true
		}
	}
	if !remove {
		added, err := account.services()
		if err != nil {
			return err
		}
		for i := range added {
			added[i].Enabled = enabled
			candidate := added[i]
			for _, existing := range kept {
				if broker.HostsOverlap(existing, candidate) && (candidate.HTTPSOnly || existing.HTTPSOnly ||
					(existing.Path == candidate.Path && broker.PortVal(existing.Port) == broker.PortVal(candidate.Port))) {
					return failure("service_conflict", "An existing service or account already owns this OAuth destination")
				}
			}
		}
		kept = append(kept, added...)
	}
	if err := broker.Validate(&broker.Config{Vault: vault, Services: kept}); err != nil {
		return fmt.Errorf("invalid MCP service configuration: %w", err)
	}
	data, err := json.Marshal(kept)
	if err != nil {
		return err
	}
	now := r.dialect.FormatTime(time.Now())
	_, err = tx.ExecContext(ctx, r.dialect.Rebind(`INSERT INTO broker_configs
		(id,vault_id,services_json,created_at,updated_at) VALUES (?,?,?,?,?)
		ON CONFLICT(vault_id) DO UPDATE SET services_json=excluded.services_json,updated_at=excluded.updated_at`),
		rand.Text(), vault, string(data), now, now)
	return err
}

func (r *Repository) removeAccount(ctx context.Context, vault string, a *Account, removeClient bool) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := r.deleteAccount(ctx, tx, vault, a, removeClient); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) deleteAccount(ctx context.Context, tx *sql.Tx, vault string, a *Account, removeClient bool) error {
	if err := r.updateServices(ctx, tx, vault, a, true); err != nil {
		return err
	}
	for _, query := range []string{
		`DELETE FROM credentials WHERE vault_id=? AND key=? AND type IN ('mcp_oauth','oauth_app')`,
		`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='account' AND record_key=?`,
		`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='state' AND account_key=?`,
	} {
		if _, err := tx.ExecContext(ctx, r.dialect.Rebind(query), vault, a.Key); err != nil {
			return err
		}
	}
	if removeClient {
		if _, err := tx.ExecContext(ctx, r.dialect.Rebind(
			`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='client' AND record_key=?`),
			vault, digest(a.Issuer)); err != nil {
			return err
		}
	}
	return nil
}
