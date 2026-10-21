package mcpauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
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
		`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='account' ORDER BY record_key`), vault)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	accounts := make([]Account, 0)
	for rows.Next() {
		var ct, nonce []byte
		var account Account
		if err := rows.Scan(&ct, &nonce); err != nil {
			return nil, err
		}
		if err := r.decode(ct, nonce, &account); err != nil {
			return nil, err
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
	if err := r.put(ctx, tx, vault, "account", a.Key, a, 0); err != nil {
		return err
	}
	ct, nonce, err := crypto.Encrypt([]byte(a.AccessToken), r.key)
	if err != nil {
		return err
	}
	now := r.dialect.FormatTime(a.UpdatedAt)
	result, err := tx.ExecContext(ctx, r.dialect.Rebind(`INSERT INTO credentials
		(id,vault_id,key,type,ciphertext,nonce,created_at,updated_at) VALUES (?,?,?,'mcp_oauth',?,?,?,?)
		ON CONFLICT(vault_id,key) DO UPDATE SET ciphertext=excluded.ciphertext,nonce=excluded.nonce,
		type=excluded.type,updated_at=excluded.updated_at WHERE credentials.type='mcp_oauth'`), rand.Text(), vault, a.Key, ct, nonce, now, now)
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
	return tx.Commit()
}

func (r *Repository) updateServices(ctx context.Context, tx *sql.Tx, vault string, account *Account, remove bool) error {
	var raw string
	err := tx.QueryRowContext(ctx, r.dialect.Rebind(`SELECT services_json FROM broker_configs WHERE vault_id=?`), vault).Scan(&raw)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	services := make([]broker.Service, 0)
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &services); err != nil {
			return err
		}
	}
	name := "mcp-" + strings.ToLower(strings.TrimPrefix(account.Key, "MCP_"))
	kept := services[:0]
	for _, service := range services {
		if service.Name != name && service.Name != name+"-children" {
			service.Host, service.Path, service.Port = broker.SplitInlineHost(service.Host, service.Path)
			kept = append(kept, service)
		}
	}
	if !remove {
		added, err := account.services()
		if err != nil {
			return err
		}
		for _, candidate := range added {
			for _, existing := range kept {
				if strings.EqualFold(existing.Host, candidate.Host) && existing.Path == candidate.Path &&
					broker.PortVal(existing.Port) == broker.PortVal(candidate.Port) {
					return failure("service_conflict", "An existing service already owns this MCP destination; remove it before signing in")
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
	if err := r.updateServices(ctx, tx, vault, a, true); err != nil {
		return err
	}
	for _, query := range []string{
		`DELETE FROM credentials WHERE vault_id=? AND key=? AND type='mcp_oauth'`,
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
	return tx.Commit()
}
