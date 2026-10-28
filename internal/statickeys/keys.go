// Package statickeys provides atomic credential/destination edits for the host.
package statickeys

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/store"
)

var ErrManaged = errors.New("managed OAuth services and credentials must be changed through account endpoints")
var ErrInvalid = errors.New("invalid key or service")
var ErrConflict = errors.New("credential or service is already owned by another key")

type Repository struct {
	db      *sql.DB
	dialect store.Dialect
	key     []byte
	mu      sync.Mutex
	touched map[string]time.Time
}

func New(db *sql.DB, d store.Dialect, key []byte) *Repository {
	return &Repository{db: db, dialect: d, key: key, touched: make(map[string]time.Time)}
}

func Managed(name string) bool {
	return strings.HasPrefix(name, "mcp-") || strings.HasPrefix(name, "oauth-")
}

func Protect(before, after []broker.Service) error {
	existing := map[string]string{}
	for _, s := range before {
		if Managed(s.Name) {
			data, _ := json.Marshal(s)
			existing[s.Name] = string(data)
		}
	}
	for _, s := range after {
		if Managed(s.Name) {
			data, _ := json.Marshal(s)
			if existing[s.Name] != string(data) {
				return ErrManaged
			}
			delete(existing, s.Name)
		}
	}
	if len(existing) != 0 {
		return ErrManaged
	}
	return nil
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

func (r *Repository) saveServices(ctx context.Context, tx *sql.Tx, vault string, services []broker.Service) error {
	if err := broker.ValidateExclusiveHosts(services); err != nil {
		return fmt.Errorf("%w: %v", ErrConflict, err)
	}
	if err := broker.Validate(&broker.Config{Vault: vault, Services: services}); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	data, err := json.Marshal(services)
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

// Put atomically replaces a static key and its single service; nil value preserves the value.
// Caller holds the existing cross-process vault mutation lock.
func (r *Repository) Put(ctx context.Context, vault, key string, value *string, service broker.Service) error {
	if !broker.CredentialKeyPattern.MatchString(key) {
		return ErrInvalid
	}
	service.Host, service.Path, service.Port = broker.SplitInlineHost(service.Host, service.Path)
	if Managed(service.Name) {
		return ErrManaged
	}
	refs := service.CredentialKeys()
	if len(refs) != 1 || refs[0] != key {
		return fmt.Errorf("%w: service must reference only this key", ErrInvalid)
	}
	if value != nil && *value == "" {
		return fmt.Errorf("%w: value cannot be empty", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind string
	err = tx.QueryRowContext(ctx, r.dialect.Rebind(`SELECT type FROM credentials WHERE vault_id=? AND key=?`), vault, key).Scan(&kind)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if kind != "" && kind != "static" {
		return ErrManaged
	}
	if kind == "" && value == nil {
		return fmt.Errorf("%w: a new key requires value", ErrInvalid)
	}
	services, err := r.services(ctx, tx, vault)
	if err != nil {
		return err
	}
	kept := make([]broker.Service, 0, len(services)+1)
	for _, old := range services {
		references := old.CredentialKeys()
		if slices.Contains(references, key) {
			if Managed(old.Name) || len(references) != 1 {
				return ErrConflict
			}
			continue
		}
		if old.Name == service.Name {
			return ErrConflict
		}
		kept = append(kept, old)
	}
	kept = append(kept, service)
	now := r.dialect.FormatTime(time.Now())
	if value != nil {
		ct, nonce, err := crypto.Encrypt([]byte(*value), r.key)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, r.dialect.Rebind(`INSERT INTO credentials(id,vault_id,key,type,ciphertext,nonce,created_at,updated_at)
			VALUES (?,?,?,'static',?,?,?,?) ON CONFLICT(vault_id,key) DO UPDATE SET ciphertext=excluded.ciphertext,nonce=excluded.nonce,updated_at=excluded.updated_at`),
			rand.Text(), vault, key, ct, nonce, now, now)
		if err != nil {
			return err
		}
	} else {
		if _, err := tx.ExecContext(ctx, r.dialect.Rebind(`UPDATE credentials SET updated_at=? WHERE vault_id=? AND key=?`), now, vault, key); err != nil {
			return err
		}
	}
	if err := r.saveServices(ctx, tx, vault, kept); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) Delete(ctx context.Context, vault, key string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var kind string
	if err := tx.QueryRowContext(ctx, r.dialect.Rebind(`SELECT type FROM credentials WHERE vault_id=? AND key=?`), vault, key).Scan(&kind); err != nil {
		return err
	}
	if kind != "static" {
		return ErrManaged
	}
	services, err := r.services(ctx, tx, vault)
	if err != nil {
		return err
	}
	kept := make([]broker.Service, 0, len(services))
	for _, s := range services {
		refs := s.CredentialKeys()
		if slices.Contains(refs, key) {
			if Managed(s.Name) || len(refs) != 1 {
				return ErrConflict
			}
			continue
		}
		kept = append(kept, s)
	}
	if err := r.saveServices(ctx, tx, vault, kept); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, r.dialect.Rebind(`DELETE FROM credentials WHERE vault_id=? AND key=?`), vault, key); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *Repository) Touch(ctx context.Context, c *store.Credential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	if prior, ok := r.touched[c.ID]; ok && now.Sub(prior) < time.Minute {
		return nil
	}
	if len(r.touched) > 10000 {
		for id, at := range r.touched {
			if now.Sub(at) >= time.Minute {
				delete(r.touched, id)
			}
		}
	}
	_, err := r.db.ExecContext(ctx, r.dialect.Rebind(`INSERT INTO gateway_credential_usage(credential_id,last_used_at) VALUES (?,?)
		ON CONFLICT(credential_id) DO UPDATE SET last_used_at=excluded.last_used_at WHERE gateway_credential_usage.last_used_at<?`), c.ID, now.Unix(), now.Add(-time.Minute).Unix())
	if err == nil {
		r.touched[c.ID] = now
	}
	return err
}

func (r *Repository) Usage(ctx context.Context, vault string) (map[string]*time.Time, error) {
	rows, err := r.db.QueryContext(ctx, r.dialect.Rebind(`SELECT c.key,u.last_used_at FROM credentials c JOIN gateway_credential_usage u ON c.id=u.credential_id WHERE c.vault_id=?`), vault)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]*time.Time{}
	for rows.Next() {
		var key string
		var at int64
		if err := rows.Scan(&key, &at); err != nil {
			return nil, err
		}
		t := time.Unix(at, 0).UTC()
		result[key] = &t
	}
	return result, rows.Err()
}
