package statickeys

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
)

var ErrPrecondition = errors.New("credential set revision does not match")

// SetInfo contains only safe routing metadata and an opaque state revision.
type SetInfo struct {
	Service  broker.Service `json:"service"`
	Keys     []string       `json:"keys"`
	Revision string         `json:"revision"`
}

type setCredential struct {
	Key        string
	Kind       string
	Ciphertext []byte
	Nonce      []byte
}

func staticSetKeys(service broker.Service) ([]string, error) {
	if Managed(service.Name) {
		return nil, ErrManaged
	}
	keys := service.CredentialKeys()
	if len(keys) == 0 || len(keys) > 64 {
		return nil, fmt.Errorf("%w: a credential set needs 1-64 referenced keys", ErrInvalid)
	}
	for _, key := range keys {
		if !broker.CredentialKeyPattern.MatchString(key) {
			return nil, fmt.Errorf("%w: invalid credential reference", ErrInvalid)
		}
		if strings.HasPrefix(key, "MCP_") || strings.HasPrefix(key, "OAUTH_") {
			return nil, ErrManaged
		}
	}
	slices.Sort(keys)
	return keys, nil
}

func setExclusive(services []broker.Service, name string, keys []string) error {
	for _, service := range services {
		if service.Name == name {
			continue
		}
		for _, reference := range service.CredentialKeys() {
			if slices.Contains(keys, reference) {
				return ErrConflict
			}
		}
	}
	return nil
}

func (r *Repository) getSet(ctx context.Context, tx *sql.Tx, vault, name string, services []broker.Service) (*SetInfo, error) {
	var service *broker.Service
	for i := range services {
		if services[i].Name == name {
			service = &services[i]
			break
		}
	}
	if service == nil {
		return nil, sql.ErrNoRows
	}
	keys, err := staticSetKeys(*service)
	if err != nil {
		return nil, err
	}
	if err := setExclusive(services, name, keys); err != nil {
		return nil, err
	}
	credentials := make([]setCredential, 0, len(keys))
	for _, key := range keys {
		item := setCredential{Key: key}
		err := tx.QueryRowContext(ctx, r.dialect.Rebind(`SELECT type,ciphertext,nonce FROM credentials WHERE vault_id=? AND key=?`), vault, key).
			Scan(&item.Kind, &item.Ciphertext, &item.Nonce)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrConflict
		}
		if err != nil {
			return nil, err
		}
		if item.Kind != "static" {
			return nil, ErrManaged
		}
		credentials = append(credentials, item)
	}
	state, err := json.Marshal(struct {
		Vault       string
		Service     broker.Service
		Credentials []setCredential
	}{vault, *service, credentials})
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, r.key)
	_, _ = mac.Write(state)
	return &SetInfo{Service: *service, Keys: keys, Revision: `"` + hex.EncodeToString(mac.Sum(nil)) + `"`}, nil
}

func (r *Repository) GetSet(ctx context.Context, vault, name string) (*SetInfo, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	services, err := r.services(ctx, tx, vault)
	if err != nil {
		return nil, err
	}
	return r.getSet(ctx, tx, vault, name, services)
}

// PutSet creates only when createOnly is true; edits require the exact revision.
// The caller holds the cross-process vault mutation lock throughout this call.
func (r *Repository) PutSet(ctx context.Context, vault string, service broker.Service, values map[string]string, createOnly bool, revision string) (*SetInfo, error) {
	service.Host, service.Path, service.Port = broker.SplitInlineHost(service.Host, service.Path)
	service.HTTPSOnly = true
	keys, err := staticSetKeys(service)
	if err != nil {
		return nil, err
	}
	for key, value := range values {
		if !slices.Contains(keys, key) || value == "" || len(value) > 16<<10 || strings.ContainsAny(value, "\r\n\x00") {
			return nil, fmt.Errorf("%w: invalid or unexpected value field", ErrInvalid)
		}
	}
	if err := broker.Validate(&broker.Config{Vault: vault, Services: []broker.Service{service}}); err != nil {
		return nil, fmt.Errorf("%w: invalid service configuration", ErrInvalid)
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	services, err := r.services(ctx, tx, vault)
	if err != nil {
		return nil, err
	}
	current, err := r.getSet(ctx, tx, vault, service.Name, services)
	if createOnly {
		// A name collision is never permission to replace any part of a set.
		for _, existing := range services {
			if existing.Name == service.Name {
				return nil, ErrPrecondition
			}
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if len(values) != len(keys) {
			return nil, fmt.Errorf("%w: every new key requires a value", ErrInvalid)
		}
		for _, key := range keys {
			var count int
			if err := tx.QueryRowContext(ctx, r.dialect.Rebind(`SELECT COUNT(*) FROM credentials WHERE vault_id=? AND key=?`), vault, key).Scan(&count); err != nil {
				return nil, err
			}
			if count != 0 {
				return nil, ErrPrecondition
			}
		}
	} else {
		if err != nil {
			return nil, err
		}
		if revision == "" || !hmac.Equal([]byte(current.Revision), []byte(revision)) {
			return nil, ErrPrecondition
		}
		if !slices.Equal(keys, current.Keys) {
			return nil, fmt.Errorf("%w: set membership cannot be changed by an edit", ErrInvalid)
		}
	}
	if err := setExclusive(services, service.Name, keys); err != nil {
		return nil, err
	}
	kept := make([]broker.Service, 0, len(services)+1)
	for _, existing := range services {
		if existing.Name != service.Name {
			if broker.HostsOverlap(existing, service) {
				return nil, ErrConflict
			}
			kept = append(kept, existing)
		}
	}
	kept = append(kept, service)
	now := r.dialect.FormatTime(time.Now())
	for key, value := range values {
		ct, nonce, err := crypto.Encrypt([]byte(value), r.key)
		if err != nil {
			return nil, err
		}
		if createOnly {
			_, err = tx.ExecContext(ctx, r.dialect.Rebind(`INSERT INTO credentials
				(id,vault_id,key,type,ciphertext,nonce,created_at,updated_at) VALUES (?,?,?,'static',?,?,?,?)`),
				rand.Text(), vault, key, ct, nonce, now, now)
		} else {
			_, err = tx.ExecContext(ctx, r.dialect.Rebind(`UPDATE credentials SET ciphertext=?,nonce=?,updated_at=? WHERE vault_id=? AND key=? AND type='static'`),
				ct, nonce, now, vault, key)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := r.saveServices(ctx, tx, vault, kept); err != nil {
		return nil, err
	}
	result, err := r.getSet(ctx, tx, vault, service.Name, kept)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// DeleteSet removes exactly the current exclusive service/key membership.
func (r *Repository) DeleteSet(ctx context.Context, vault, name, revision string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	services, err := r.services(ctx, tx, vault)
	if err != nil {
		return err
	}
	current, err := r.getSet(ctx, tx, vault, name, services)
	if err != nil {
		return err
	}
	if revision == "" || !hmac.Equal([]byte(current.Revision), []byte(revision)) {
		return ErrPrecondition
	}
	kept := make([]broker.Service, 0, len(services))
	for _, service := range services {
		if service.Name != name {
			kept = append(kept, service)
		}
	}
	if err := r.saveServices(ctx, tx, vault, kept); err != nil {
		return err
	}
	for _, key := range current.Keys {
		if _, err := tx.ExecContext(ctx, r.dialect.Rebind(`DELETE FROM credentials WHERE vault_id=? AND key=? AND type='static'`), vault, key); err != nil {
			return err
		}
	}
	return tx.Commit()
}
