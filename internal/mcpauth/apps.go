package mcpauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
)

type AppInput struct {
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret,omitempty"`
}

type AppInfo struct {
	ClientID          string    `json:"client_id"`
	UpdatedAt         time.Time `json:"updated_at"`
	Accounts          int       `json:"accounts"`
	AccountsAllVaults *int      `json:"accounts_all_vaults,omitempty"`
}

func (m *Manager) LockApps(ctx context.Context) (func(), error) {
	return m.core.LockVault(ctx, "gateway-oauth-apps")
}

func (m *Manager) storedApp(ctx context.Context, vault, id string) (*Client, error) {
	var client Client
	if vault != "" {
		if err := m.repo.get(ctx, vault, "app", id, &client); err != nil {
			return nil, err
		}
	} else {
		raw, err := m.core.GetSetting(ctx, "gateway.oauth_app."+id)
		if err != nil {
			return nil, err
		}
		var envelope struct{ Ciphertext, Nonce []byte }
		if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
			return nil, err
		}
		if err := m.repo.decode(envelope.Ciphertext, envelope.Nonce, &client); err != nil {
			return nil, err
		}
	}
	return &client, nil
}

func (m *Manager) allVaults(ctx context.Context) ([]string, error) {
	rows, err := m.repo.db.QueryContext(ctx, `SELECT id FROM vaults ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func appMatches(a Account, scope string, c Client) bool {
	return a.Client.Kind == "app" && a.Client.Source == scope && a.Client.Issuer == c.Issuer && a.Client.ID == c.ID
}

func (m *Manager) appAccounts(ctx context.Context, vault string, c Client, change func(string, *Account) error) (int, error) {
	scope := "vault"
	ids := []string{vault}
	if vault == "" {
		scope = "install"
		var err error
		ids, err = m.allVaults(ctx)
		if err != nil {
			return 0, err
		}
	}
	count := 0
	for _, id := range ids {
		accounts, err := m.repo.Accounts(ctx, id)
		if err != nil {
			return 0, err
		}
		for i := range accounts {
			if appMatches(accounts[i], scope, c) {
				count++
				if change != nil {
					if err := change(id, &accounts[i]); err != nil {
						return 0, err
					}
				}
			}
		}
	}
	return count, nil
}

func (m *Manager) GetApp(ctx context.Context, vault, id string) (*AppInfo, error) {
	if _, err := catalogProvider(id); err != nil {
		return nil, err
	}
	unlock, err := m.LockApps(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	client, err := m.storedApp(ctx, vault, id)
	if err != nil {
		return nil, err
	}
	count, err := m.appAccounts(ctx, vault, *client, nil)
	if err != nil {
		return nil, err
	}
	info := &AppInfo{ClientID: client.ID, UpdatedAt: client.UpdatedAt, Accounts: count}
	if vault == "" {
		info.AccountsAllVaults = &count
	}
	return info, nil
}

func (m *Manager) PutApp(ctx context.Context, vault, id string, input AppInput) (*AppInfo, error) {
	p, err := catalogProvider(id)
	if err != nil {
		return nil, err
	}
	if input.ClientID == "" {
		return nil, failure("invalid_app", "client_id is required")
	}
	unlock, err := m.LockApps(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	old, err := m.storedApp(ctx, vault, id)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	secret := ""
	if old != nil && old.ID == input.ClientID {
		secret = old.Secret
	}
	if input.ClientSecret != nil {
		secret = *input.ClientSecret
	}
	if secret == "" {
		return nil, failure("invalid_app", "client_secret is required for a new or changed client_id")
	}
	next := Client{Issuer: p.Issuer, ID: input.ClientID, Secret: secret, AuthMethod: "client_secret_post", Kind: "app", UpdatedAt: m.now().UTC()}
	if old != nil && old.ID != next.ID {
		if err := m.invalidateApp(ctx, vault, *old); err != nil {
			return nil, err
		}
	}
	if err := m.storeAppValue(ctx, vault, id, next); err != nil {
		return nil, err
	}
	// A secret-only rotation retains accounts but updates their pinned secret.
	if old != nil && old.ID == next.ID {
		_, err = m.appAccounts(ctx, vault, *old, func(v string, a *Account) error {
			a.Client.Secret = next.Secret
			a.Client.UpdatedAt = next.UpdatedAt
			return m.repo.saveAccount(ctx, v, a, false)
		})
		if err != nil {
			return nil, err
		}
	}
	count, err := m.appAccounts(ctx, vault, next, nil)
	if err != nil {
		return nil, err
	}
	info := &AppInfo{ClientID: next.ID, UpdatedAt: next.UpdatedAt, Accounts: count}
	if vault == "" {
		info.AccountsAllVaults = &count
	}
	return info, nil
}

func (m *Manager) storeAppValue(ctx context.Context, vault, id string, client Client) error {
	if vault != "" {
		return m.repo.put(ctx, m.repo.db, vault, "app", id, &client, 0)
	}
	plaintext, err := json.Marshal(client)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(plaintext)
	ct, nonce, err := crypto.Encrypt(plaintext, m.repo.key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(struct{ Ciphertext, Nonce []byte }{ct, nonce})
	if err != nil {
		return err
	}
	return m.core.SetSetting(ctx, "gateway.oauth_app."+id, string(data))
}

func (m *Manager) DeleteApp(ctx context.Context, vault, id string) error {
	if _, err := catalogProvider(id); err != nil {
		return err
	}
	unlock, err := m.LockApps(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	old, err := m.storedApp(ctx, vault, id)
	if err != nil {
		return err
	}
	if err := m.invalidateApp(ctx, vault, *old); err != nil {
		return err
	}
	if vault == "" {
		_, err = m.repo.db.ExecContext(ctx, m.repo.dialect.Rebind(`DELETE FROM instance_settings WHERE key=?`), "gateway.oauth_app."+id)
	} else {
		_, err = m.repo.db.ExecContext(ctx, m.repo.dialect.Rebind(`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='app' AND record_key=?`), vault, id)
	}
	return err
}

func (m *Manager) invalidateApp(ctx context.Context, vault string, old Client) error {
	scope := "vault"
	query := `SELECT vault_id,record_key,ciphertext,nonce FROM gateway_oauth_records WHERE kind='state'`
	args := []any{}
	if vault != "" {
		query += ` AND vault_id=?`
		args = append(args, vault)
	} else {
		scope = "install"
	}
	rows, err := m.repo.db.QueryContext(ctx, m.repo.dialect.Rebind(query), args...)
	if err != nil {
		return err
	}
	type pending struct{ vault, key string }
	var deleted []pending
	for rows.Next() {
		var id, key string
		var ct, nonce []byte
		var flow Flow
		if err := rows.Scan(&id, &key, &ct, &nonce); err != nil {
			rows.Close()
			return err
		}
		if err := m.repo.decode(ct, nonce, &flow); err != nil {
			rows.Close()
			return err
		}
		if appMatches(flow.Account, scope, old) {
			deleted = append(deleted, pending{id, key})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, state := range deleted {
		if _, err := m.repo.db.ExecContext(ctx, m.repo.dialect.Rebind(`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='state' AND record_key=?`), state.vault, state.key); err != nil {
			return err
		}
	}
	_, err = m.appAccounts(ctx, vault, old, func(id string, a *Account) error {
		unlock, err := m.core.LockVault(ctx, id)
		if err != nil {
			return err
		}
		defer unlock()
		cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		m.revoke(cleanup, a)
		return m.repo.removeAccount(ctx, id, a, false)
	})
	return err
}
