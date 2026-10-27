package mcpauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
)

type AppInfo struct {
	AppConfig
	ID                string    `json:"id"`
	Issuer            string    `json:"issuer"`
	ClientID          string    `json:"client_id"`
	ClientSecretSet   bool      `json:"client_secret_set"`
	Source            string    `json:"source"`
	OverridesInstall  bool      `json:"overrides_install"`
	UpdatedAt         time.Time `json:"updated_at"`
	Accounts          int       `json:"accounts"`
	AccountsAllVaults *int      `json:"accounts_all_vaults,omitempty"`
}

func (c Client) metadata() oauthex.AuthServerMeta {
	return oauthex.AuthServerMeta{
		Issuer: c.Issuer, AuthorizationEndpoint: c.Config.AuthorizationEndpoint, TokenEndpoint: c.Config.TokenEndpoint,
		RevocationEndpoint: c.Config.RevocationEndpoint, JWKSURI: c.Config.JWKSURI,
		CodeChallengeMethodsSupported: []string{"S256"},
	}
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
		client.Source = "vault"
	} else {
		raw, err := m.core.GetSetting(ctx, "gateway.oauth_app."+id)
		if err != nil {
			return nil, err
		}
		if err := m.repo.decodeEnvelope(raw, &client); err != nil {
			return nil, err
		}
		client.Source = "install"
	}
	client.AppID, client.Kind = id, "app"
	return &client, nil
}

func (m *Manager) effectiveApp(ctx context.Context, vault, id string) (*Client, error) {
	if vault != "" {
		client, err := m.storedApp(ctx, vault, id)
		if err == nil || !errors.Is(err, sql.ErrNoRows) {
			return client, err
		}
	}
	return m.storedApp(ctx, "", id)
}

func (r *Repository) decodeEnvelope(raw string, value any) error {
	var envelope struct{ Ciphertext, Nonce []byte }
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return err
	}
	return r.decode(envelope.Ciphertext, envelope.Nonce, value)
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
	return a.Client.Kind == "app" && a.Client.Source == scope && a.Client.AppID == c.AppID &&
		a.Client.Issuer == c.Issuer && a.Client.ID == c.ID
}

func (m *Manager) appAccounts(ctx context.Context, vault string, c Client, change func(string, *Account) error) (int, error) {
	ids := []string{vault}
	if vault == "" {
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
			if appMatches(accounts[i], c.Source, c) {
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

func (m *Manager) configuredApps(ctx context.Context, vault string) ([]Client, error) {
	apps := map[string]Client{}
	rows, err := m.repo.db.QueryContext(ctx, `SELECT key,value FROM instance_settings WHERE substr(key,1,18)='gateway.oauth_app.' ORDER BY key`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var key, raw string
		var client Client
		if err := rows.Scan(&key, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		if err := m.repo.decodeEnvelope(raw, &client); err != nil {
			rows.Close()
			return nil, err
		}
		client.AppID, client.Kind, client.Source = strings.TrimPrefix(key, "gateway.oauth_app."), "app", "install"
		apps[client.AppID] = client
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if vault != "" {
		rows, err := m.repo.db.QueryContext(ctx, m.repo.dialect.Rebind(
			`SELECT record_key,ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='app' ORDER BY record_key`), vault)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var id string
			var ct, nonce []byte
			var client Client
			if err := rows.Scan(&id, &ct, &nonce); err != nil {
				rows.Close()
				return nil, err
			}
			if err := m.repo.decode(ct, nonce, &client); err != nil {
				rows.Close()
				return nil, err
			}
			client.AppID, client.Kind, client.Source = id, "app", "vault"
			apps[id] = client
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	result := make([]Client, 0, len(apps))
	for _, client := range apps {
		result = append(result, client)
	}
	slices.SortFunc(result, func(a, b Client) int { return strings.Compare(a.AppID, b.AppID) })
	return result, nil
}

func (m *Manager) appInfo(ctx context.Context, vault string, client Client) (*AppInfo, error) {
	count, err := m.appAccounts(ctx, vault, client, nil)
	if err != nil {
		return nil, err
	}
	info := &AppInfo{AppConfig: client.Config, ID: client.AppID, Issuer: client.Issuer, ClientID: client.ID,
		ClientSecretSet: client.Secret != "", Source: client.Source, UpdatedAt: client.UpdatedAt, Accounts: count}
	if vault == "" {
		info.AccountsAllVaults = &count
	} else if client.Source == "vault" {
		_, err := m.storedApp(ctx, "", client.AppID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		info.OverridesInstall = err == nil
	}
	return info, nil
}

func (m *Manager) ListApps(ctx context.Context, vault string) ([]AppInfo, error) {
	unlock, err := m.LockApps(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	clients, err := m.configuredApps(ctx, vault)
	if err != nil {
		return nil, err
	}
	items := make([]AppInfo, 0, len(clients))
	for _, client := range clients {
		info, err := m.appInfo(ctx, vault, client)
		if err != nil {
			return nil, err
		}
		items = append(items, *info)
	}
	return items, nil
}

func (m *Manager) GetApp(ctx context.Context, vault, id string) (*AppInfo, error) {
	if err := appIDValid(id); err != nil {
		return nil, err
	}
	unlock, err := m.LockApps(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	client, err := m.effectiveApp(ctx, vault, id)
	if err != nil {
		return nil, err
	}
	return m.appInfo(ctx, vault, *client)
}

type appAccount struct {
	vault string
	value Account
}

type pendingApp struct{ vault, key string }

func (m *Manager) appDependents(ctx context.Context, source string, client Client) ([]appAccount, []pendingApp, error) {
	accounts := []appAccount{}
	_, err := m.appAccounts(ctx, source, client, func(vault string, a *Account) error {
		accounts = append(accounts, appAccount{vault, *a})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	rows, err := m.repo.db.QueryContext(ctx, `SELECT vault_id,record_key,ciphertext,nonce FROM gateway_oauth_records WHERE kind='state'`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var pending []pendingApp
	for rows.Next() {
		var id, key string
		var ct, nonce []byte
		var flow Flow
		if err := rows.Scan(&id, &key, &ct, &nonce); err != nil {
			return nil, nil, err
		}
		if err := m.repo.decode(ct, nonce, &flow); err != nil {
			return nil, nil, err
		}
		if (source == "" || source == id) && appMatches(flow.Account, client.Source, client) {
			pending = append(pending, pendingApp{id, key})
		}
	}
	return accounts, pending, rows.Err()
}

func (m *Manager) PutApp(ctx context.Context, vault, id string, input AppInput) (*AppInfo, error) {
	if err := appIDValid(id); err != nil {
		return nil, err
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
	next, err := configureApp(id, old, input)
	if err != nil {
		return nil, err
	}
	next.Source = "vault"
	if vault == "" {
		next.Source = "install"
	}
	next.UpdatedAt = m.now().UTC()
	if err := m.changeApp(ctx, vault, id, old, &next); err != nil {
		return nil, err
	}
	return m.appInfo(ctx, vault, next)
}

func (r *Repository) storeApp(ctx context.Context, exec executor, vault, id string, client Client) error {
	if vault != "" {
		return r.put(ctx, exec, vault, "app", id, &client, 0)
	}
	plaintext, err := json.Marshal(client)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(plaintext)
	ct, nonce, err := crypto.Encrypt(plaintext, r.key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(struct{ Ciphertext, Nonce []byte }{ct, nonce})
	if err != nil {
		return err
	}
	_, err = exec.ExecContext(ctx, r.dialect.Rebind(`INSERT INTO instance_settings (key,value,updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`),
		"gateway.oauth_app."+id, string(data), r.dialect.FormatTime(client.UpdatedAt))
	return err
}

func (m *Manager) DeleteApp(ctx context.Context, vault, id string) error {
	if err := appIDValid(id); err != nil {
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
	return m.changeApp(ctx, vault, id, old, nil)
}

func (m *Manager) changeApp(ctx context.Context, vault, id string, old, next *Client) error {
	var accounts []appAccount
	var pending []pendingApp
	if old != nil {
		var err error
		accounts, pending, err = m.appDependents(ctx, vault, *old)
		if err != nil {
			return err
		}
	}
	ids := []string{}
	for _, a := range accounts {
		ids = append(ids, a.vault)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	unlocks := []func(){}
	defer func() {
		for i := len(unlocks) - 1; i >= 0; i-- {
			unlocks[i]()
		}
	}()
	for _, id := range ids {
		unlock, err := m.core.LockVault(ctx, id)
		if err != nil {
			return err
		}
		unlocks = append(unlocks, unlock)
	}
	tx, err := m.repo.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	invalidates := next == nil || (old != nil && !sameAppBinding(*old, *next))
	for i := range accounts {
		a := &accounts[i]
		if invalidates {
			if err := m.repo.deleteAccount(ctx, tx, a.vault, &a.value, false); err != nil {
				return err
			}
		} else if old.Secret != next.Secret {
			a.value.Client.Secret, a.value.Client.UpdatedAt = next.Secret, next.UpdatedAt
			if err := m.repo.writeAccount(ctx, tx, a.vault, &a.value, false); err != nil {
				return err
			}
		}
	}
	if invalidates {
		for _, state := range pending {
			if _, err := tx.ExecContext(ctx, m.repo.dialect.Rebind(
				`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='state' AND record_key=?`), state.vault, state.key); err != nil {
				return err
			}
		}
	}
	if next != nil {
		if err := m.repo.storeApp(ctx, tx, vault, id, *next); err != nil {
			return err
		}
		if err := m.repo.rememberTokenAuthority(ctx, tx, next.Config.TokenEndpoint); err != nil {
			return err
		}
	} else if vault == "" {
		_, err = tx.ExecContext(ctx, m.repo.dialect.Rebind(`DELETE FROM instance_settings WHERE key=?`), "gateway.oauth_app."+id)
	} else {
		_, err = tx.ExecContext(ctx, m.repo.dialect.Rebind(`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='app' AND record_key=?`), vault, id)
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if invalidates {
		cleanup, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		for i := range accounts {
			m.revoke(cleanup, &accounts[i].value)
		}
	}
	return nil
}
