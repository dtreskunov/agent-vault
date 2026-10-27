package mcpauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/Infisical/agent-vault/internal/broker"
)

const modelSetting = "gateway.oauth_model"

type storedApp struct {
	vault  string
	client Client
	legacy bool
}

func legacyConfig(c Client) AppConfig {
	config := AppConfig{Label: c.AppID, AuthMethod: c.AuthMethod, Identity: "none", TokenScopeSeparator: "space",
		APIHosts: []string{}, DefaultScopes: []string{}}
	if config.AuthMethod == "" {
		config.AuthMethod = "client_secret_post"
	}
	switch c.Issuer {
	case "https://accounts.google.com":
		config.Identity = "google"
		config.AuthorizationParams = map[string]string{
			"access_type": "offline", "include_granted_scopes": "true", "prompt": "consent",
		}
	case "https://github.com/login/oauth":
		config.Identity, config.TokenScopeSeparator = "github", "comma"
	}
	return config
}

// Migrate runs before any proxy capability is exposed. It does not refresh or
// rewrite credential tokens, and commits the entire model transition atomically.
func (m *Manager) Migrate(ctx context.Context) error {
	appUnlock, err := m.LockApps(ctx)
	if err != nil {
		return err
	}
	defer appUnlock()
	version, err := m.core.GetSetting(ctx, modelSetting)
	if err == nil && version == "2" {
		return nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if version != "" {
		return fmt.Errorf("unsupported OAuth storage model %q", version)
	}
	ids, err := m.allVaults(ctx)
	if err != nil {
		return err
	}
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
	apps := map[string]*storedApp{}
	for _, vault := range append([]string{""}, ids...) {
		clients, err := m.configuredApps(ctx, vault)
		if err != nil {
			return err
		}
		for _, client := range clients {
			if vault != "" && client.Source != "vault" {
				continue
			}
			legacy := client.Config.AuthMethod == ""
			if legacy {
				client.Config = legacyConfig(client)
			}
			apps[vault+"\x00"+client.AppID] = &storedApp{vault, client, legacy}
		}
	}
	var accounts []appAccount
	for _, id := range ids {
		items, err := m.repo.Accounts(ctx, id)
		if err != nil {
			return err
		}
		for _, a := range items {
			accounts = append(accounts, appAccount{id, a})
		}
	}
	type pending struct {
		vault, key string
		flow       Flow
	}
	var states []pending
	rows, err := m.repo.db.QueryContext(ctx, `SELECT vault_id,record_key,ciphertext,nonce FROM gateway_oauth_records WHERE kind='state'`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var state pending
		var ct, nonce []byte
		if err := rows.Scan(&state.vault, &state.key, &ct, &nonce); err != nil {
			rows.Close()
			return err
		}
		if err := m.repo.decode(ct, nonce, &state.flow); err != nil {
			rows.Close()
			return err
		}
		states = append(states, state)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	bind := func(vault string, a *Account) (*storedApp, error) {
		if a.Client.Kind != "app" {
			return nil, nil
		}
		source := vault
		if a.Client.Source == "install" {
			source = ""
		}
		var selected *storedApp
		for _, app := range apps {
			if app.vault != source || app.client.ID != a.Client.ID || app.client.Issuer != a.Client.Issuer {
				continue
			}
			id := a.Client.AppID
			if id == "" {
				id = a.Provider
			}
			if id != "" && id != app.client.AppID {
				continue
			}
			if selected != nil {
				return nil, failure("ambiguous_app", "Legacy account matches multiple issuing apps")
			}
			selected = app
		}
		if selected == nil {
			return nil, failure("invalid_app", "Legacy account's issuing app is missing or inconsistent")
		}
		a.Client.AppID = selected.client.AppID
		if a.Client.Config.AuthMethod == "" {
			a.Client.Config = selected.client.Config
			a.Client.Config.AuthorizationEndpoint = a.Metadata.AuthorizationEndpoint
			a.Client.Config.TokenEndpoint = a.Metadata.TokenEndpoint
			a.Client.Config.RevocationEndpoint = a.Metadata.RevocationEndpoint
			a.Client.Config.JWKSURI = a.Metadata.JWKSURI
			a.Client.Config.AuthMethod = a.Client.AuthMethod
		}
		if selected.client.Config.TokenEndpoint == "" {
			selected.client.Config.AuthorizationEndpoint = a.Metadata.AuthorizationEndpoint
			selected.client.Config.TokenEndpoint = a.Metadata.TokenEndpoint
			selected.client.Config.RevocationEndpoint = a.Metadata.RevocationEndpoint
			selected.client.Config.JWKSURI = a.Metadata.JWKSURI
		} else if a.Client.Config.TokenEndpoint != selected.client.Config.TokenEndpoint ||
			a.Client.Config.AuthorizationEndpoint != selected.client.Config.AuthorizationEndpoint {
			return nil, failure("invalid_app", "Legacy issuing app has inconsistent pinned OAuth endpoints")
		}
		return selected, nil
	}
	tx, err := m.repo.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for i := range accounts {
		entry := &accounts[i]
		a := &entry.value
		legacy := a.AppID == "" && a.Provider != ""
		app, err := bind(entry.vault, a)
		if err != nil {
			return fmt.Errorf("migrate OAuth account %s: %w", a.Key, err)
		}
		if a.ScopeSource == "" {
			a.ScopeSource = "legacy"
		}
		if legacy {
			a.AppID, a.IdentityAdapter = a.Client.AppID, a.Client.Config.Identity
			services, err := m.repo.services(ctx, tx, entry.vault)
			if err != nil {
				return err
			}
			for _, service := range services {
				owned, err := accountOwns(*a, service)
				if err != nil {
					return err
				}
				if !owned {
					continue
				}
				port := service.Port
				if port == nil {
					port = new(443)
				}
				pattern := broker.Service{Host: service.Host, Port: port}.MatcherPattern()
				canonical, _, _, err := apiHost(pattern)
				if err != nil {
					return err
				}
				a.APIHosts = append(a.APIHosts, canonical)
			}
			a.APIHosts = unique(a.APIHosts)
			if len(a.APIHosts) == 0 {
				return failure("service_conflict", "Legacy API account has no owned generated destinations")
			}
			a.Client.Config.APIHosts = slices.Clone(a.APIHosts)
			if err := m.repo.updateServices(ctx, tx, entry.vault, a, false); err != nil {
				return fmt.Errorf("migrate OAuth account %s: %w", a.Key, err)
			}
		}
		if app != nil && app.legacy && a.AppID != "" {
			app.client.Config.APIHosts = unique(append(app.client.Config.APIHosts, a.APIHosts...))
		}
		if err := m.repo.put(ctx, tx, entry.vault, "account", a.Key, a, 0); err != nil {
			return err
		}
		if err := m.repo.rememberTokenAuthority(ctx, tx, a.Metadata.TokenEndpoint); err != nil {
			return err
		}
	}
	expired := 0
	for _, state := range states {
		a := &state.flow.Account
		if a.Provider != "" && a.AppID == "" {
			if _, err := tx.ExecContext(ctx, m.repo.dialect.Rebind(
				`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='state' AND record_key=?`), state.vault, state.key); err != nil {
				return err
			}
			expired++
			continue
		}
		if _, err := bind(state.vault, a); err != nil {
			return err
		}
		if err := m.repo.put(ctx, tx, state.vault, "state", state.key, &state.flow, state.flow.ExpiresAt.Unix()); err != nil {
			return err
		}
		if err := m.repo.rememberTokenAuthority(ctx, tx, a.Metadata.TokenEndpoint); err != nil {
			return err
		}
	}
	keys := make([]string, 0, len(apps))
	for key := range apps {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	for _, key := range keys {
		app := apps[key]
		if err := m.repo.storeApp(ctx, tx, app.vault, app.client.AppID, app.client); err != nil {
			return err
		}
		if err := m.repo.rememberTokenAuthority(ctx, tx, app.client.Config.TokenEndpoint); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, m.repo.dialect.Rebind(`INSERT INTO instance_settings (key,value,updated_at) VALUES (?,?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at`),
		modelSetting, "2", m.repo.dialect.FormatTime(m.now()))
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	m.logger.Info("OAuth accounts migrated to generic host routing", "accounts", len(accounts), "expired_signins", expired)
	return nil
}
