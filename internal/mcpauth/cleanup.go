package mcpauth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (m *Manager) revoke(ctx context.Context, account *Account) error {
	if account.Client.Kind == "app" && account.Issuer == "https://github.com/login/oauth" && account.AccessToken != "" {
		data, err := json.Marshal(map[string]string{"access_token": account.AccessToken})
		if err != nil {
			m.logger.Error("encoding GitHub revocation request", "err", err)
			return err
		}
		request, err := http.NewRequestWithContext(ctx, "DELETE", "https://api.github.com/applications/"+url.PathEscape(account.Client.ID)+"/token", bytes.NewReader(data))
		if err != nil {
			m.logger.Error("building GitHub revocation request", "err", err)
			return err
		}
		request.SetBasicAuth(account.Client.ID, account.Client.Secret)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Accept", "application/vnd.github+json")
		return m.cleanupRequest(request, "GitHub token revocation", account.Key)
	}
	if account.Metadata.RevocationEndpoint == "" {
		return nil
	}
	var failures []error
	for _, token := range []struct{ value, hint string }{
		{account.AccessToken, "access_token"}, {account.RefreshToken, "refresh_token"},
	} {
		if token.value == "" {
			continue
		}
		form := url.Values{"token": {token.value}, "token_type_hint": {token.hint}, "client_id": {account.Client.ID}}
		if account.Client.AuthMethod == "client_secret_post" && account.Client.Secret != "" {
			form.Set("client_secret", account.Client.Secret)
		}
		request, err := http.NewRequestWithContext(ctx, "POST", account.Metadata.RevocationEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			m.logger.Warn("MCP token revocation request failed", "key", account.Key)
			failures = append(failures, err)
			continue
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if account.Client.AuthMethod == "client_secret_basic" {
			request.SetBasicAuth(account.Client.ID, account.Client.Secret)
		}
		if err := m.cleanupRequest(request, "token revocation", account.Key); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (m *Manager) deleteClient(ctx context.Context, client Client) error {
	if client.Kind != "registered" || client.ManagementURI == "" || client.ManagementToken == "" {
		return nil
	}
	request, err := http.NewRequestWithContext(ctx, "DELETE", client.ManagementURI, nil)
	if err != nil {
		m.logger.Warn("MCP client cleanup request failed", "issuer", client.Issuer)
		return err
	}
	request.Header.Set("Authorization", "Bearer "+client.ManagementToken)
	return m.cleanupRequest(request, "client deletion", client.Issuer)
}

func (m *Manager) cleanupRequest(request *http.Request, operation, key string) error {
	response, err := m.client.Do(request)
	if err != nil {
		m.logger.Warn("MCP remote cleanup failed; local disconnect continues", "operation", operation, "key", key)
		return fmt.Errorf("%s failed", operation)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Google returns 400 for an already-invalid token instead of RFC 7009's 200.
		if operation == "token revocation" && response.StatusCode == http.StatusBadRequest && readErr == nil {
			var failure struct {
				Error string `json:"error"`
			}
			if json.Unmarshal(body, &failure) == nil && failure.Error == "invalid_token" {
				m.logger.Info("MCP token already invalid; revocation complete", "key", key)
				return nil
			}
		}
		m.logger.Warn("MCP remote cleanup unavailable; local disconnect continues",
			"operation", operation, "key", key, "status", response.StatusCode)
		return fmt.Errorf("%s returned HTTP %d", operation, response.StatusCode)
	}
	return nil
}

// DisconnectConnection is the sole shared-connection upstream lifecycle
// operation. A group detachment never reaches this method.
func (m *Manager) DisconnectConnection(ctx context.Context, vault, key string) error {
	appUnlock, err := m.LockApps(ctx)
	if err != nil {
		return err
	}
	defer appUnlock()
	unlock, err := m.core.LockVault(ctx, vault)
	if err != nil {
		return err
	}
	defer unlock()
	account, err := m.repo.Account(ctx, vault, key)
	if errors.Is(err, sql.ErrNoRows) {
		return m.disconnectDraftConnection(ctx, vault, key)
	}
	if err != nil {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err = m.revoke(cleanupCtx, account); err != nil {
		return err
	}
	if err = m.deleteClient(cleanupCtx, account.Client); err != nil {
		return err
	}
	tx, err := m.repo.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = m.repo.deleteAccount(ctx, tx, vault, account, false); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, m.repo.dialect.Rebind(`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='client' AND record_key=?`), vault, digest(account.Issuer+"\x00"+key))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (m *Manager) disconnectDraftConnection(ctx context.Context, vault, key string) error {
	rows, err := m.repo.db.QueryContext(ctx, m.repo.dialect.Rebind(`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='client' AND account_key=?`), vault, key)
	if err != nil {
		return err
	}
	var clients []Client
	for rows.Next() {
		var ct, nonce []byte
		var client Client
		if err = rows.Scan(&ct, &nonce); err != nil {
			rows.Close()
			return err
		}
		if err = m.repo.decode(ct, nonce, &client); err != nil {
			rows.Close()
			return err
		}
		clients = append(clients, client)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, client := range clients {
		if err = m.deleteClient(cleanupCtx, client); err != nil {
			return err
		}
	}
	_, err = m.repo.db.ExecContext(ctx, m.repo.dialect.Rebind(`DELETE FROM gateway_oauth_records WHERE vault_id=? AND account_key=? AND kind IN ('client','state')`), vault, key)
	return err
}

func (m *Manager) Disconnect(ctx context.Context, vault, key string) error {
	appUnlock, err := m.LockApps(ctx)
	if err != nil {
		return err
	}
	defer appUnlock()
	unlock, err := m.core.LockVault(ctx, vault)
	if err != nil {
		return err
	}
	defer unlock()
	account, err := m.repo.Account(ctx, vault, key)
	if err != nil {
		return err
	}
	accounts, err := m.repo.Accounts(ctx, vault)
	if err != nil {
		return err
	}
	removeClient := true
	for _, other := range accounts {
		if other.Key != key && other.Issuer == account.Issuer {
			removeClient = false
		}
	}
	pending, err := m.pendingIssuer(ctx, vault, key, account.Issuer)
	if err != nil {
		return err
	}
	if pending {
		removeClient = false
	}
	// Revoke upstream before forgetting the encrypted tokens. Cleanup is best-effort.
	cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m.revoke(cleanupCtx, account)
	if removeClient {
		var current Client
		err := m.repo.get(ctx, vault, "client", digest(account.Issuer), &current)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err == nil && current.ID != account.Client.ID {
			m.deleteClient(cleanupCtx, current)
		}
		m.deleteClient(cleanupCtx, account.Client)
	}
	return m.repo.removeAccount(ctx, vault, account, removeClient)
}

func (m *Manager) pendingIssuer(ctx context.Context, vault, exclude, issuer string) (bool, error) {
	rows, err := m.repo.db.QueryContext(ctx, m.repo.dialect.Rebind(
		`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='state' AND account_key<>? AND expires_at>?`),
		vault, exclude, m.now().Unix())
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var ct, nonce []byte
		var flow Flow
		if err := rows.Scan(&ct, &nonce); err != nil {
			return false, err
		}
		if err := m.repo.decode(ct, nonce, &flow); err != nil {
			return false, err
		}
		if flow.Account.Issuer == issuer {
			return true, nil
		}
	}
	return false, rows.Err()
}

// CleanupVault must run under the caller's vault lock before the database cascade.
func (m *Manager) CleanupVault(ctx context.Context, vault string) error {
	accounts, err := m.repo.Accounts(ctx, vault)
	if err != nil {
		return err
	}
	clientsByID := make(map[string]Client)
	cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for i := range accounts {
		m.revoke(cleanupCtx, &accounts[i])
		client := accounts[i].Client
		if client.Kind == "registered" {
			clientsByID[client.Issuer+"|"+client.ID] = client
		}
	}
	rows, err := m.repo.db.QueryContext(ctx, m.repo.dialect.Rebind(
		`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='client'`), vault)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ct, nonce []byte
		var client Client
		if err := rows.Scan(&ct, &nonce); err != nil {
			rows.Close()
			return err
		}
		if err := m.repo.decode(ct, nonce, &client); err != nil {
			rows.Close()
			return err
		}
		clientsByID[client.Issuer+"|"+client.ID] = client
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, client := range clientsByID {
		m.deleteClient(cleanupCtx, client)
	}
	return nil
}
