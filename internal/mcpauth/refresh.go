package mcpauth

import (
	"context"
	"errors"
	"time"

	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

func (m *Manager) Credential(ctx context.Context, vault, key string) (*store.Credential, error) {
	unlock, err := m.core.LockVault(ctx, vault)
	if err != nil {
		return nil, err
	}
	defer unlock()
	account, err := m.repo.Account(ctx, vault, key)
	if err != nil {
		return nil, err
	}
	if account.Reconnect || account.AccessToken == "" {
		return nil, failure("oauth_not_connected", "MCP OAuth account needs a new sign-in")
	}
	changed := false
	if !account.ExpiresAt.IsZero() && account.ExpiresAt.Before(m.now().Add(5*time.Minute)) {
		if account.RefreshToken == "" {
			if account.ExpiresAt.Before(m.now()) {
				return nil, failure("oauth_not_connected", "MCP OAuth token expired; sign in again")
			}
		} else {
			token, err := oauth.Refresh(ctx, oauth.RefreshConfig{
				Client: m.client, TokenURL: account.Metadata.TokenEndpoint, ClientID: account.Client.ID,
				ClientSecret: account.Client.Secret, TokenAuthMethod: account.Client.AuthMethod,
				RefreshToken: account.RefreshToken, Scopes: account.Scopes, Resource: account.Resource,
			})
			if err != nil {
				if invalidClient(err) && account.Client.Kind == "registered" {
					if err := m.reregister(ctx, vault, account); err != nil {
						return nil, err
					}
					return nil, failure("oauth_not_connected", "MCP OAuth client was re-registered; sign in again")
				}
				var endpoint *oauth.TokenError
				if errors.As(err, &endpoint) && endpoint.Permanent {
					account.Reconnect, account.UpdatedAt = true, m.now().UTC()
					if saveErr := m.repo.saveAccount(ctx, vault, account, false); saveErr != nil {
						return nil, saveErr
					}
				}
				return nil, failure("oauth_refresh_failed", "MCP OAuth token refresh failed")
			}
			if token.AccessToken == "" || (token.TokenType != "" && token.TokenType != "Bearer" && token.TokenType != "bearer") {
				return nil, failure("oauth_refresh_failed", "MCP OAuth token refresh returned an unusable token")
			}
			account.AccessToken, account.ExpiresAt = token.AccessToken, token.ExpiresAt
			if token.RefreshToken != "" {
				account.RefreshToken = token.RefreshToken
			}
			changed = true
		}
	}
	now := m.now().UTC()
	if account.LastUsedAt == nil || now.Sub(*account.LastUsedAt) >= time.Minute {
		account.LastUsedAt = &now
		changed = true
	}
	if changed {
		account.UpdatedAt = now
		if err := m.repo.saveAccount(ctx, vault, account, false); err != nil {
			return nil, err
		}
	}
	return m.core.GetCredential(ctx, vault, key)
}
