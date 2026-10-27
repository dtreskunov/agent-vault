package mcpauth

import (
	"context"

	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/oauthidentity"
)

func (m *Manager) resolveIdentity(ctx context.Context, a *Account, token *oauth.TokenResponse, nonce string) {
	var identity oauthidentity.Identity
	var err error
	if a.IdentityAdapter == "google" || a.IdentityAdapter == "github" {
		identity, err = oauthidentity.Provider(ctx, m.client, a.IdentityAdapter, token.AccessToken)
	} else if (a.AppID == "" || a.IdentityAdapter == "oidc") && token.IDToken != "" && a.Metadata.JWKSURI != "" {
		identity, err = oauthidentity.Verify(ctx, m.client, token.IDToken, oauthidentity.OIDCConfig{
			Issuer: a.Issuer, ClientID: a.Client.ID, JWKSURI: a.Metadata.JWKSURI, Nonce: nonce, AccessToken: token.AccessToken, Now: m.now(),
		})
	} else {
		return
	}
	if err != nil {
		// Do not log provider response bodies or token claims.
		m.logger.Warn("OAuth identity lookup or verification failed; sign-in continues", "app", a.Client.AppID, "issuer", a.Issuer)
		return
	}
	a.Subject = identity.Subject
	if identity.Label != "" {
		a.Identity = &identity.Label
	}
}

func (m *Manager) mergeIdentity(ctx context.Context, vault string, a *Account, explicit bool) error {
	if explicit {
		old, err := m.repo.Account(ctx, vault, a.Key)
		if err != nil {
			return err
		}
		retainAccountState(a, old)
		return nil
	}
	if a.AppID == "" || a.Subject == "" {
		return nil
	}
	accounts, err := m.repo.Accounts(ctx, vault)
	if err != nil {
		return err
	}
	for _, old := range accounts {
		if old.AppID != a.AppID || old.Issuer != a.Issuer || old.Subject != a.Subject || old.Client.Source != a.Client.Source ||
			old.Client.ID != a.Client.ID || old.Metadata.TokenEndpoint != a.Metadata.TokenEndpoint {
			continue
		}
		a.Key = old.Key
		retainAccountState(a, &old)
		return nil
	}

	return nil
}

func retainAccountState(a, old *Account) {
	if a.RefreshToken == "" && a.Client.AppID == old.Client.AppID && a.Client.Source == old.Client.Source &&
		sameAppBinding(old.Client, a.Client) && old.Metadata.TokenEndpoint == a.Metadata.TokenEndpoint {
		a.RefreshToken = old.RefreshToken
	}
	a.LastUsedAt, a.ConnectedAt = old.LastUsedAt, old.ConnectedAt
}
