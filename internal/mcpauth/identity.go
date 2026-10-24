package mcpauth

import (
	"context"
	"slices"
	"strings"

	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/oauthidentity"
)

func (m *Manager) resolveIdentity(ctx context.Context, a *Account, token *oauth.TokenResponse, nonce string) {
	var identity oauthidentity.Identity
	var err error
	if a.Provider == "google" || a.Provider == "github" {
		identity, err = oauthidentity.Provider(ctx, m.client, a.Provider, token.AccessToken)
	} else if token.IDToken != "" && a.Metadata.JWKSURI != "" {
		identity, err = oauthidentity.Verify(ctx, m.client, token.IDToken, oauthidentity.OIDCConfig{
			Issuer: a.Issuer, ClientID: a.Client.ID, JWKSURI: a.Metadata.JWKSURI, Nonce: nonce, AccessToken: token.AccessToken, Now: m.now(),
		})
	} else {
		return
	}
	if err != nil {
		// Do not log provider response bodies or token claims.
		m.logger.Warn("OAuth identity lookup or verification failed; sign-in continues", "provider", a.Provider, "issuer", a.Issuer)
		return
	}
	a.Subject = identity.Subject
	if identity.Label != "" {
		a.Identity = &identity.Label
	}
}

func (m *Manager) mergeIdentity(ctx context.Context, vault string, a *Account, explicit bool) error {
	if explicit || a.Provider == "" || a.Subject == "" {
		return nil
	}
	accounts, err := m.repo.Accounts(ctx, vault)
	if err != nil {
		return err
	}
	for _, old := range accounts {
		if old.Provider != a.Provider || old.Subject != a.Subject {
			continue
		}
		a.Key = old.Key
		for _, set := range old.ScopeSets {
			if !slices.Contains(a.ScopeSets, set) {
				a.ScopeSets = append(a.ScopeSets, set)
			}
		}
		scopes := strings.Fields(a.Scopes)
		for _, scope := range strings.Fields(old.Scopes) {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
		a.Scopes = strings.Join(scopes, " ")
		if a.RefreshToken == "" && old.Client.ID == a.Client.ID && old.Client.Source == a.Client.Source {
			a.RefreshToken = old.RefreshToken
		}
		a.LastUsedAt = old.LastUsedAt
		return nil
	}
	return nil
}
