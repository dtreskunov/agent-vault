package mcpauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/oauth"
)

func accountType(a Account) string {
	if a.Provider != "" {
		return "oauth_app"
	}
	return "mcp_oauth"
}

func servicePrefix(a Account) string {
	if a.Provider != "" {
		return "oauth-" + strings.ToLower(strings.TrimPrefix(a.Key, "OAUTH_")) + "-"
	}
	return "mcp-" + strings.ToLower(strings.TrimPrefix(a.Key, "MCP_"))
}

func (m *Manager) StartProvider(ctx context.Context, vault, provider string, sets []string, replace string) (*Started, error) {
	p, err := catalogProvider(provider)
	if err != nil {
		return nil, err
	}
	scopes, _, err := scopeSelection(p, sets)
	if err != nil {
		return nil, err
	}
	appUnlock, err := m.LockApps(ctx)
	if err != nil {
		return nil, err
	}
	defer appUnlock()
	unlock, err := m.core.LockVault(ctx, vault)
	if err != nil {
		return nil, err
	}
	defer unlock()
	client, err := m.app(ctx, vault, p.Issuer)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, unsupported(p.Issuer)
	}
	if err != nil {
		return nil, err
	}
	key := "OAUTH_" + strings.ToUpper(rand.Text()[:16])
	if replace != "" {
		old, err := m.repo.Account(ctx, vault, replace)
		if err != nil {
			return nil, err
		}
		if old.Provider != provider {
			return nil, failure("invalid_account", "Replacement account belongs to another provider")
		}
		key = replace
	}
	a := Account{Key: key, Provider: provider, ScopeSets: slices.Clone(sets), Issuer: p.Issuer, Metadata: p.metadata(), Client: *client, Scopes: strings.Join(scopes, " ")}
	services, err := a.services()
	if err != nil {
		return nil, err
	}
	if err := broker.Validate(&broker.Config{Vault: vault, Services: services}); err != nil {
		return nil, err
	}
	return m.startFlow(ctx, vault, a)
}

func (m *Manager) startFlow(ctx context.Context, vault string, account Account) (*Started, error) {
	verifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}
	state := "mcp_oast_" + rand.Text()
	flow := Flow{VaultID: vault, Account: account, Verifier: verifier, RedirectURI: m.config.RedirectURI, ExpiresAt: m.now().Add(10 * time.Minute)}
	if err := m.repo.put(ctx, m.repo.db, vault, "state", digest(state), &flow, flow.ExpiresAt.Unix()); err != nil {
		return nil, err
	}
	authorization := oauth.BuildAuthorizationURL(account.Metadata.AuthorizationEndpoint, account.Client.ID, flow.RedirectURI, state,
		oauth.CodeChallengeS256(verifier), account.Scopes, " ", false)
	u, err := url.Parse(authorization)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	if account.Resource != "" {
		q.Set("resource", account.Resource)
	}
	if account.Provider == "google" {
		q.Set("access_type", "offline")
		q.Set("prompt", "consent")
	}
	u.RawQuery = q.Encode()
	return &Started{State: state, AuthorizeURL: u.String()}, nil
}

func (m *Manager) validateFlowClient(ctx context.Context, vault string, a *Account) error {
	if a.Client.Kind != "app" {
		return nil
	}
	id := provider(a.Issuer)
	source := vault
	if a.Client.Source == "install" {
		source = ""
	}
	current, err := m.storedApp(ctx, source, id)
	if errors.Is(err, sql.ErrNoRows) {
		return failure("needs_reconnect", "OAuth app was removed; start a new sign-in")
	}
	if err != nil {
		return err
	}
	if current.ID != a.Client.ID {
		return failure("needs_reconnect", "OAuth app changed; start a new sign-in")
	}
	a.Client.Secret = current.Secret
	return nil
}

func grantedScopeSets(a *Account, scope string) error {
	if a.Provider == "" || scope == "" {
		return nil
	}
	p, err := catalogProvider(a.Provider)
	if err != nil {
		return err
	}
	granted := strings.Fields(scope)
	kept := make([]string, 0, len(a.ScopeSets))
	for _, set := range p.ScopeSets {
		if !slices.Contains(a.ScopeSets, set.ID) {
			continue
		}
		all := true
		for _, s := range set.Scopes {
			if !slices.Contains(granted, s) {
				all = false
			}
		}
		if all {
			kept = append(kept, set.ID)
		}
	}
	if len(kept) == 0 {
		return failure("insufficient_scope", "No requested scope set was granted")
	}
	a.ScopeSets = kept
	a.Scopes = scope
	return nil
}
