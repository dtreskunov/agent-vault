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
	if a.AppID != "" || a.Provider != "" {
		return "oauth_app"
	}
	return "mcp_oauth"
}

func servicePrefix(a Account) string {
	if a.AppID != "" || a.Provider != "" {
		return "oauth-" + strings.ToLower(strings.TrimPrefix(a.Key, "OAUTH_")) + "-"
	}
	return "mcp-" + strings.ToLower(strings.TrimPrefix(a.Key, "MCP_"))
}

func (m *Manager) StartAccount(ctx context.Context, vault, appID string, scopes []string, replace string) (*Started, error) {
	if err := appIDValid(appID); err != nil {
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
	client, err := m.effectiveApp(ctx, vault, appID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, failure("invalid_app", "OAuth app is not configured")
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
		if old.AppID != appID || old.Issuer != client.Issuer {
			return nil, failure("invalid_account", "Replacement account belongs to another OAuth app or issuer")
		}
		key = replace
	}
	if client.Config.AuthorizationEndpoint == "" || client.Config.TokenEndpoint == "" || len(client.Config.APIHosts) == 0 {
		return nil, failure("invalid_app", "Direct API sign-in requires OAuth endpoints and api_hosts")
	}
	if scopes == nil {
		scopes = client.Config.DefaultScopes
	}
	if err := validScopes(scopes); err != nil {
		return nil, err
	}
	a := Account{Key: key, AppID: appID, APIHosts: slices.Clone(client.Config.APIHosts), IdentityAdapter: client.Config.Identity,
		Issuer: client.Issuer, Metadata: client.metadata(), Client: *client, Scopes: strings.Join(unique(scopes), " "),
		RequestedScopes: unique(scopes), ScopeSource: "requested"}
	if len(scopes) == 0 {
		a.ScopeSource = "unknown"
	}
	services, err := a.services()
	if err != nil {
		return nil, err
	}
	if err := broker.Validate(&broker.Config{Vault: vault, Services: services}); err != nil {
		return nil, err
	}
	return m.startFlow(ctx, vault, a, replace != "")
}

func (m *Manager) startFlow(ctx context.Context, vault string, account Account, explicit ...bool) (*Started, error) {
	verifier, err := oauth.GenerateCodeVerifier()
	if err != nil {
		return nil, err
	}
	state := "mcp_oast_" + rand.Text()
	flow := Flow{VaultID: vault, Account: account, Verifier: verifier, Nonce: rand.Text(), RedirectURI: m.config.RedirectURI, ExpiresAt: m.now().Add(10 * time.Minute)}
	if len(explicit) != 0 {
		flow.ExplicitReplace = explicit[0]
	}
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
	q.Set("nonce", flow.Nonce)
	if account.Resource != "" {
		q.Set("resource", account.Resource)
	}
	for key, value := range account.Client.Config.AuthorizationParams {
		q.Set(key, value)
	}
	u.RawQuery = q.Encode()
	return &Started{State: state, AuthorizeURL: u.String()}, nil
}

func (m *Manager) validateFlowClient(ctx context.Context, vault string, a *Account) error {
	if a.Client.Kind != "app" {
		return nil
	}
	id := a.Client.AppID
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
	if current.ID != a.Client.ID || current.Issuer != a.Client.Issuer || current.AuthMethod != a.Client.AuthMethod ||
		current.Config.AuthorizationEndpoint != a.Client.Config.AuthorizationEndpoint || current.Config.TokenEndpoint != a.Client.Config.TokenEndpoint {
		return failure("needs_reconnect", "OAuth app changed; start a new sign-in")
	}
	a.Client.Secret = current.Secret
	return nil
}

func recordScopes(a *Account, scope string) error {
	if scope == "" {
		return nil
	}
	if a.Client.Config.TokenScopeSeparator == "comma" {
		scope = strings.ReplaceAll(scope, ",", " ")
	}
	granted := strings.Fields(scope)
	if err := validScopes(granted); err != nil {
		return err
	}
	a.GrantedScopes = unique(granted)
	a.Scopes, a.ScopeSource = strings.Join(a.GrantedScopes, " "), "provider"
	return nil
}
