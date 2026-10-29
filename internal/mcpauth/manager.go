package mcpauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

type Manager struct {
	core   Core
	repo   *Repository
	config oauthrelay.Config
	client *http.Client
	logger *slog.Logger
	now    func() time.Time
}

func New(core Core, repo *Repository, config oauthrelay.Config, logger *slog.Logger) *Manager {
	return &Manager{core: core, repo: repo, config: config, client: guardedClient(), logger: logger, now: time.Now}
}

type Started struct {
	State        string `json:"state"`
	AuthorizeURL string `json:"authorize_url"`
}

func (m *Manager) Start(ctx context.Context, vault, resource string) (*Started, error) {
	return m.StartNamed(ctx, vault, resource, "")
}

// StartNamed is Start with the client_name to register under, e.g. the agent
// group's display name. Empty keeps the existing registration's name.
func (m *Manager) StartNamed(ctx context.Context, vault, resource, clientName string, appID ...string) (*Started, error) {
	discovery, err := m.discover(ctx, resource)
	if err != nil {
		return nil, err
	}
	if !discovery.OAuth {
		return nil, failure("oauth_not_required", "MCP resource did not request OAuth authentication")
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
	account := Account{Key: accountKey(resource), ResourceURL: resource, Resource: discovery.Resource.Resource,
		Issuer: discovery.Server.Issuer, Metadata: discovery.Server, Scopes: strings.Join(discovery.Resource.ScopesSupported, " ")}
	if identity, ok := ctx.Value(managedFlowKey{}).(managedFlowIdentity); ok {
		account.Key = identity.Connection
	}
	if identity, ok := ctx.Value(managedFlowKey{}).(managedFlowIdentity); ok {
		account.ConnectionID = identity.Connection
		if identity.Scopes != nil {
			if err := validScopes(identity.Scopes); err != nil {
				return nil, err
			}
			account.Scopes = strings.Join(unique(identity.Scopes), " ")
		}
	} else if slices.Contains(discovery.Server.ScopesSupported, "openid") {
		account.Scopes = strings.TrimSpace(account.Scopes + " openid")
		if slices.Contains(discovery.Server.ScopesSupported, "email") {
			account.Scopes += " email"
		}
	}
	services, err := account.services()
	if err != nil {
		return nil, err
	}
	if err := broker.Validate(&broker.Config{Vault: vault, Services: services}); err != nil {
		return nil, failure("invalid_resource", "MCP resource must have a supported service hostname and path")
	}
	if existing, err := m.core.GetCredential(ctx, vault, account.Key); err == nil && existing.Type != "mcp_oauth" {
		return nil, failure("credential_conflict", "MCP credential key is already used by another credential")
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	client, err := m.chooseClient(ctx, vault, discovery, true, clientName, appID...)
	if err != nil {
		return nil, err
	}
	account.Client = *client
	account.RequestedScopes, account.ScopeSource = strings.Fields(account.Scopes), "requested"
	if _, err := m.repo.db.ExecContext(ctx, `DELETE FROM gateway_oauth_records WHERE kind='state' AND expires_at>0 AND expires_at<`+
		m.repo.dialect.Rebind("?"), m.now().Unix()); err != nil {
		return nil, err
	}
	return m.startFlow(ctx, vault, account)
}

func (m *Manager) Complete(ctx context.Context, input oauthrelay.Input, authorize func(string) error) (*oauthrelay.Result, error) {
	appUnlock, err := m.LockApps(ctx)
	if err != nil {
		return nil, err
	}
	defer appUnlock()
	flow, err := m.repo.Flow(ctx, input.State)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, failure("invalid_state", "Invalid or expired MCP OAuth state")
	}
	if err != nil {
		return nil, err
	}
	if flow.ManagedUserID != "" && authorize == nil {
		return nil, failure("managed_user_required", "Managed OAuth completion requires the initiating effective user")
	}
	if authorize != nil {
		if err := authorize(flow.VaultID); err != nil {
			return nil, err
		}
	}
	unlock, err := m.core.LockVault(ctx, flow.VaultID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := m.repo.consume(ctx, flow.VaultID, input.State); err != nil {
		return nil, err
	}
	if !flow.ExpiresAt.After(m.now()) {
		return nil, failure("invalid_state", "MCP OAuth state expired")
	}
	vault, err := m.core.GetVaultByID(ctx, flow.VaultID)
	if err != nil {
		return nil, err
	}
	result := &oauthrelay.Result{Status: "failed", Vault: vault.Name, Key: flow.Account.Key}
	if flow.ConnectionID != "" {
		result.ConnectionID, result.Vault, result.Key = flow.ConnectionID, "", ""
	}
	if (flow.Account.Metadata.AuthorizationResponseIssParameterSupported && input.Issuer == "") ||
		(input.Issuer != "" && input.Issuer != flow.Account.Issuer) {
		result.Code, result.Error = "issuer_mismatch", "OAuth callback issuer is missing or does not match the sign-in"
		return result, nil
	}
	if input.Error != "" {
		result.Code, result.Error = "declined", "OAuth authorization was declined"
		return result, nil
	}
	if input.Code == "" {
		return nil, failure("invalid_state", "An OAuth authorization code is required")
	}
	a := &flow.Account
	if err := m.validateFlowClient(ctx, flow.VaultID, a); err != nil {
		return nil, err
	}
	token, err := oauth.Exchange(ctx, oauth.ExchangeConfig{
		Client: m.client, TokenURL: a.Metadata.TokenEndpoint, ClientID: a.Client.ID, ClientSecret: a.Client.Secret,
		TokenAuthMethod: a.Client.AuthMethod, Code: input.Code, CodeVerifier: flow.Verifier,
		RedirectURI: flow.RedirectURI, Resource: a.Resource,
	})
	if err != nil {
		if invalidClient(err) && a.Client.Kind == "registered" {
			if err := m.reregister(ctx, flow.VaultID, a); err != nil {
				return nil, err
			}
			result.Code, result.Error = "needs_reconnect", "OAuth client was re-registered; start a new sign-in"
		} else {
			result.Code, result.Error = "token_exchange_failed", "MCP OAuth token exchange failed; start a new sign-in"
		}
		return result, nil
	}
	if token.AccessToken == "" || (token.TokenType != "" && !strings.EqualFold(token.TokenType, "bearer")) {
		return nil, failure("invalid_token_response", "MCP OAuth token endpoint returned an unusable token")
	}
	a.AccessToken, a.RefreshToken, a.ExpiresAt = token.AccessToken, token.RefreshToken, token.ExpiresAt
	if err := recordScopes(a, token.Scope); err != nil {
		m.revoke(ctx, a)
		return nil, err
	}
	m.resolveIdentity(ctx, a, token, flow.Nonce)
	if flow.ConnectionID == "" {
		if err := m.mergeIdentity(ctx, flow.VaultID, a, flow.ExplicitReplace); err != nil {
			return nil, err
		}
	} else {
		old, err := m.repo.Account(ctx, flow.VaultID, a.Key)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if old != nil {
			refresh := a.RefreshToken
			retainAccountState(a, old)
			if refresh == "" && (a.Subject == "" || a.Subject != old.Subject) {
				a.RefreshToken = ""
			}
		}
	}
	now := m.now().UTC()
	if a.ConnectedAt == nil {
		a.ConnectedAt = &now
	}
	a.UpdatedAt, a.Reconnect = now, false
	if authorize != nil {
		if err := authorize(flow.VaultID); err != nil {
			m.revoke(ctx, a)
			return nil, err
		}
	}
	if err := m.repo.saveAccount(ctx, flow.VaultID, a, true); err != nil {
		m.revoke(ctx, a)
		return nil, err
	}
	result.Status = "connected"
	result.Key, result.Account = a.Key, a.Identity
	if flow.ConnectionID != "" {
		result.Key = ""
	}
	return result, nil
}

func invalidClient(err error) bool {
	var endpoint *oauth.TokenError
	if !errors.As(err, &endpoint) {
		return false
	}
	var response struct {
		Error string `json:"error"`
	}
	return json.Unmarshal([]byte(endpoint.Body), &response) == nil && response.Error == "invalid_client"
}

func (m *Manager) reregister(ctx context.Context, vault string, account *Account) error {
	if account.ConnectionID != "" {
		if _, err := m.repo.db.ExecContext(ctx, m.repo.dialect.Rebind(`DELETE FROM gateway_oauth_records WHERE vault_id=? AND kind='client' AND record_key=?`), vault, digest(account.Issuer+"\x00"+account.ConnectionID)); err != nil {
			return err
		}
		account.Reconnect, account.AccessToken, account.RefreshToken, account.UpdatedAt = true, "", "", m.now().UTC()
		return m.repo.saveAccount(ctx, vault, account, false)
	}
	var current Client
	err := m.repo.get(ctx, vault, "client", digest(account.Issuer), &current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if current.ID == account.Client.ID || errors.Is(err, sql.ErrNoRows) {
		if _, err := m.registeredClient(ctx, vault, &Discovery{Server: account.Metadata}, true, ""); err != nil {
			return err
		}
	}
	accounts, err := m.repo.Accounts(ctx, vault)
	if err != nil {
		return err
	}
	for i := range accounts {
		a := &accounts[i]
		if a.Issuer == account.Issuer && a.Client.Kind == "registered" && a.Client.ID == account.Client.ID {
			a.Reconnect, a.AccessToken, a.RefreshToken, a.UpdatedAt = true, "", "", m.now().UTC()
			if err := m.repo.saveAccount(ctx, vault, a, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) List(ctx context.Context, vault string) ([]AccountInfo, error) {
	accounts, err := m.repo.Accounts(ctx, vault)
	if err != nil {
		return nil, err
	}
	items := make([]AccountInfo, 0, len(accounts))
	for _, account := range accounts {
		items = append(items, account.Info())
	}
	return items, nil
}

func (m *Manager) Probe(ctx context.Context, vault, resource string, appID ...string) (*ProbeInfo, error) {
	discovery, err := m.discover(ctx, resource)
	if err != nil {
		return nil, err
	}
	info := &ProbeInfo{OAuth: discovery.OAuth}
	if !discovery.OAuth {
		return info, nil
	}
	info.Issuer = discovery.Server.Issuer
	client, err := m.chooseClient(ctx, vault, discovery, false, "", appID...)
	if err != nil {
		var unsupported *Failure
		if errors.As(err, &unsupported) && unsupported.Code == "registration_unsupported" {
			info.Code = unsupported.Code
			return info, nil
		}
		return nil, err
	}
	info.Client = client.Kind
	info.AppID = client.AppID
	return info, nil
}
