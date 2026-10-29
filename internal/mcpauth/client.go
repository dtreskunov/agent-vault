package mcpauth

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"slices"
	"time"

	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
)

// registeredClient returns the vault's dynamic registration for the issuer,
// registering one when there is none, it can't be reused, or it was registered
// under a different name than `name` (empty keeps the stored name).
func (m *Manager) registeredClient(ctx context.Context, vault string, discovery *Discovery, force bool, name string) (*Client, error) {
	var stored Client
	err := m.repo.get(ctx, vault, "client", clientRecordKey(ctx, discovery.Server.Issuer), &stored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	hasStored := err == nil
	if !force && hasStored && stored.RedirectURI == m.config.RedirectURI &&
		(stored.SecretExpiresAt.IsZero() || stored.SecretExpiresAt.After(m.now())) &&
		(name == "" || stored.Name == name) {
		return &stored, nil
	}
	if name == "" && hasStored {
		name = stored.Name
	}
	if name == "" {
		name = "NanoClaw " + vault
	}
	var client Client
	authMethod := "none"
	methods := discovery.Server.TokenEndpointAuthMethodsSupported
	if len(methods) != 0 && !slices.Contains(methods, "none") {
		switch {
		case slices.Contains(methods, "client_secret_basic"):
			authMethod = "client_secret_basic"
		case slices.Contains(methods, "client_secret_post"):
			authMethod = "client_secret_post"
		default:
			return nil, failure("registration_failed", "Authorization server requires an unsupported client authentication method")
		}
	}
	registration, err := oauthex.RegisterClient(ctx, discovery.Server.RegistrationEndpoint,
		&oauthex.ClientRegistrationMetadata{
			RedirectURIs: []string{m.config.RedirectURI}, ClientName: name,
			TokenEndpointAuthMethod: authMethod, GrantTypes: []string{"authorization_code", "refresh_token"},
			ResponseTypes: []string{"code"},
		}, m.client)
	if err != nil {
		// Do not expose registration response bodies, which may contain credentials.
		return nil, failure("registration_failed", "MCP dynamic client registration failed")
	}
	method := registration.TokenEndpointAuthMethod
	if method == "" {
		method = authMethod
	}
	if method != "none" && method != "client_secret_post" && method != "client_secret_basic" {
		return nil, failure("registration_failed", "MCP authorization server selected an unsupported client authentication method")
	}
	if method != "none" && registration.ClientSecret == "" {
		return nil, failure("registration_failed", "Confidential client registration did not issue a client secret")
	}
	if registration.RegistrationClientURI != "" {
		if err := validateURL(registration.RegistrationClientURI); err != nil {
			return nil, err
		}
	}
	client = Client{
		Issuer: discovery.Server.Issuer, ID: registration.ClientID, Secret: registration.ClientSecret,
		AuthMethod: method, Kind: "registered", RedirectURI: m.config.RedirectURI,
		ManagementURI: registration.RegistrationClientURI, ManagementToken: registration.RegistrationAccessToken,
		SecretExpiresAt: registration.ClientSecretExpiresAt, Name: name,
	}
	if identity, ok := ctx.Value(managedFlowKey{}).(managedFlowIdentity); ok {
		client.ConnectionID = identity.Connection
	}
	if err := m.repo.put(ctx, m.repo.db, vault, "client", clientRecordKey(ctx, client.Issuer), &client, 0); err != nil {
		return nil, err
	}
	if hasStored && !force && stored.ID != client.ID {
		if _, managed := ctx.Value(managedFlowKey{}).(managedFlowIdentity); !managed {
			m.retireClient(ctx, vault, stored)
		}
	}
	return &client, nil
}

// retireClient deletes a replaced registration (RFC 7592, best effort) unless
// an account or a pending sign-in in the vault still uses its issuer's client.
func (m *Manager) retireClient(ctx context.Context, vault string, old Client) {
	accounts, err := m.repo.Accounts(ctx, vault)
	if err != nil {
		m.logger.Warn("MCP client retirement skipped", "err", err)
		return
	}
	for _, account := range accounts {
		if account.Client.ID == old.ID {
			return
		}
	}
	if pending, err := m.pendingIssuer(ctx, vault, "", old.Issuer); err != nil || pending {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	m.deleteClient(cleanupCtx, old)
}

func (m *Manager) app(ctx context.Context, vault, issuer string) (*Client, error) {
	clients, err := m.configuredApps(ctx, vault)
	if err != nil {
		return nil, err
	}
	var selected *Client
	for _, client := range clients {
		if client.Issuer == issuer {
			if selected != nil {
				return nil, failure("ambiguous_app", "Multiple configured apps match this issuer; specify app_id")
			}
			selected = &client
		}
	}
	if selected == nil {
		return nil, sql.ErrNoRows
	}
	return selected, nil
}

// StoreApp retains the initial setup helper for programmatic callers.
// An empty vault selects the instance app; this is not exposed to socket sessions.
func (m *Manager) StoreApp(ctx context.Context, vault string, client Client) error {
	id := client.AppID
	if id == "" {
		id = "app-" + digest(client.Issuer)[:16]
	}
	_, err := m.PutApp(ctx, vault, id, AppInput{ClientID: client.ID, ClientSecret: &client.Secret, Issuer: &client.Issuer})
	return err
}

func (m *Manager) chooseClient(ctx context.Context, vault string, discovery *Discovery, register bool, name string, appID ...string) (*Client, error) {
	if len(appID) != 0 && appID[0] != "" {
		if err := appIDValid(appID[0]); err != nil {
			return nil, err
		}
		client, err := m.effectiveApp(ctx, vault, appID[0])
		if err != nil {
			return nil, err
		}
		if client.Issuer != discovery.Server.Issuer {
			return nil, failure("invalid_app", "Configured app does not match the discovered issuer")
		}
		return client, nil
	}
	if discovery.Server.RegistrationEndpoint != "" {
		if !register {
			return &Client{Kind: "registered"}, nil
		}
		return m.registeredClient(ctx, vault, discovery, false, name)
	}
	if client, err := m.app(ctx, vault, discovery.Server.Issuer); err == nil {
		return client, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	metadata, _ := url.Parse(m.config.MetadataURI)
	if discovery.Server.ClientIDMetadataDocumentSupported && metadata.Scheme == "https" {
		return &Client{Issuer: discovery.Server.Issuer, ID: m.config.MetadataURI, AuthMethod: "none",
			Kind: "metadata", RedirectURI: m.config.RedirectURI}, nil
	}
	return nil, unsupported(discovery.Server.Issuer)
}
