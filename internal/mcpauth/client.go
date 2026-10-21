package mcpauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"slices"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
)

func (m *Manager) registeredClient(ctx context.Context, vault string, discovery *Discovery, force bool) (*Client, error) {
	var client Client
	if !force {
		err := m.repo.get(ctx, vault, "client", digest(discovery.Server.Issuer), &client)
		if err == nil && client.RedirectURI == m.config.RedirectURI &&
			(client.SecretExpiresAt.IsZero() || client.SecretExpiresAt.After(m.now())) {
			return &client, nil
		}
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
	}
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
			RedirectURIs: []string{m.config.RedirectURI}, ClientName: "NanoClaw " + vault,
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
		SecretExpiresAt: registration.ClientSecretExpiresAt,
	}
	if err := m.repo.put(ctx, m.repo.db, vault, "client", digest(client.Issuer), &client, 0); err != nil {
		return nil, err
	}
	return &client, nil
}

func (m *Manager) app(ctx context.Context, vault, issuer string) (*Client, error) {
	id := provider(issuer)
	if id == "" {
		return nil, sql.ErrNoRows
	}
	var client Client
	if err := m.repo.get(ctx, vault, "app", id, &client); err == nil {
		if client.Issuer != issuer {
			return nil, failure("invalid_app", "Configured OAuth app issuer does not match discovery")
		}
		client.Kind, client.Source = "app", "vault"
		return &client, nil
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	raw, err := m.core.GetSetting(ctx, "gateway.oauth_app."+id)
	if err != nil {
		return nil, err
	}
	var sealed struct{ Ciphertext, Nonce []byte }
	if err := json.Unmarshal([]byte(raw), &sealed); err != nil {
		return nil, err
	}
	if err := m.repo.decode(sealed.Ciphertext, sealed.Nonce, &client); err != nil {
		return nil, err
	}
	if client.Issuer != issuer {
		return nil, failure("invalid_app", "Install OAuth app issuer does not match discovery")
	}
	client.Kind, client.Source = "app", "install"
	return &client, nil
}

// StoreApp supplies the persistence primitive for the subsequent OAuth-app API.
// An empty vault selects the instance app; this is not exposed to socket sessions.
func (m *Manager) StoreApp(ctx context.Context, vault string, client Client) error {
	id := provider(client.Issuer)
	if id == "" || client.ID == "" || client.Secret == "" {
		return failure("invalid_app", "A catalog provider, client ID and secret are required")
	}
	client.AuthMethod = "client_secret_post"
	if vault != "" {
		return m.repo.put(ctx, m.repo.db, vault, "app", id, &client, 0)
	}
	payload, err := json.Marshal(client)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(payload)
	ct, nonce, err := crypto.Encrypt(payload, m.repo.key)
	if err != nil {
		return err
	}
	sealed, err := json.Marshal(struct{ Ciphertext, Nonce []byte }{ct, nonce})
	if err != nil {
		return err
	}
	return m.core.SetSetting(ctx, "gateway.oauth_app."+id, string(sealed))
}

func (m *Manager) chooseClient(ctx context.Context, vault string, discovery *Discovery, register bool) (*Client, error) {
	if discovery.Server.RegistrationEndpoint != "" {
		if !register {
			return &Client{Kind: "registered"}, nil
		}
		return m.registeredClient(ctx, vault, discovery, false)
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
