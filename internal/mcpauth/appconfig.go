package mcpauth

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/Infisical/agent-vault/internal/broker"
)

type AppConfig struct {
	Label                 string            `json:"label"`
	AuthorizationEndpoint string            `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         string            `json:"token_endpoint,omitempty"`
	AuthMethod            string            `json:"token_endpoint_auth_method"`
	APIHosts              []string          `json:"api_hosts"`
	DefaultScopes         []string          `json:"default_scopes"`
	AuthorizationParams   map[string]string `json:"authorization_params,omitempty"`
	RevocationEndpoint    string            `json:"revocation_endpoint,omitempty"`
	Identity              string            `json:"identity"`
	JWKSURI               string            `json:"jwks_uri,omitempty"`
	TokenScopeSeparator   string            `json:"token_scope_separator"`
}

type AppInput struct {
	ClientID              string             `json:"client_id"`
	ClientSecret          *string            `json:"client_secret,omitempty"`
	Issuer                *string            `json:"issuer,omitempty"`
	Label                 *string            `json:"label,omitempty"`
	AuthorizationEndpoint *string            `json:"authorization_endpoint,omitempty"`
	TokenEndpoint         *string            `json:"token_endpoint,omitempty"`
	AuthMethod            *string            `json:"token_endpoint_auth_method,omitempty"`
	APIHosts              *[]string          `json:"api_hosts,omitempty"`
	DefaultScopes         *[]string          `json:"default_scopes,omitempty"`
	AuthorizationParams   *map[string]string `json:"authorization_params,omitempty"`
	RevocationEndpoint    *string            `json:"revocation_endpoint,omitempty"`
	Identity              *string            `json:"identity,omitempty"`
	JWKSURI               *string            `json:"jwks_uri,omitempty"`
	TokenScopeSeparator   *string            `json:"token_scope_separator,omitempty"`
}

func appIDValid(id string) error {
	if err := broker.ValidateSlug(id); err != nil {
		return failure("invalid_app", "App ID must be a canonical service slug")
	}
	return nil
}

func configureApp(id string, old *Client, input AppInput) (Client, error) {
	next := Client{Kind: "app", AppID: id, Config: AppConfig{
		Label: id, AuthMethod: "client_secret_post", Identity: "none", TokenScopeSeparator: "space",
		APIHosts: []string{}, DefaultScopes: []string{},
	}}
	if old != nil {
		next = *old
	}
	if input.ClientID != "" {
		next.ID = input.ClientID
	}
	fields := []struct {
		input *string
		value *string
	}{
		{input.Issuer, &next.Issuer}, {input.Label, &next.Config.Label},
		{input.AuthorizationEndpoint, &next.Config.AuthorizationEndpoint}, {input.TokenEndpoint, &next.Config.TokenEndpoint},
		{input.AuthMethod, &next.Config.AuthMethod}, {input.RevocationEndpoint, &next.Config.RevocationEndpoint},
		{input.Identity, &next.Config.Identity}, {input.JWKSURI, &next.Config.JWKSURI},
		{input.TokenScopeSeparator, &next.Config.TokenScopeSeparator},
	}
	for _, field := range fields {
		if field.input != nil {
			*field.value = *field.input
		}
	}
	if input.APIHosts != nil {
		next.Config.APIHosts = slices.Clone(*input.APIHosts)
	}
	if input.DefaultScopes != nil {
		next.Config.DefaultScopes = slices.Clone(*input.DefaultScopes)
	}
	if input.AuthorizationParams != nil {
		next.Config.AuthorizationParams = *input.AuthorizationParams
	}
	next.AppID = id
	if old != nil && !sameAppBinding(*old, next) {
		next.Secret = ""
	}
	if input.ClientSecret != nil {
		next.Secret = *input.ClientSecret
	}
	if next.ID == "" || next.Issuer == "" {
		return Client{}, failure("invalid_app", "issuer and client_id are required")
	}
	if err := validateURL(next.Issuer); err != nil {
		return Client{}, err
	}
	for _, endpoint := range []string{next.Config.AuthorizationEndpoint, next.Config.TokenEndpoint, next.Config.RevocationEndpoint, next.Config.JWKSURI} {
		if endpoint != "" {
			if err := validateURL(endpoint); err != nil {
				return Client{}, err
			}
		}
	}
	if (next.Config.AuthorizationEndpoint == "") != (next.Config.TokenEndpoint == "") {
		return Client{}, failure("invalid_app", "authorization_endpoint and token_endpoint must be configured together")
	}
	switch next.Config.AuthMethod {
	case "none":
		if next.Secret != "" {
			return Client{}, failure("invalid_app", "Public OAuth clients must not have a client_secret")
		}
	case "client_secret_post", "client_secret_basic":
		if next.Secret == "" {
			return Client{}, failure("invalid_app", "client_secret is required for a new or changed confidential binding")
		}
	default:
		return Client{}, failure("invalid_app", "Unsupported token_endpoint_auth_method")
	}
	if !slices.Contains([]string{"none", "oidc", "google", "github"}, next.Config.Identity) {
		return Client{}, failure("invalid_app", "Unsupported identity verifier")
	}
	if next.Config.Identity == "oidc" && next.Config.JWKSURI == "" {
		return Client{}, failure("invalid_app", "OIDC identity verification requires jwks_uri")
	}
	if (next.Config.Identity == "google" && next.Issuer != "https://accounts.google.com") ||
		(next.Config.Identity == "github" && next.Issuer != "https://github.com/login/oauth") {
		return Client{}, failure("invalid_app", "Identity verifier does not match the issuer")
	}
	if !slices.Contains([]string{"space", "comma"}, next.Config.TokenScopeSeparator) {
		return Client{}, failure("invalid_app", "token_scope_separator must be space or comma")
	}
	for i, host := range next.Config.APIHosts {
		canonical, _, _, err := apiHost(host)
		if err != nil {
			return Client{}, err
		}
		next.Config.APIHosts[i] = canonical
	}
	next.Config.APIHosts = unique(next.Config.APIHosts)
	if err := validScopes(next.Config.DefaultScopes); err != nil {
		return Client{}, err
	}
	for name, value := range next.Config.AuthorizationParams {
		switch strings.ToLower(name) {
		case "", "state", "client_id", "client_secret", "redirect_uri", "response_type", "scope", "nonce",
			"code_challenge", "code_challenge_method", "resource", "request", "request_uri", "access_token", "refresh_token", "id_token":
			return Client{}, failure("invalid_app", "Authorization parameters cannot override OAuth bindings or contain credentials")
		}
		if strings.IndexFunc(name+value, unicode.IsControl) >= 0 {
			return Client{}, failure("invalid_app", "Authorization parameters cannot contain control characters")
		}
	}
	next.AuthMethod = next.Config.AuthMethod
	return next, nil
}

func sameAppBinding(a, b Client) bool {
	return a.ID == b.ID && a.Issuer == b.Issuer && a.Config.AuthorizationEndpoint == b.Config.AuthorizationEndpoint &&
		a.Config.TokenEndpoint == b.Config.TokenEndpoint && a.AuthMethod == b.Config.AuthMethod
}

func validScopes(scopes []string) error {
	for _, scope := range scopes {
		if scope == "" {
			return failure("invalid_scopes", "OAuth scopes must be nonempty individual scope strings")
		}
		for _, c := range scope {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return failure("invalid_scopes", "OAuth scopes must be individual RFC 6749 scope strings")
			}
		}
	}
	return nil
}

func unique(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !slices.Contains(result, value) {
			result = append(result, value)
		}
	}
	return result
}

func apiHost(raw string) (canonical, host string, port int, err error) {
	u, parseErr := url.Parse("https://" + raw)
	if parseErr != nil || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" ||
		u.Fragment != "" || strings.ContainsAny(raw, "/*?#@") {
		return "", "", 0, failure("invalid_app", "api_hosts requires exact hosts without paths, wildcards or userinfo")
	}
	host, port = strings.ToLower(u.Hostname()), 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", "", 0, failure("invalid_app", "Invalid API host port")
		}
	}
	service := broker.Service{Name: "oauth-validation", Host: host, Port: &port, Auth: broker.Auth{Type: "bearer", Token: "OAUTH_VALIDATION"}}
	if err := broker.Validate(&broker.Config{Vault: "validation", Services: []broker.Service{service}}); err != nil {
		return "", "", 0, failure("invalid_app", fmt.Sprintf("Invalid API host: %v", err))
	}
	canonical = host
	if port != 443 || strings.Contains(host, ":") {
		canonical = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return canonical, host, port, nil
}

func (a Account) apiServices() ([]broker.Service, error) {
	if len(a.APIHosts) == 0 {
		return nil, failure("invalid_app", "Direct API accounts require configured api_hosts")
	}
	services := make([]broker.Service, 0, len(a.APIHosts))
	for i, raw := range a.APIHosts {
		_, host, port, err := apiHost(raw)
		if err != nil {
			return nil, err
		}
		services = append(services, broker.Service{Name: servicePrefix(a) + strconv.Itoa(i), Host: host, Port: &port,
			HTTPSOnly: true, Auth: broker.Auth{Type: "bearer", Token: a.Key}})
	}
	return services, nil
}
