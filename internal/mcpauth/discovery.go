package mcpauth

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
	"github.com/Infisical/agent-vault/internal/netguard"
)

type Discovery struct {
	URL      string
	Resource oauthex.ProtectedResourceMetadata
	Server   oauthex.AuthServerMeta
	OAuth    bool
}

type ProbeInfo struct {
	OAuth  bool   `json:"oauth"`
	Issuer string `json:"issuer,omitempty"`
	Client string `json:"client,omitempty"`
	Code   string `json:"code,omitempty"`
	AppID  string `json:"app_id,omitempty"`
}

func guardedClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = netguard.SafeDialContext(false)
	return &http.Client{
		Timeout: 20 * time.Second, Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || via[0].Method != http.MethodGet {
				return http.ErrUseLastResponse
			}
			if via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return fmt.Errorf("OAuth discovery HTTPS downgrade refused")
			}
			return validateURL(req.URL.String())
		},
	}
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil || u.Fragment != "" ||
		(u.Scheme != "https" && u.Scheme != "http") {
		return failure("invalid_resource", "An absolute HTTP(S) URL without userinfo or fragment is required")
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "localhost.localdomain"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if u.Scheme != "https" && !loopback {
		return failure("invalid_resource", "OAuth URLs require HTTPS except on loopback")
	}
	if strings.Contains(u.Path, "*") {
		return failure("invalid_resource", "MCP URLs cannot contain service-glob wildcards")
	}
	return nil
}

func (m *Manager) discover(ctx context.Context, raw string) (*Discovery, error) {
	if err := validateURL(raw); err != nil {
		return nil, err
	}
	resource, _ := url.Parse(raw)
	request, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	response, err := m.client.Do(request)
	if err != nil {
		return nil, failure("discovery_failed", "MCP resource probe failed")
	}
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	response.Body.Close()
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		return &Discovery{URL: raw}, nil
	}
	var metadataURLs []string
	challenges, err := oauthex.ParseWWWAuthenticate(response.Header.Values("WWW-Authenticate"))
	if err != nil {
		return nil, failure("discovery_failed", "Malformed MCP authentication challenge")
	}
	for _, challenge := range challenges {
		if challenge.Scheme == "bearer" && challenge.Params["resource_metadata"] != "" {
			metadataURLs = append(metadataURLs, challenge.Params["resource_metadata"])
		}
	}
	origin := resource.Scheme + "://" + resource.Host
	path := resource.EscapedPath()
	metadataURLs = append(metadataURLs, origin+"/.well-known/oauth-protected-resource"+path)
	if strings.HasSuffix(path, "/") {
		metadataURLs = append(metadataURLs, origin+"/.well-known/oauth-protected-resource"+strings.TrimSuffix(path, "/"))
	}
	if path != "" {
		metadataURLs = append(metadataURLs, origin+"/.well-known/oauth-protected-resource")
	}
	var protected *oauthex.ProtectedResourceMetadata
	for _, metadataURL := range slices.Compact(metadataURLs) {
		if err := validateURL(metadataURL); err != nil {
			return nil, err
		}
		// Origin-wide fallback metadata describes the origin rather than its MCP path.
		expected := raw
		if metadataURL == origin+"/.well-known/oauth-protected-resource" && path != "" {
			expected = origin
		}
		var lookupErr error
		protected, lookupErr = oauthex.GetProtectedResourceMetadata(ctx, metadataURL, expected, m.client)
		if lookupErr != nil && strings.HasSuffix(expected, "/") {
			protected, lookupErr = oauthex.GetProtectedResourceMetadata(ctx, metadataURL, strings.TrimSuffix(expected, "/"), m.client)
		}
		if lookupErr == nil {
			break
		}
		protected = nil
	}
	if protected == nil || len(protected.AuthorizationServers) == 0 {
		return nil, failure("discovery_failed", "MCP protected-resource metadata is unavailable or invalid")
	}
	issuer := protected.AuthorizationServers[0]
	if err := validateURL(issuer); err != nil {
		return nil, err
	}
	u, _ := url.Parse(issuer)
	base := u.Scheme + "://" + u.Host
	issuerPath := strings.TrimSuffix(u.EscapedPath(), "/")
	candidates := []string{
		base + "/.well-known/oauth-authorization-server" + issuerPath,
		base + "/.well-known/openid-configuration" + issuerPath,
		strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration",
	}
	var metadata *oauthex.AuthServerMeta
	for _, endpoint := range slices.Compact(candidates) {
		metadata, err = oauthex.GetAuthServerMeta(ctx, endpoint, issuer, m.client)
		if err != nil {
			return nil, failure("discovery_failed", "Authorization-server metadata validation failed")
		}
		if metadata != nil {
			break
		}
	}
	if metadata == nil || !slices.Contains(metadata.CodeChallengeMethodsSupported, "S256") ||
		metadata.AuthorizationEndpoint == "" || metadata.TokenEndpoint == "" {
		return nil, failure("discovery_failed", "Authorization server must support authorization code and S256 PKCE")
	}
	for _, endpoint := range []string{metadata.AuthorizationEndpoint, metadata.TokenEndpoint, metadata.RegistrationEndpoint,
		metadata.RevocationEndpoint} {
		if endpoint != "" {
			if err := validateURL(endpoint); err != nil {
				return nil, err
			}
		}
	}
	return &Discovery{URL: raw, Resource: *protected, Server: *metadata, OAuth: true}, nil
}

func (a Account) services() ([]broker.Service, error) {
	if accountType(a) == "oauth_app" {
		return a.apiServices()
	}
	u, err := url.Parse(a.ResourceURL)
	if err != nil {
		return nil, err
	}
	host, _, port := broker.SplitInlineHost(u.Host, "")
	path := u.Path
	if path == "" {
		path = "/"
	}
	name := servicePrefix(a)
	auth := broker.Auth{Type: "bearer", Token: a.Key}
	exact := broker.Service{Name: name, Host: host, Port: port, Path: path, Auth: auth, HTTPSOnly: a.ConnectionID != ""}
	services := []broker.Service{exact}
	if strings.HasSuffix(path, "/") {
		services[0].Path = path + "*"
	} else {
		services = append(services, broker.Service{Name: name + "-children", Host: host, Port: port, Path: path + "/*", Auth: auth, HTTPSOnly: a.ConnectionID != ""})
	}
	return services, nil
}
