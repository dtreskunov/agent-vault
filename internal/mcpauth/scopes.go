package mcpauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
)

type ScopeOptions struct {
	Scopes []string `json:"scopes"`
	Source string   `json:"source"`
	Issuer string   `json:"issuer,omitempty"`
	OAuth  bool     `json:"oauth"`
}

func CanonicalScopes(scopes []string) ([]string, error) {
	if err := validScopes(scopes); err != nil {
		return nil, err
	}
	result := slices.Clone(scopes)
	slices.Sort(result)
	return slices.Compact(result), nil
}

func authorizationMetadataURLs(issuer string) []string {
	u, _ := url.Parse(issuer)
	base := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.EscapedPath(), "/")
	return slices.Compact([]string{
		base + "/.well-known/oauth-authorization-server" + path,
		base + "/.well-known/openid-configuration" + path,
		strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration",
	})
}

// DiscoverScopes inspects public metadata without registering a client,
// creating consent state, refreshing tokens or changing connection policy.
func (m *Manager) DiscoverScopes(ctx context.Context, library, resource, appID, issuer string) (*ScopeOptions, error) {
	if issuer != "" && (resource != "" || appID != "") {
		return nil, failure("invalid_request", "Inspect an issuer separately from a resource or configured app")
	}
	result := &ScopeOptions{Scopes: []string{}, Source: "not_advertised", OAuth: true}
	var app *Client
	if appID != "" {
		if err := appIDValid(appID); err != nil {
			return nil, err
		}
		var err error
		app, err = m.effectiveApp(ctx, library, appID)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, failure("invalid_app", "OAuth app is not configured")
		}
		if err != nil {
			return nil, err
		}
	}
	var scopes []string
	if resource != "" {
		discovery, err := m.discover(ctx, resource)
		if err != nil {
			return nil, err
		}
		result.OAuth = discovery.OAuth
		if !discovery.OAuth {
			return result, nil
		}
		result.Issuer = discovery.Server.Issuer
		if app != nil && app.Issuer != result.Issuer {
			return nil, failure("invalid_app", "OAuth app issuer does not match the MCP resource")
		}
		if len(discovery.Resource.ScopesSupported) > 0 {
			scopes, result.Source = discovery.Resource.ScopesSupported, "resource"
		} else if len(discovery.Server.ScopesSupported) > 0 {
			scopes, result.Source = discovery.Server.ScopesSupported, "authorization_server"
		} else {
			scopes, err = m.issuerScopes(ctx, result.Issuer)
			if err != nil {
				return nil, err
			}
			if len(scopes) > 0 {
				result.Source = "authorization_server"
			}
		}
	} else if app != nil || issuer != "" {
		result.Issuer = issuer
		if app != nil {
			result.Issuer = app.Issuer
		}
		var err error
		scopes, err = m.issuerScopes(ctx, result.Issuer)
		if err != nil {
			return nil, err
		}
		if len(scopes) > 0 {
			result.Source = "authorization_server"
		}
	} else {
		return nil, failure("invalid_request", "Provide an MCP resource URL, OAuth app or issuer")
	}
	normalized, err := CanonicalScopes(scopes)
	if err != nil {
		return nil, failure("scope_discovery_failed", "Provider metadata contains invalid scope values")
	}
	if normalized != nil {
		result.Scopes = normalized
	}
	return result, nil
}

func (m *Manager) issuerScopes(ctx context.Context, issuer string) ([]string, error) {
	if err := validateURL(issuer); err != nil {
		return nil, err
	}
	for _, endpoint := range authorizationMetadataURLs(issuer) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/json")
		response, err := m.client.Do(request)
		if err != nil {
			return nil, failure("scope_discovery_failed", "OAuth scope metadata request failed")
		}
		if response.StatusCode == http.StatusNotFound || response.StatusCode == http.StatusGone {
			response.Body.Close()
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
		response.Body.Close()
		if err != nil || len(raw) > 1<<20 || response.StatusCode != http.StatusOK {
			return nil, failure("scope_discovery_failed", "OAuth scope metadata is unavailable")
		}
		var metadata struct {
			Issuer string   `json:"issuer"`
			Scopes []string `json:"scopes_supported"`
		}
		if json.Unmarshal(raw, &metadata) != nil || metadata.Issuer != issuer {
			return nil, failure("scope_discovery_failed", "OAuth scope metadata is invalid or has a different issuer")
		}
		if len(metadata.Scopes) > 0 {
			return metadata.Scopes, nil
		}
	}
	return nil, nil
}
