package mcpauth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const RefreshPlaceholderPrefix = "av-refresh:"
const AccessPlaceholderPrefix = "av-access:"

func tokenProvider(host string, port int, path string) string {
	if port != 443 {
		return ""
	}
	for _, p := range Catalog() {
		u, err := url.Parse(p.TokenEndpoint)
		if err == nil && strings.EqualFold(host, u.Hostname()) && (path == "" || path == u.Path) {
			return p.ID
		}
	}
	return ""
}

// InterceptTokenHost ensures stubs are handled before they could leave the gateway.
func InterceptTokenHost(host string, port int) bool { return tokenProvider(host, port, "") != "" }

func (m *Manager) TokenResponse(ctx context.Context, vault string, r *http.Request) (*http.Response, error) {
	port := 443
	if r.URL.Port() != "" {
		var err error
		port, err = strconv.Atoi(r.URL.Port())
		if err != nil {
			return nil, err
		}
	}
	id := tokenProvider(r.URL.Hostname(), port, r.URL.Path)
	if id == "" || r.Method != "POST" {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	if len(data) > 64<<10 {
		return stubError(413, "invalid_request", "Token request exceeds 64 KiB"), nil
	}
	form, err := url.ParseQuery(string(data))
	if err != nil {
		return stubError(400, "invalid_request", "Malformed token request"), nil
	}
	refresh := form.Get("refresh_token")
	if !strings.HasPrefix(refresh, RefreshPlaceholderPrefix) {
		if strings.Contains(string(data), RefreshPlaceholderPrefix) {
			return stubError(400, "invalid_request", "Placeholder refresh must use the form-encoded refresh_token field"), nil
		}
		return nil, nil
	}
	if r.URL.Scheme != "https" || form.Get("grant_type") != "refresh_token" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return stubError(400, "invalid_request", "Placeholder refreshes require HTTPS and a form-encoded refresh_token grant"), nil
	}
	key := strings.TrimPrefix(refresh, RefreshPlaceholderPrefix)
	account, err := m.repo.Account(ctx, vault, key)
	if errors.Is(err, sql.ErrNoRows) {
		return stubError(400, "invalid_grant", "Placeholder account is not available in this vault"), nil
	}
	if err != nil {
		return nil, err
	}
	if account.Provider != id || account.Reconnect || account.AccessToken == "" {
		return stubError(400, "invalid_grant", "OAuth account requires sign-in"), nil
	}
	// Real refresh is deferred to API-token injection, never this synthetic endpoint.
	return stubJSON(200, map[string]any{"access_token": AccessPlaceholderPrefix + key, "refresh_token": RefreshPlaceholderPrefix + key,
		"token_type": "Bearer", "expires_in": 3600, "scope": account.Scopes}), nil
}

func stubError(status int, code, message string) *http.Response {
	return stubJSON(status, map[string]string{"error": code, "error_description": message})
}
func stubJSON(status int, value any) *http.Response {
	data, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("encoding static token response: %v", err))
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}, "Pragma": {"no-cache"}},
		Body: io.NopCloser(bytes.NewReader(data)), ContentLength: int64(len(data))}
}
