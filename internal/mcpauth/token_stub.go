package mcpauth

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const RefreshPlaceholderPrefix = "av-refresh:"
const AccessPlaceholderPrefix = "av-access:"

func tokenAuthority(host string, port int) string {
	return net.JoinHostPort(strings.ToLower(host), strconv.Itoa(port))
}

func endpointAuthority(raw string) (string, error) {
	if err := validateURL(raw); err != nil {
		return "", err
	}
	u, _ := url.Parse(raw)
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if u.Port() != "" {
		var err error
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return "", failure("invalid_app", "Invalid token endpoint port")
		}
	}
	return tokenAuthority(u.Hostname(), port), nil
}

func (r *Repository) rememberTokenAuthority(ctx context.Context, exec executor, endpoint string) error {
	if endpoint == "" {
		return nil
	}
	authority, err := endpointAuthority(endpoint)
	if err != nil {
		return err
	}
	_, err = exec.ExecContext(ctx, r.dialect.Rebind(
		`INSERT INTO gateway_oauth_token_authorities (authority) VALUES (?) ON CONFLICT(authority) DO NOTHING`), authority)
	return err
}

// Interception is instance-wide and survives account and app deletion.
func (m *Manager) InterceptTokenHost(ctx context.Context, host string, port int) (bool, error) {
	var authority string
	err := m.repo.db.QueryRowContext(ctx, m.repo.dialect.Rebind(
		`SELECT authority FROM gateway_oauth_token_authorities WHERE authority=?`), tokenAuthority(host, port)).Scan(&authority)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func sameTokenEndpoint(a, b *url.URL) bool {
	aa, err := endpointAuthority(a.String())
	if err != nil {
		return false
	}
	bb, err := endpointAuthority(b.String())
	return err == nil && a.Scheme == b.Scheme && aa == bb && a.EscapedPath() == b.EscapedPath() && a.RawQuery == b.RawQuery
}

func (m *Manager) TokenResponse(ctx context.Context, vault string, r *http.Request) (*http.Response, error) {
	return m.tokenResponse(ctx, r, func(key string) (*Account, error) { return m.repo.Account(ctx, vault, key) }, false)
}

func (m *Manager) BindingTokenResponse(ctx context.Context, r *http.Request, resolve func(string) (*Account, error)) (*http.Response, error) {
	return m.tokenResponse(ctx, r, resolve, true)
}

func (m *Manager) tokenResponse(ctx context.Context, r *http.Request, resolve func(string) (*Account, error), strict bool) (*http.Response, error) {
	port := 443
	if r.URL.Port() != "" {
		var err error
		port, err = strconv.Atoi(r.URL.Port())
		if err != nil {
			return nil, err
		}
	}
	intercept, err := m.InterceptTokenHost(ctx, r.URL.Hostname(), port)
	if err != nil {
		return nil, err
	}
	if !intercept && (!strict || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")) {
		return nil, nil
	}
	if r.Body == nil {
		return nil, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(data), r.Body), r.Body}
	formEncoded := strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded")
	if len(data) > 64<<10 && formEncoded && (intercept || bytes.Contains(data, []byte(RefreshPlaceholderPrefix))) {
		return stubError(413, "invalid_request", "Token request exceeds 64 KiB"), nil
	}
	if !formEncoded && !bytes.Contains(data, []byte(RefreshPlaceholderPrefix)) {
		return nil, nil
	}
	form, err := url.ParseQuery(string(data))
	if err != nil {
		if bytes.Contains(data, []byte(RefreshPlaceholderPrefix)) {
			return stubError(400, "invalid_request", "Malformed token request"), nil
		}
		return nil, nil
	}
	refresh := form.Get("refresh_token")
	if !strings.HasPrefix(refresh, RefreshPlaceholderPrefix) {
		if strings.Contains(string(data), RefreshPlaceholderPrefix) {
			return stubError(400, "invalid_request", "Placeholder refresh must use the form-encoded refresh_token field"), nil
		}
		return nil, nil
	}
	if r.URL.Scheme != "https" || r.Method != "POST" || form.Get("grant_type") != "refresh_token" || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		return stubError(400, "invalid_request", "Placeholder refreshes require HTTPS and a form-encoded refresh_token grant"), nil
	}
	key := strings.TrimPrefix(refresh, RefreshPlaceholderPrefix)
	account, err := resolve(key)
	if errors.Is(err, sql.ErrNoRows) {
		return stubError(400, "invalid_grant", "Placeholder account is not available in this vault"), nil
	}
	if err != nil {
		return stubError(400, "invalid_grant", "Unknown, revoked or suspended group binding"), nil
	}
	endpoint, err := url.Parse(account.Metadata.TokenEndpoint)
	if err != nil {
		return nil, err
	}
	if !sameTokenEndpoint(endpoint, r.URL) || account.Reconnect || account.AccessToken == "" {
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
