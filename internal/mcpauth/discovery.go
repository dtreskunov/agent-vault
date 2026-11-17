package mcpauth

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
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
	response, err := m.initialize(ctx, raw)
	if err != nil {
		return nil, failure("discovery_failed", "MCP resource probe failed")
	}
	legacy := response.StatusCode == http.StatusMethodNotAllowed
	if legacy {
		response.Body.Close()
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "application/json, text/event-stream")
		response, err = m.client.Do(request)
		if err != nil {
			return nil, failure("discovery_failed", "MCP resource probe failed")
		}
	}
	defer response.Body.Close()
	public := false
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		challenge, err := m.validateMCPResponse(ctx, response, legacy)
		if err != nil {
			return nil, err
		}
		if challenge == nil {
			public = true
		} else {
			response.Body.Close()
			response = challenge
			defer response.Body.Close()
		}
	}
	if !public {
		io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	}
	response.Body.Close()
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
		if public {
			return &Discovery{URL: raw}, nil
		}
		return nil, failure("discovery_failed", "MCP protected-resource metadata is unavailable or invalid")
	}
	issuer := protected.AuthorizationServers[0]
	if err := validateURL(issuer); err != nil {
		return nil, err
	}
	var metadata *oauthex.AuthServerMeta
	for _, endpoint := range authorizationMetadataURLs(issuer) {
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

func (m *Manager) initialize(ctx context.Context, raw string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, raw, strings.NewReader(
		`{"jsonrpc":"2.0","id":"agent-vault-discovery","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"Agent Vault","version":"1"}}}`))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("Content-Type", "application/json")
	return m.client.Do(request)
}

func (m *Manager) closeProbeSession(ctx context.Context, response *http.Response, protocolVersion string) {
	sessionID := response.Header.Get("Mcp-Session-Id")
	if sessionID == "" {
		return
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(cleanup, http.MethodDelete, response.Request.URL.String(), nil)
	if err == nil {
		request.Header.Set("Mcp-Session-Id", sessionID)
		request.Header.Set("MCP-Protocol-Version", protocolVersion)
		var result *http.Response
		result, err = m.client.Do(request)
		if err == nil {
			result.Body.Close()
			if result.StatusCode < 200 || result.StatusCode >= 300 {
				m.logger.Warn("MCP discovery session cleanup rejected", "status", result.StatusCode)
			}
			return
		}
	}
	m.logger.Warn("MCP discovery session cleanup failed")
}

func invalidMCPResponse(status int, empty bool) error {
	detail := "did not return a valid MCP initialization response"
	if empty {
		detail = "returned an empty response, not an MCP authentication challenge or initialization response"
	}
	return failure("invalid_mcp_response", fmt.Sprintf(
		"The URL %s (HTTP %d). Check the full, active MCP endpoint, not a website address or an old webhook.", detail, status))
}

func initializationVersion(raw []byte) string {
	var response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      string          `json:"id"`
		Error   json.RawMessage `json:"error"`
		Result  struct {
			ProtocolVersion string         `json:"protocolVersion"`
			Capabilities    map[string]any `json:"capabilities"`
			ServerInfo      struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	valid := json.Unmarshal(raw, &response) == nil && response.JSONRPC == "2.0" &&
		response.ID == "agent-vault-discovery" && len(response.Error) == 0 &&
		response.Result.ProtocolVersion != "" && response.Result.Capabilities != nil &&
		response.Result.ServerInfo.Name != "" && response.Result.ServerInfo.Version != ""
	if !valid {
		return ""
	}
	return response.Result.ProtocolVersion
}

func (m *Manager) validateMCPResponse(ctx context.Context, response *http.Response, legacy bool) (*http.Response, error) {
	protocolVersion := "2025-03-26"
	defer func() { m.closeProbeSession(ctx, response, protocolVersion) }()
	const limit = 64 * 1024
	reader := bufio.NewReader(io.LimitReader(response.Body, limit+1))
	if _, err := reader.Peek(1); err != nil {
		if err == io.EOF {
			return nil, invalidMCPResponse(response.StatusCode, true)
		}
		return nil, failure("discovery_failed", "MCP initialization response could not be read")
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil {
		return nil, invalidMCPResponse(response.StatusCode, false)
	}
	if mediaType == "application/json" && !legacy {
		raw, err := io.ReadAll(reader)
		if err != nil {
			return nil, failure("discovery_failed", "MCP initialization response could not be read")
		}
		if version := initializationVersion(raw); len(raw) <= limit && version != "" {
			protocolVersion = version
			return nil, nil
		}
	} else if mediaType == "text/event-stream" {
		var event, data string
		var consumed int
		var legacyPosted bool
		for {
			line, err := reader.ReadString('\n')
			consumed += len(line)
			if consumed > limit {
				return nil, invalidMCPResponse(response.StatusCode, false)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, failure("discovery_failed", "MCP initialization stream could not be read")
			}
			line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
			if line == "" {
				if legacy && !legacyPosted && event == "endpoint" {
					endpoint, err := url.Parse(strings.TrimSuffix(data, "\n"))
					if err != nil || data == "" {
						return nil, invalidMCPResponse(response.StatusCode, false)
					}
					target := response.Request.URL.ResolveReference(endpoint).String()
					if err := validateURL(target); err != nil {
						return nil, err
					}
					initialized, err := m.initialize(ctx, target)
					if err != nil {
						return nil, failure("discovery_failed", "Legacy MCP initialization request failed")
					}
					if initialized.StatusCode < 200 || initialized.StatusCode >= 300 {
						return initialized, nil
					}
					if initialized.StatusCode != http.StatusAccepted {
						challenge, err := m.validateMCPResponse(ctx, initialized, false)
						initialized.Body.Close()
						return challenge, err
					}
					initialized.Body.Close()
					defer func() { m.closeProbeSession(ctx, initialized, protocolVersion) }()
					legacyPosted = true
				} else if (!legacy || legacyPosted) && (event == "" || event == "message") {
					if version := initializationVersion([]byte(data)); version != "" {
						protocolVersion = version
						return nil, nil
					}
				}
				event, data = "", ""
				continue
			}
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "event":
				event = value
			case "data":
				data += value + "\n"
			}
		}
	}
	return nil, invalidMCPResponse(response.StatusCode, false)
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
