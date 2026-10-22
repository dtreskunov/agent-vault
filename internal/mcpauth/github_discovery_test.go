package mcpauth

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type githubMetadataTransport struct{}

func (githubMetadataTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body := ""
	status := 200
	headers := http.Header{"Content-Type": {"application/json"}}
	switch request.URL.String() {
	case "https://api.githubcopilot.com/mcp/":
		status = 401
		headers.Set("WWW-Authenticate", `Bearer error="invalid_request", error_description="No access token", resource_metadata="https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/"`)
	case "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp/":
		status = 404
	case "https://api.githubcopilot.com/.well-known/oauth-protected-resource/mcp":
		body = `{"resource":"https://api.githubcopilot.com/mcp","authorization_servers":["https://github.com/login/oauth"]}`
	case "https://github.com/.well-known/oauth-authorization-server/login/oauth":
		body = `{"issuer":"https://github.com/login/oauth","authorization_endpoint":"https://github.com/login/oauth/authorize","token_endpoint":"https://github.com/login/oauth/access_token","code_challenge_methods_supported":["S256"]}`
	default:
		status = 404
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
}

func TestGitHubTrailingSlashProbe(t *testing.T) {
	m, _, vault := testManager(t)
	m.client.Transport = githubMetadataTransport{}
	probe, err := m.Probe(context.Background(), vault, "https://api.githubcopilot.com/mcp/")
	if err != nil || !probe.OAuth || probe.Code != "registration_unsupported" || probe.Provider != "github" {
		t.Fatalf("GitHub metadata not accepted: %v", err)
	}
	if err := m.StoreApp(context.Background(), "", Client{Issuer: "https://github.com/login/oauth", ID: "test-github", Secret: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	probe, err = m.Probe(context.Background(), vault, "https://api.githubcopilot.com/mcp/")
	if err != nil || probe.Client != "app" {
		t.Fatal("configured GitHub app not selected")
	}
}
