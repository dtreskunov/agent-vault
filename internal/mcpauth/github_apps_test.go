package mcpauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type githubRevocationTransport struct {
	t      *testing.T
	called bool
}

func (x *githubRevocationTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	user, secret, ok := r.BasicAuth()
	var input map[string]string
	err := json.NewDecoder(r.Body).Decode(&input)
	if r.Method != "DELETE" || r.URL.String() != "https://api.github.com/applications/client/token" || !ok || user != "client" || secret != "synthetic-secret" || err != nil || input["access_token"] != "synthetic-token" {
		x.t.Error("GitHub revocation not authenticated/bound correctly")
	}
	x.called = true
	return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader(""))}, nil
}
func TestGitHubAppRevocationAndCommaScopes(t *testing.T) {
	m, _, _ := testManager(t)
	transport := &githubRevocationTransport{t: t}
	m.client.Transport = transport
	a := Account{Provider: "github", ScopeSets: []string{"repo"}, Issuer: "https://github.com/login/oauth", AccessToken: "synthetic-token",
		Client: Client{Kind: "app", ID: "client", Secret: "synthetic-secret"}}
	if err := grantedScopeSets(&a, "repo,read:user"); err != nil {
		t.Fatal("GitHub comma-delimited grants rejected")
	}
	m.revoke(context.Background(), &a)
	if !transport.called {
		t.Fatal("GitHub token was not revoked")
	}
}
