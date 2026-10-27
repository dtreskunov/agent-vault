package mcpauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

type identityTransport struct {
	base    http.RoundTripper
	fail    bool
	subject string
}

func (x *identityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.String() == "https://openidconnect.googleapis.com/v1/userinfo" {
		status := 200
		if x.fail {
			status = 503
		}
		body, _ := json.Marshal(map[string]any{"sub": x.subject, "email": "verified@example.com", "email_verified": true})
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(string(body)))}, nil
	}
	return x.base.RoundTrip(r)
}

func TestVerifiedProviderIdentityMerge(t *testing.T) {
	m, _, vault := testManager(t)
	transport := &identityTransport{base: &providerTransport{t: t}, subject: "google-subject"}
	m.client.Transport = transport
	secret := "synthetic-secret"
	if _, err := m.PutApp(context.Background(), "", "google", testAppInput("google", "client", &secret)); err != nil {
		t.Fatal(err)
	}
	connect := func(scopes []string, replace string) *oauthrelay.Result {
		scopes = append(scopes, "openid", "email")
		start, err := m.StartAccount(context.Background(), vault, "google", scopes, replace)
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(start.AuthorizeURL)
		if !strings.Contains(u.Query().Get("scope"), "openid email") || u.Query().Get("include_granted_scopes") != "true" {
			t.Fatal("identity scopes/incremental grants missing")
		}
		result, err := m.Complete(context.Background(), oauthrelay.Input{State: start.State, Code: "synthetic-code"}, nil)
		if err != nil || result.Status != "connected" {
			t.Fatal(err)
		}
		return result
	}
	first := connect([]string{gmailReadScope}, "")
	second := connect([]string{calendarScope}, "")
	if first.Key != second.Key || second.Account == nil || *second.Account != "verified@example.com" {
		t.Fatal("same verified subject was not merged")
	}
	list, err := m.List(context.Background(), vault)
	if err != nil || len(list) != 1 || list[0].Account == nil || slices.Contains(list[0].Scopes, gmailReadScope) || !slices.Contains(list[0].Scopes, calendarScope) {
		t.Fatal("identity or authoritative scope metadata not persisted")
	}
	encoded, _ := json.Marshal(list)
	if strings.Contains(string(encoded), "google-subject") {
		t.Fatal("private subject returned")
	}
	transport.subject = "different-subject"
	explicit := connect([]string{driveScope}, first.Key)
	if explicit.Key != first.Key {
		t.Fatal("explicit replacement did not preserve key")
	}
	transport.fail = true
	if _, err := m.PutApp(context.Background(), "", "google", AppInput{APIHosts: &[]string{"other.example.com"}}); err != nil {
		t.Fatal(err)
	}
	result := connect([]string{gmailReadScope}, "")
	if result.Account != nil {
		t.Fatal("failed userinfo fabricated identity")
	}
	list, _ = m.List(context.Background(), vault)
	if len(list) != 2 {
		t.Fatal("unverified subject merged into verified account")
	}
}

func TestMCPIdentityRequiresSignedTokenAndJWKS(t *testing.T) {
	m, _, _ := testManager(t)
	account := Account{Issuer: "https://issuer.example", Client: Client{ID: "client"}}
	token := &oauth.TokenResponse{IDToken: `eyJhbGciOiJub25lIn0.eyJlbWFpbCI6ImZvcmdlZEBleGFtcGxlLmNvbSJ9.`}
	m.resolveIdentity(context.Background(), &account, token, "nonce")
	if account.Identity != nil || account.Subject != "" {
		t.Fatal("MCP unsigned identity without keys accepted")
	}
	account.Metadata.JWKSURI = "https://issuer.example/keys"
	m.resolveIdentity(context.Background(), &account, token, "nonce")
	if account.Identity != nil || account.Subject != "" {
		t.Fatal("MCP unsigned identity with keys accepted")
	}
}
