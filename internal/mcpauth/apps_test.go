package mcpauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

type providerTransport struct {
	t         *testing.T
	exchanges int
	refreshes int
}

func (p *providerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	headers := http.Header{"Content-Type": {"application/json"}}
	status := 200
	body := ""
	switch r.URL.String() {
	case "https://oauth2.googleapis.com/token", "https://github.com/login/oauth/access_token":
		r.ParseForm()
		if r.Form.Get("client_secret") == "" {
			p.t.Error("app secret not sent")
		}
		if r.Form.Get("grant_type") == "refresh_token" {
			p.refreshes++
		} else {
			if r.Form.Get("code_verifier") == "" || r.Form.Get("redirect_uri") == "" {
				p.t.Error("provider code binding missing")
			}
			p.exchanges++
		}
		body = fmt.Sprintf(`{"access_token":"synthetic-%d","refresh_token":"synthetic-refresh","token_type":"Bearer","expires_in":3600}`, p.exchanges)
	case "https://oauth2.googleapis.com/revoke":
		body = `{}`
	default:
		return (githubMetadataTransport{}).RoundTrip(r)
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func TestAppIsolationAndProviderServices(t *testing.T) {
	ctx := context.Background()
	m, db, one := testManager(t)
	transport := &providerTransport{t: t}
	m.client.Transport = transport
	two, err := db.CreateVault(ctx, "second-app-vault")
	if err != nil {
		t.Fatal(err)
	}
	secret := "synthetic-secret"
	if _, err := m.PutApp(ctx, "", "github", AppInput{ClientID: "install", ClientSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	signIn := func(vault string) string {
		start, err := m.Start(ctx, vault, "https://api.githubcopilot.com/mcp/")
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(start.AuthorizeURL)
		result, err := m.Complete(ctx, oauthrelay.Input{State: start.State, Code: "code", Issuer: "https://github.com/login/oauth"}, nil)
		if err != nil || result.Status != "connected" {
			t.Fatalf("app MCP sign-in failed: %v", err)
		}
		if u.Query().Get("client_id") == "" {
			t.Fatal("missing app client")
		}
		return result.Key
	}
	k1 := signIn(one)
	k2 := signIn(two.ID)
	info, err := m.GetApp(ctx, "", "github")
	if err != nil || info.Accounts != 2 || *info.AccountsAllVaults != 2 {
		t.Fatal("install usage count incorrect")
	}
	if _, err := m.PutApp(ctx, two.ID, "github", AppInput{ClientID: "override", ClientSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	signIn(two.ID)
	info, _ = m.GetApp(ctx, "", "github")
	if info.Accounts != 1 {
		t.Fatal("override did not replace app source")
	}
	if err := m.DeleteApp(ctx, two.ID, "github"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Credential(ctx, one, k1); err != nil {
		t.Fatal("override deletion broke install account")
	}
	if _, err := m.repo.Account(ctx, two.ID, k2); err == nil {
		t.Fatal("deleted override account survived")
	}
	if _, err := m.PutApp(ctx, "", "github", AppInput{ClientID: "new-install", ClientSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	if list, _ := m.List(ctx, one); len(list) != 0 {
		t.Fatal("client-id change retained accounts")
	}

	if _, err := m.PutApp(ctx, "", "google", AppInput{ClientID: "google", ClientSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	start, err := m.StartProvider(ctx, one, "google", []string{"gmail-read", "calendar"}, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start.AuthorizeURL)
	if u.Query().Get("access_type") != "offline" || !strings.Contains(u.Query().Get("scope"), "gmail.readonly") {
		t.Fatal("Google offline scopes missing")
	}
	result, err := m.Complete(ctx, oauthrelay.Input{State: start.State, Code: "code"}, nil)
	if err != nil || result.Status != "connected" {
		t.Fatal(err)
	}
	account, err := m.repo.Account(ctx, one, result.Key)
	if err != nil || account.Provider != "google" {
		t.Fatal("provider account not persisted")
	}
	cfg, _ := db.GetBrokerConfig(ctx, one)
	var services []broker.Service
	if err := json.Unmarshal([]byte(cfg.ServicesJSON), &services); err != nil {
		t.Fatal(err)
	}
	var gmail bool
	for _, service := range services {
		if service.Host == "gmail.googleapis.com" && service.Auth.Token == result.Key {
			gmail = true
		}
	}
	if !gmail {
		t.Fatal("scope set did not generate Gmail injection service")
	}
	if _, err := m.PutApp(ctx, "", "google", AppInput{ClientID: "google"}); err != nil {
		t.Fatal("secret omitted on unchanged client rejected")
	}
	if err := m.Disconnect(ctx, one, result.Key); err != nil {
		t.Fatal(err)
	}
}

func TestAppChangesInvalidatePendingSignIns(t *testing.T) {
	ctx := context.Background()
	m, _, vault := testManager(t)
	m.client.Transport = &providerTransport{t: t}
	secret := "synthetic"
	if _, err := m.PutApp(ctx, "", "google", AppInput{ClientID: "one", ClientSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	start, err := m.StartProvider(ctx, vault, "google", []string{"gmail-read"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.DeleteApp(ctx, "", "google"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Complete(ctx, oauthrelay.Input{State: start.State, Code: "unused"}, nil); err == nil {
		t.Fatal("removed app pending state completed")
	}
	if _, err := m.PutApp(ctx, vault, "google", AppInput{ClientID: "missing-secret"}); err == nil {
		t.Fatal("first setup accepted without secret")
	}
}
