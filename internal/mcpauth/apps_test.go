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
	t           *testing.T
	exchanges   int
	refreshes   int
	omitRefresh bool
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
		if p.omitRefresh {
			body = fmt.Sprintf(`{"access_token":"synthetic-%d","token_type":"Bearer","expires_in":3600}`, p.exchanges)
		}
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
	if _, err := m.PutApp(ctx, "", "github", testAppInput("github", "install", &secret)); err != nil {
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
	if _, err := m.PutApp(ctx, two.ID, "github", testAppInput("github", "override", &secret)); err != nil {
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
	if _, err := m.PutApp(ctx, "", "github", testAppInput("github", "new-install", &secret)); err != nil {
		t.Fatal(err)
	}
	if list, _ := m.List(ctx, one); len(list) != 0 {
		t.Fatal("client-id change retained accounts")
	}

	if _, err := m.PutApp(ctx, "", "google", testAppInput("google", "google", &secret)); err != nil {
		t.Fatal(err)
	}
	start, err := m.StartAccount(ctx, one, "google", []string{gmailReadScope, calendarScope}, "")
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
	if err != nil || account.AppID != "google" {
		t.Fatal("provider account not persisted")
	}
	cfg, _ := db.GetBrokerConfig(ctx, one)
	var services []broker.Service
	if err := json.Unmarshal([]byte(cfg.ServicesJSON), &services); err != nil {
		t.Fatal(err)
	}
	var gmail bool
	for _, service := range services {
		service.Host, service.Path, service.Port = broker.SplitInlineHost(service.Host, service.Path)
		if service.Host == "gmail.googleapis.com" && service.Auth.Token == result.Key {
			gmail = true
		}
	}
	if !gmail {
		t.Fatal("configured API host did not generate Gmail injection service")
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
	if _, err := m.PutApp(ctx, "", "google", testAppInput("google", "one", &secret)); err != nil {
		t.Fatal(err)
	}

	start, err := m.StartAccount(ctx, vault, "google", []string{gmailReadScope}, "")
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

func TestAppBindingChangesAreSourceAndAppIsolated(t *testing.T) {
	m, db, vault := testManager(t)
	ctx := context.Background()
	transport := &providerTransport{t: t}
	m.client.Transport = transport
	other, err := db.CreateVault(ctx, "source-isolation")
	if err != nil {
		t.Fatal(err)
	}
	secret := "synthetic-secret"
	for _, spec := range []struct{ vault, id, host string }{
		{"", "first-app", "first.example.com"}, {"", "second-app", "second.example.com"}, {other.ID, "first-app", "first.example.com"},
	} {
		input := testAppInput("github", "shared-client-id", &secret)
		input.APIHosts, input.Identity = &[]string{spec.host}, new("none")
		if _, err := m.PutApp(ctx, spec.vault, spec.id, input); err != nil {
			t.Fatal(err)
		}
	}
	signIn := func(vault, id, replace string) string {
		t.Helper()
		start, err := m.StartAccount(ctx, vault, id, nil, replace)
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.Complete(ctx, oauthrelay.Input{State: start.State, Code: "code"}, nil)
		if err != nil || result.Status != "connected" {
			t.Fatal(err)
		}
		return result.Key
	}
	first := signIn(vault, "first-app", "")
	second := signIn(vault, "second-app", "")
	override := signIn(other.ID, "first-app", "")
	transport.omitRefresh = true
	if got := signIn(vault, "first-app", first); got != first {
		t.Fatal("explicit reconnect did not preserve account key")
	}
	a, err := m.repo.Account(ctx, vault, first)
	if err != nil || a.RefreshToken != "synthetic-refresh" {
		t.Fatal("legitimate reconnect lost its previous refresh token")
	}
	rotated := "synthetic-rotated-secret"
	if _, err := m.PutApp(ctx, "", "first-app", AppInput{ClientSecret: &rotated}); err != nil {
		t.Fatal(err)
	}
	a, _ = m.repo.Account(ctx, vault, first)
	otherApp, _ := m.repo.Account(ctx, vault, second)
	otherSource, _ := m.repo.Account(ctx, other.ID, override)
	if a.Client.Secret != rotated || otherApp.Client.Secret != secret || otherSource.Client.Secret != secret {
		t.Fatal("secret rotation crossed an app or source boundary")
	}
	before := databaseSnapshot(t, m.repo.db)
	if _, err := m.PutApp(ctx, "", "first-app", AppInput{TokenEndpoint: new("https://changed.example/token")}); err == nil {
		t.Fatal("changed endpoint silently reused an existing secret")
	}
	if before != databaseSnapshot(t, m.repo.db) {
		t.Fatal("rejected endpoint mutation changed state")
	}
	if _, err := m.PutApp(ctx, "", "first-app", AppInput{TokenEndpoint: new("https://changed.example/token"), ClientSecret: &rotated}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.repo.Account(ctx, vault, first); err == nil {
		t.Fatal("binding change retained an account issued under the old binding")
	}
	if _, err := m.repo.Account(ctx, vault, second); err != nil {
		t.Fatal("binding change invalidated a different app")
	}
	if _, err := m.repo.Account(ctx, other.ID, override); err != nil {
		t.Fatal("binding change invalidated a vault override")
	}
}
