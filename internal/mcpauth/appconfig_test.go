package mcpauth

import (
	"context"
	"errors"
	"slices"
	"testing"
)

const gmailReadScope = "https://www.googleapis.com/auth/gmail.readonly"
const calendarScope = "https://www.googleapis.com/auth/calendar"
const driveScope = "https://www.googleapis.com/auth/drive.readonly"

func testAppInput(id, clientID string, secret *string) AppInput {
	issuer, authorize, token := "https://github.com/login/oauth", "https://github.com/login/oauth/authorize", "https://github.com/login/oauth/access_token"
	hosts, scopes, identity, separator := []string{"api.github.com"}, []string{"repo"}, "github", "comma"
	params := map[string]string{}
	revoke := ""
	if id == "google" {
		issuer, authorize, token = "https://accounts.google.com", "https://accounts.google.com/o/oauth2/v2/auth", "https://oauth2.googleapis.com/token"
		hosts, scopes, identity, separator = []string{"gmail.googleapis.com", "www.googleapis.com"}, []string{gmailReadScope, "openid", "email"}, "google", "space"
		params = map[string]string{"access_type": "offline", "include_granted_scopes": "true", "prompt": "consent"}
		revoke = "https://oauth2.googleapis.com/revoke"
	}
	return AppInput{Issuer: &issuer, ClientID: clientID, ClientSecret: secret, AuthorizationEndpoint: &authorize, TokenEndpoint: &token,
		APIHosts: &hosts, DefaultScopes: &scopes, AuthorizationParams: &params, Identity: &identity, TokenScopeSeparator: &separator, RevocationEndpoint: &revoke}
}

func TestGenericAppValidation(t *testing.T) {
	secret := "synthetic-secret"
	base := AppInput{ClientID: "client", ClientSecret: &secret, Issuer: new("https://issuer.example"),
		AuthorizationEndpoint: new("https://issuer.example/authorize"), TokenEndpoint: new("https://issuer.example/token"),
		APIHosts: &[]string{"api.example.com"}}
	for _, name := range []string{"state", "STATE", "client_id", "client_secret", "redirect_uri", "scope", "nonce", "code_challenge", "resource", "request_uri"} {
		input := base
		input.AuthorizationParams = &map[string]string{name: "bad"}
		if _, err := configureApp("custom-app", nil, input); err == nil {
			t.Errorf("accepted reserved authorization parameter %s", name)
		}
	}
	for _, host := range []string{"*.example.com", "api.example.com/repos/*", "https://api.example.com", "user@api.example.com", "api.example.com:0", "api.example.com?key=x"} {
		input := base
		input.APIHosts = &[]string{host}
		if _, err := configureApp("custom-app", nil, input); err == nil {
			t.Errorf("accepted invalid API host %s", host)
		}
	}
	next, err := configureApp("custom-app", nil, base)
	if err != nil {
		t.Fatal(err)
	}
	changed := AppInput{TokenEndpoint: new("https://different.example/token")}
	if _, err := configureApp("custom-app", &next, changed); err == nil {
		t.Fatal("reused old secret against a changed endpoint")
	}
	if _, err := configureApp("custom-app", &next, AppInput{}); err != nil {
		t.Fatal("unchanged binding lost its secret", err)
	}
	public := base
	public.AuthMethod, public.ClientSecret = new("none"), new("")
	if _, err := configureApp("custom-app", nil, public); err != nil {
		t.Fatal("public OAuth client rejected", err)
	}
}

func TestConfiguredAppsOverrideAndAmbiguity(t *testing.T) {
	m, db, vault := testManager(t)
	ctx := context.Background()
	secret := "synthetic-secret"
	for _, id := range []string{"first-app", "second-app"} {
		if _, err := m.PutApp(ctx, "", id, testAppInput("github", id, &secret)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.app(ctx, vault, "https://github.com/login/oauth"); err == nil {
		t.Fatal("ambiguous issuer silently selected an app")
	} else {
		var failure *Failure
		if !errors.As(err, &failure) || failure.Code != "ambiguous_app" {
			t.Fatal(err)
		}
	}
	if _, err := m.PutApp(ctx, vault, "first-app", testAppInput("github", "override", &secret)); err != nil {
		t.Fatal(err)
	}
	items, err := m.ListApps(ctx, vault)
	if err != nil || len(items) != 2 || items[0].Source != "vault" || !items[0].OverridesInstall || items[0].AccountsAllVaults != nil {
		t.Fatalf("effective app collection invalid: %+v, %v", items, err)
	}
	other, err := db.CreateVault(ctx, "other-apps")
	if err != nil {
		t.Fatal(err)
	}
	items, err = m.ListApps(ctx, other.ID)
	if err != nil || items[0].Source != "install" {
		t.Fatal("override leaked across vaults")
	}
	discovery := &Discovery{Server: Client{Issuer: "https://github.com/login/oauth"}.metadata()}
	client, err := m.chooseClient(ctx, vault, discovery, false, "", "second-app")
	if err != nil || client.AppID != "second-app" {
		t.Fatal("explicit MCP app selection failed", err)
	}
}

func TestScopeReportingDoesNotInventGrants(t *testing.T) {
	a := Account{RequestedScopes: []string{"requested"}, Scopes: "requested", ScopeSource: "requested", Client: Client{Config: AppConfig{TokenScopeSeparator: "comma"}}}
	if err := recordScopes(&a, "repo,read:user"); err != nil {
		t.Fatal(err)
	}
	if a.Scopes != "repo read:user" || !slices.Equal(a.GrantedScopes, []string{"repo", "read:user"}) || a.ScopeSource != "provider" {
		t.Fatal("provider scope response not authoritative")
	}
	if err := recordScopes(&a, ""); err != nil || a.Scopes != "repo read:user" {
		t.Fatal("omitted refresh scope lost existing metadata")
	}
	if err := recordScopes(&a, "read:user"); err != nil || a.Scopes != "read:user" {
		t.Fatal("narrowed scopes were blindly unioned")
	}
}
