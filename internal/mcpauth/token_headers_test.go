package mcpauth

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

func TestConfiguredTokenHeadersLifecycle(t *testing.T) {
	ctx := context.Background()
	m, _, vault := testManager(t)
	a := newAuthority(t, m)
	a.register, a.expires = false, 1
	a.tokenHeaders = map[string]string{"Authorization": "Bearer pk_test_initial"}
	params := map[string]string{"key": "pk_test_initial"}
	info, err := m.PutApp(ctx, "", "link", AppInput{
		ClientID: "link-client", ClientSecret: new("synthetic-secret"), Issuer: &a.server.URL,
		AuthorizationParams: &params, TokenHeaders: &a.tokenHeaders,
	})
	if err != nil {
		t.Fatal(err)
	}
	if info.TokenHeaders["Authorization"] != "Bearer pk_test_initial" {
		t.Fatal("public app metadata lost token headers")
	}
	data, err := json.Marshal(info)
	if err != nil || strings.Contains(string(data), "synthetic-secret") {
		t.Fatal("app metadata exposed the confidential client secret")
	}
	start, err := m.Start(ctx, vault, a.server.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(start.AuthorizeURL)
	if err != nil || u.Query().Get("key") != "pk_test_initial" {
		t.Fatal("additional authorization parameter was lost", err)
	}
	code, _ := a.code(t, start)

	// A pending flow must use current headers, just as it uses the current client secret.
	a.tokenHeaders = map[string]string{"Authorization": "Bearer pk_test_updated"}
	if _, err := m.PutApp(ctx, "", "link", AppInput{TokenHeaders: &a.tokenHeaders}); err != nil {
		t.Fatal(err)
	}
	result, err := m.Complete(ctx, oauthrelay.Input{State: start.State, Code: code, Issuer: a.server.URL}, nil)
	if err != nil || result.Status != "connected" {
		t.Fatalf("configured MCP app failed to connect: %+v, %v", result, err)
	}
	if _, err := m.Credential(ctx, vault, result.Key); err != nil {
		t.Fatal("configured headers missing during refresh", err)
	}

	a.tokenHeaders = map[string]string{"Authorization": "Bearer pk_test_rotated"}
	if _, err := m.PutApp(ctx, "", "link", AppInput{TokenHeaders: &a.tokenHeaders}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Credential(ctx, vault, result.Key); err != nil {
		t.Fatal("active account did not receive rotated token headers", err)
	}
	if err := m.Disconnect(ctx, vault, result.Key); err != nil {
		t.Fatal(err)
	}
	if a.exchanges != 1 || a.refreshes != 2 || a.revocations != 2 || a.registrations != 0 {
		t.Fatalf("unexpected lifecycle counts: exchange=%d refresh=%d revoke=%d register=%d", a.exchanges, a.refreshes, a.revocations, a.registrations)
	}
}
