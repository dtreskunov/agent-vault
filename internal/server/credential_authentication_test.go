package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestCredentialAllowsDestinationAuthentication(t *testing.T) {
	services := []broker.Service{
		{Name: "api", Host: "api.example.com", Auth: broker.Auth{Type: "bearer", Token: "KEY"}},
		{Name: "uploads", Host: "uploads.example.com", Auth: broker.Auth{Type: "bearer", Token: "OTHER"}},
	}
	if err := normalizeConnectionServices(services, []string{"KEY", "OTHER"}); err != nil {
		t.Fatal("per-destination value references rejected", err)
	}
	services[0].Auth = broker.Auth{Type: "api-key", Key: "KEY"}
	services[1].Auth = broker.Auth{Type: "api-key", Key: "KEY", Location: "header", Header: "authorization"}
	if err := normalizeConnectionServices(services, []string{"KEY"}); err != nil {
		t.Fatal("equivalent shared authentication rejected", err)
	}
	services[1].Auth = broker.Auth{Type: "api-key", Key: "OTHER", Location: "query", Parameter: "api_key"}
	if err := normalizeConnectionServices(services, []string{"KEY", "OTHER"}); err != nil {
		t.Fatal("per-destination placement rejected", err)
	}
	if err := normalizeConnectionServices(services, []string{"KEY"}); err == nil {
		t.Fatal("unknown credential reference accepted")
	}
	services[1].Auth.Parameter = ""
	if err := normalizeConnectionServices(services, []string{"KEY", "OTHER"}); err == nil {
		t.Fatal("invalid destination authentication accepted")
	}
	services[1].Auth = broker.Auth{Type: "passthrough"}
	services[1].Substitutions = []broker.Substitution{{Key: "OTHER", Placeholder: "__OTHER__", In: []string{"query"}}}
	if err := normalizeConnectionServices(services, []string{"KEY", "OTHER"}); err != nil {
		t.Fatal("per-destination substitution rejected", err)
	}
}

func TestConnectionAPIPreservesIndependentDestinationAuthentication(t *testing.T) {
	f := newManagedFixture(t)
	c := f.create(`{"label":"Mixed API","kind":"static","values":{"API_KEY":"synthetic-api","UPLOAD_KEY":"synthetic-upload"},"services":[{"name":"api","host":"api.example.com/v1/*","auth":{"type":"bearer","token":"API_KEY"}},{"name":"uploads","host":"uploads.example.com/*","auth":{"type":"api-key","key":"UPLOAD_KEY","location":"query","parameter":"upload_key"}}]}`)
	if len(c.Services) != 2 || c.Services[0].Auth.Type != "bearer" || c.Services[1].Auth.Location != "query" {
		t.Fatal("destination authentication was rewritten")
	}
	path := f.base() + "/connections/" + c.ID + "/grants/group-one"
	if w := f.call("PUT", path, `{}`, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	ctx := context.Background()
	vault, err := f.db.GetVault(ctx, "group-one")
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.s.CredentialProvider().Inject(ctx, vault.ID, "api.example.com", 443, "/v1/items")
	if err != nil || result.Headers["Authorization"] != "Bearer synthetic-api" || len(result.Query) != 0 {
		t.Fatal("API destination used the wrong authentication", err)
	}
	result, err = f.s.CredentialProvider().Inject(ctx, vault.ID, "uploads.example.com", 443, "/file")
	if err != nil || result.Query["upload_key"] != "synthetic-upload" || len(result.Headers) != 0 {
		t.Fatal("upload destination used the wrong authentication", err)
	}
}

func TestSharedQueryCredentialResolutionAndRevocation(t *testing.T) {
	f := newManagedFixture(t)
	c := f.create(`{"label":"Query API","kind":"static","values":{"KEY":"synthetic-query-secret"},"services":[{"name":"api","host":"api.example.com/v1/*","auth":{"type":"api-key","key":"KEY","location":"query","parameter":"api_key"}}]}`)
	path := f.base() + "/connections/" + c.ID + "/grants/group-one"
	if w := f.call("PUT", path, `{}`, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	ctx := context.Background()
	vault, err := f.db.GetVault(ctx, "group-one")
	if err != nil {
		t.Fatal(err)
	}
	services, _, err := f.s.sharedDiscovery(ctx, vault.ID)
	if err != nil || len(services) != 1 {
		t.Fatal("query discovery failed", err)
	}
	raw, err := json.Marshal(services)
	if err != nil || strings.Contains(string(raw), "synthetic-query-secret") {
		t.Fatal("discovery exposed a query credential")
	}
	selected := brokercore.WithRequestBinding(ctx, []string{services[0].BindingHandle})
	result, err := f.s.CredentialProvider().Inject(selected, vault.ID, "api.example.com", 443, "/v1/items")
	if err != nil || result.Query["api_key"] != "synthetic-query-secret" || len(result.Headers) != 0 || !result.HTTPSOnly {
		t.Fatal("query binding resolution failed", err)
	}
	if w := f.call("DELETE", path, "", ""); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body)
	}
	if _, err := f.s.CredentialProvider().Inject(selected, vault.ID, "api.example.com", 443, "/v1/items"); !errors.Is(err, brokercore.ErrServiceDisabled) {
		t.Fatal("revoked query binding remained usable", err)
	}
}
