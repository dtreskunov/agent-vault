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

func TestCredentialRequiresSharedAuthentication(t *testing.T) {
	services := []broker.Service{
		{Name: "api", Host: "api.example.com", Auth: broker.Auth{Type: "bearer", Token: "KEY"}},
		{Name: "uploads", Host: "uploads.example.com", Auth: broker.Auth{Type: "bearer", Token: "OTHER"}},
	}
	if err := normalizeConnectionServices(services, []string{"KEY", "OTHER"}); err == nil {
		t.Fatal("per-destination credentials accepted")
	}
	services[0].Auth = broker.Auth{Type: "api-key", Key: "KEY"}
	services[1].Auth = broker.Auth{Type: "api-key", Key: "KEY", Location: "header", Header: "authorization"}
	if err := normalizeConnectionServices(services, []string{"KEY"}); err != nil {
		t.Fatal("equivalent shared authentication rejected", err)
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
