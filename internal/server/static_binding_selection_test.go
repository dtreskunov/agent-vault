package server

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestExplicitStaticBindingCannotFallThroughAfterRevocation(t *testing.T) {
	f := newManagedFixture(t)
	c := f.create(basicConnection)
	path := f.base() + "/connections/" + c.ID + "/grants/group-one"
	if w := f.call("PUT", path, `{}`, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	ctx := context.Background()
	vault, _ := f.db.GetVault(ctx, "group-one")
	services, _, err := f.s.sharedDiscovery(ctx, vault.ID)
	if err != nil || len(services) != 1 {
		t.Fatal(err)
	}
	selected := brokercore.WithRequestBinding(ctx, []string{services[0].BindingHandle})
	if result, err := f.s.CredentialProvider().Inject(selected, vault.ID, "api.example.com", 443, "/v1/items"); err != nil || result.Headers["Authorization"] == "" {
		t.Fatal(err)
	}
	if w := f.call("DELETE", path, "", ""); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body)
	}
	replacement := f.create(basicConnection)
	if w := f.call("PUT", f.base()+"/connections/"+replacement.ID+"/grants/group-one", `{}`, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	if _, err := f.s.CredentialProvider().Inject(selected, vault.ID, "api.example.com", 443, "/v1/items"); !errors.Is(err, brokercore.ErrServiceDisabled) {
		t.Fatal("revoked reference silently selected another static account", err)
	}
	for _, values := range [][]string{{""}, {"BIND_A", "BIND_B"}, {"BIND_A,BIND_B"}} {
		if _, err := f.s.CredentialProvider().Inject(brokercore.WithRequestBinding(ctx, values), vault.ID, "api.example.com", 443, "/v1/items"); !errors.Is(err, brokercore.ErrServiceDisabled) {
			t.Fatal("malformed selector accepted", err)
		}
	}
}
