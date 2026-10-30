package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
)

func TestManagedGrantCoversExistingAndFutureConnectionRules(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	c := f.create(`{"label":"Whole credential","kind":"static","values":{"KEY":"synthetic-key"},"services":[{"name":"first","host":"first.example.com","auth":{"type":"bearer","token":"KEY"}},{"name":"second","host":"second.example.com","auth":{"type":"bearer","token":"KEY"}}]}`)
	route := f.base() + "/connections/" + c.ID
	if w := f.call("PUT", route+"/grants/group-one", `{"services":["first"]}`, ""); w.Code != 400 {
		t.Fatal("obsolete partial selection was accepted", w.Code, w.Body)
	}
	if w := f.call("PUT", route+"/grants/group-one", `{}`, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	// Simulate an existing partial grant from before whole-credential access.
	db, _ := f.db.GatewaySQL()
	legacy, err := json.Marshal(c.Services[:1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.ExecContext(ctx, `UPDATE connection_grants SET services_json='["first"]',bound_services_json=? WHERE connection_id=?`, string(legacy), c.ID); err != nil {
		t.Fatal(err)
	}
	c, err = f.s.loadConnection(ctx, c.ID)
	if err != nil || len(c.Grants) != 1 || strings.Join(c.Grants[0].Services, ",") != "first,second" {
		t.Fatal("existing partial grant was not expanded", err)
	}
	group, _ := f.db.GetVault(ctx, "group-one")
	other, _ := f.db.GetVault(ctx, "group-two")
	for _, host := range []string{"first.example.com", "second.example.com"} {
		if _, err := f.s.CredentialProvider().Inject(ctx, group.ID, host, 443, "/"); err != nil {
			t.Fatal("existing grant did not cover the whole credential", host, err)
		}
		if result, err := f.s.CredentialProvider().Inject(ctx, other.ID, host, 443, "/"); err == nil && result != nil &&
			(len(result.CredentialKeys) > 0 || result.Headers["Authorization"] != "") {
			t.Fatal("agent without a grant gained credential access", host)
		}
	}
	accepted, err := f.s.CredentialProvider().Inject(ctx, group.ID, "first.example.com", 443, "/")
	if err != nil {
		t.Fatal(err)
	}
	rules := append(c.Services, broker.Service{Name: "third", Host: "third.example.com", Auth: broker.Auth{Type: "bearer", Token: "KEY"}})
	body, err := json.Marshal(map[string]any{"services": rules})
	if err != nil {
		t.Fatal(err)
	}
	if w := f.call("PUT", route, string(body), c.Revision); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if err := accepted.Authorize(ctx); err == nil {
		t.Fatal("an in-flight request retained a stale routing policy")
	}
	if _, err := f.s.CredentialProvider().Inject(ctx, group.ID, "third.example.com", 443, "/"); err != nil {
		t.Fatal("new URL rule required grant reapproval", err)
	}
	for _, enabled := range []bool{false, true} {
		c, err = f.s.loadConnection(ctx, c.ID)
		if err != nil {
			t.Fatal(err)
		}
		body, err = json.Marshal(map[string]bool{"enabled": enabled})
		if err != nil {
			t.Fatal(err)
		}
		if w := f.call("PUT", route, string(body), c.Revision); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
		current, err := f.s.loadConnection(ctx, c.ID)
		if err != nil || current.Grants[0].Status != "active" {
			t.Fatal("credential disable/enable changed the agent's access setting", err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE connection_grants SET approved_revision=approved_revision WHERE connection_id=?`, c.ID); err != nil {
			t.Fatal("durable grant still depended on a stale policy snapshot or credential availability", err)
		}
		_, err = f.s.CredentialProvider().Inject(ctx, group.ID, "third.example.com", 443, "/")
		if (err == nil) != enabled {
			t.Fatal("credential disable/enable was not enforced", enabled, err)
		}
		w := f.call("GET", f.base()+"/vaults/group-one/access", "", "")
		wantStatus := "disabled"
		if enabled {
			wantStatus = "active"
		}
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"status":"`+wantStatus+`"`) {
			t.Fatal("access metadata did not reflect credential availability", w.Code, w.Body)
		}
	}
	if w := f.call("DELETE", route+"/grants/group-one", "", ""); w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	for _, host := range []string{"first.example.com", "second.example.com", "third.example.com"} {
		if _, err := f.s.CredentialProvider().Inject(ctx, group.ID, host, 443, "/"); err == nil {
			t.Fatal("revocation left a URL rule authorized", host)
		}
	}
}

func TestManagedConnectionRuleExpansionRejectsDestinationConflicts(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	first := f.create(basicConnection)
	second := f.create(strings.NewReplacer("basic-api", "other-api", "api.example.com", "other.example.com").Replace(basicConnection))
	for _, c := range []*connection{first, second} {
		if w := f.call("PUT", f.base()+"/connections/"+c.ID+"/grants/group-one", `{}`, ""); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	first, err := f.s.loadConnection(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(map[string]any{"services": append(first.Services, second.Services...)})
	if err != nil {
		t.Fatal(err)
	}
	if w := f.call("PUT", f.base()+"/connections/"+first.ID, string(body), first.Revision); w.Code != 409 {
		t.Fatal("URL expansion broke another credential's destination", w.Code, w.Body)
	}
	group, _ := f.db.GetVault(ctx, "group-one")
	for _, host := range []string{"api.example.com", "other.example.com"} {
		if _, err := f.s.CredentialProvider().Inject(ctx, group.ID, host, 443, "/v1/items"); err != nil {
			t.Fatal("rejected expansion changed existing access", host, err)
		}
	}
}
