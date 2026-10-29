package server

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagedGrantFreshAttachNeverResurrectsOldBindingHandle(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	c := f.create(basicConnection)
	route := f.base() + "/connections/" + c.ID + "/grants/group-one"
	if w := f.call("PUT", route, `{"services":["basic-api"]}`, ""); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	group, _ := f.db.GetVault(ctx, "group-one")
	accepted, err := f.s.CredentialProvider().Inject(ctx, group.ID, "api.example.com", 443, "/v1/item")
	if err != nil {
		t.Fatal(err)
	}
	if w := f.call("DELETE", route, "", ""); w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
	request := httptest.NewRequest("PUT", route, strings.NewReader(`{"services":["basic-api"]}`))
	request.Header.Set("Authorization", "Bearer "+f.token)
	request.Header.Set("If-None-Match", "*")
	response := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal("explicit fresh attachment after detachment failed", response.Code, response.Body)
	}
	if err = accepted.Authorize(ctx); err == nil {
		t.Fatal("fresh attachment resurrected a revoked binding handle")
	}
	if _, err = f.s.CredentialProvider().Inject(ctx, group.ID, "api.example.com", 443, "/v1/item"); err != nil {
		t.Fatal("new binding did not authorize", err)
	}
}
