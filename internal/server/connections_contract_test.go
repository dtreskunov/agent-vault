package server

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestManagedNonHeadlessPreservesNativeCoreWithoutForkAliases(t *testing.T) {
	f := newManagedFixture(t)
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	f.s = New("127.0.0.1:0", f.db, make([]byte, 32), notify.New(nil), true, "http://127.0.0.1:14321", slog.New(slog.DiscardHandler))
	for _, path := range []string{"/v1/oauth-apps", "/v1/vaults/group-one/keys/KEY", "/v1/vaults/group-one/key-sets/set", "/v1/vaults/group-one/mcp-oauth", "/v1/vaults/group-one/oauth-accounts", "/v1/vaults/group-one/oauth-apps"} {
		if w := f.call("GET", path, "", ""); w.Code != 404 {
			t.Fatal("fork-era route survived as a non-headless alias", path, w.Code)
		}
	}
	if w := f.call("POST", "/v1/credentials", `{"vault":"group-one","credentials":{"LOCAL_KEY":"synthetic-native"}}`, ""); w.Code != 200 {
		t.Fatal("upstream standalone credential management changed", w.Code, w.Body)
	}
	// A managed principal remains non-login even when the headless wrapper is off.
	if _, err := f.db.CreateUserSession(context.Background(), store.CreateUserSessionParams{UserID: f.user}); err == nil {
		t.Fatal("managed user acquired a non-headless human session")
	}
	if w := f.call("PUT", "/v1/managed-users", `{"installation_id":"install","subject":"owner","role":"no-access","vault_grants":[]}`, ""); w.Code != 400 {
		t.Fatal("missing active snapshot silently disabled a managed user", w.Code)
	}
}

func TestManagedGrantRevisionCoversRecipientUpdates(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	c := f.create(`{"label":"Two services","kind":"static","values":{"KEY":"synthetic-key"},"services":[{"name":"first-api","host":"first.example.com","auth":{"type":"bearer","token":"KEY"}},{"name":"second-api","host":"second.example.com","auth":{"type":"bearer","token":"KEY"}}]}`)
	route := f.base() + "/connections/" + c.ID + "/grants/group-one"
	w := f.call("PUT", route, `{"services":["first-api"]}`, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	current, err := f.s.loadConnection(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	status := make(chan int, 2)
	var wg sync.WaitGroup
	for _, service := range []string{"first-api", "second-api"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.call("PUT", route, fmt.Sprintf(`{"services":[%q]}`, service), current.Revision)
			status <- w.Code
		}()
	}
	wg.Wait()
	close(status)
	counts := map[int]int{}
	for code := range status {
		counts[code]++
	}
	if counts[200] != 1 || counts[412] != 1 {
		t.Fatal("concurrent grant update lost precondition protection", counts)
	}
}
