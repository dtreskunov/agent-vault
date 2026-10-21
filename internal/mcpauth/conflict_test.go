package mcpauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

func TestExistingServiceCannotShadowConnectedAccount(t *testing.T) {
	m, db, vault := testManager(t)
	a := newAuthority(t, m)
	ctx := context.Background()
	started, err := m.Start(ctx, vault, a.server.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	resource := Account{Key: accountKey(a.server.URL + "/mcp"), ResourceURL: a.server.URL + "/mcp"}
	services, err := resource.services()
	if err != nil {
		t.Fatal(err)
	}
	services[0].Name = "existing-service"
	services[0].Auth = broker.Auth{Type: "passthrough"}
	snapshot, err := json.Marshal(services[:1])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetBrokerConfig(ctx, vault, string(snapshot)); err != nil {
		t.Fatal(err)
	}
	code, _ := a.code(t, started)
	_, err = m.Complete(ctx, oauthrelay.Input{State: started.State, Code: code, Issuer: a.server.URL}, nil)
	var conflict *Failure
	if !errors.As(err, &conflict) || conflict.Code != "service_conflict" {
		t.Fatal("shadowing service did not fail the connection explicitly")
	}
	if _, err := db.GetCredential(ctx, vault, resource.Key); err != sql.ErrNoRows {
		t.Fatal("service conflict left a half-committed credential")
	}
	if accounts, err := m.List(ctx, vault); err != nil || len(accounts) != 0 {
		t.Fatal("service conflict left a connected account")
	}
}
