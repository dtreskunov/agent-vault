package mcpauth

import (
	"context"
	"database/sql"
	"testing"
)

func TestManagedMCPClientDisplayNameReuseAndChange(t *testing.T) {
	m, db, _ := testManager(t)
	authority := newAuthority(t, m)
	ctx := context.Background()
	user, library, _ := managedMCPFixture(t, m, db, "CONN_NAMED")
	for _, name := range []string{"BananaClaw (Denis Treskunov)", "BananaClaw (Denis Treskunov)", "Other brand (Denis Treskunov)"} {
		if _, err := m.StartConnection(ctx, library, user, "CONN_NAMED", "mcp_oauth", authority.server.URL+"/mcp", "", name, nil); err != nil {
			t.Fatal(err)
		}
	}
	authority.mu.Lock()
	registrations, names := authority.registrations, append([]string(nil), authority.names...)
	authority.mu.Unlock()
	if registrations != 2 || names[0] != "BananaClaw (Denis Treskunov)" || names[1] != "Other brand (Denis Treskunov)" {
		t.Fatal("registration display name was not propagated or reused", registrations, names)
	}
}

func TestManagedMCPNewestConsentAndDraftClientCleanup(t *testing.T) {
	m, db, _ := testManager(t)
	authority := newAuthority(t, m)
	ctx := context.Background()
	user, library, _ := managedMCPFixture(t, m, db, "CONN_DRAFT")
	first, err := m.StartConnection(ctx, library, user, "CONN_DRAFT", "mcp_oauth", authority.server.URL+"/mcp", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}

	second, err := m.StartConnection(ctx, library, user, "CONN_DRAFT", "mcp_oauth", authority.server.URL+"/mcp", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.ConnectionFlow(ctx, first.State); err != sql.ErrNoRows {
		t.Fatal("superseded consent remained usable", err)
	}
	if _, err = m.ConnectionFlow(ctx, second.State); err != nil {
		t.Fatal("latest consent was not retained", err)
	}
	if err = m.DisconnectConnection(ctx, library, "CONN_DRAFT"); err != nil {
		t.Fatal("draft client cleanup failed", err)
	}
	if _, err = m.ConnectionFlow(ctx, second.State); err != sql.ErrNoRows {
		t.Fatal("deleted draft retained a pending consent", err)
	}
	authority.mu.Lock()
	registrations, deletions, revocations := authority.registrations, authority.deletions, authority.revocations
	authority.mu.Unlock()
	if registrations != 1 || deletions != 1 || revocations != 0 {
		t.Fatal("draft lifecycle duplicated clients or revoked nonexistent tokens", registrations, deletions, revocations)
	}
}
