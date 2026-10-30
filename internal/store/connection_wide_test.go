package store

import (
	"context"
	"encoding/json"
	"testing"
)

func TestWholeCredentialGrantMigrationPreservesLifecycleAndExpandsSnapshots(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	user, err := s.ReconcileManagedUser(ctx, ManagedUserInput{
		InstallationID: "whole-credential-test", Subject: "owner", Active: true, Role: "no-access",
		VaultGrants: []ManagedVaultGrant{{Vault: "active-group", Role: "admin"}, {Vault: "paused-group", Role: "admin"}, {Vault: "revoked-group", Role: "admin"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	library, err := s.GetVault(ctx, user.LibraryVault)
	if err != nil {
		t.Fatal(err)
	}
	const rules = `[{"name":"first","host":"first.example.com"},{"name":"second","host":"second.example.com"}]`
	if _, err := s.db.Exec(`INSERT INTO connections(id,owner_user_id,library_vault_id,label,kind,status,revision,services_json)
		VALUES ('connection-wide',?,?,'Whole credential','static','disabled','current',?)`, user.ID, library.ID, rules); err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"active", "suspended", "revoked"} {
		group := status + "-group"
		if status == "suspended" {
			group = "paused-group"
		}
		vault, err := s.GetVault(ctx, group)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO connection_grants(connection_id,vault_id,services_json,bound_services_json,approved_revision,status,creator_user_id,binding_handle)
			VALUES ('connection-wide',?,'["first"]','[{"name":"first"}]','legacy',?,?,?)`, vault.ID, status, user.ID, "BIND_"+status); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.db.Exec(`DELETE FROM schema_migrations WHERE name='20261030192500_connection_wide_grants'`); err != nil {
		t.Fatal(err)
	}
	if err := runGORMMigrations(s.db, "sqlite"); err != nil {
		t.Fatal("whole-credential migration failed on existing disabled and partial grants", err)
	}
	for _, status := range []string{"active", "suspended", "revoked"} {
		var names, bound, revision, current string
		if err := s.db.QueryRow(`SELECT services_json,bound_services_json,approved_revision,status FROM connection_grants WHERE binding_handle=?`, "BIND_"+status).Scan(&names, &bound, &revision, &current); err != nil {
			t.Fatal(err)
		}
		if current != status {
			t.Fatal("migration changed an access setting", status, current)
		}
		var selected []string
		if err := json.Unmarshal([]byte(names), &selected); err != nil {
			t.Fatal(err)
		}
		if status == "revoked" {
			if len(selected) != 1 || revision != "legacy" {
				t.Fatal("migration rewrote a revoked grant")
			}
		} else if len(selected) != 2 || bound != rules || revision != "current" {
			t.Fatal("migration did not expand a live grant snapshot", status, names, revision)
		}
	}
	vault, err := s.GetVault(ctx, "active-group")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.GrantVaultRole(ctx, user.ID, "user", vault.ID, "proxy"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE connection_grants SET status='active' WHERE binding_handle='BIND_active'`); err == nil {
		t.Fatal("migration removed native destination-admin enforcement")
	}
}
