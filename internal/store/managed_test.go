package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedNativeIdentityAndNonLogin(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "managed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	in := ManagedUserInput{InstallationID: "install-1", Subject: "subject-1", DisplayName: "First", Active: true, Role: "no-access", VaultGrants: []ManagedVaultGrant{{Vault: "group-one", Role: "admin"}}}
	result, err := db.ReconcileManagedUser(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	in.Email = "real@example.com"
	in.DisplayName = "Renamed"
	again, err := db.ReconcileManagedUser(ctx, in)
	if err != nil || *result != *again {
		t.Fatal("unstable native mapping", err)
	}
	user, err := db.GetUserByID(ctx, result.ID)
	if err != nil || user.AuthMode != "managed" || user.DisplayName != "Renamed" || user.Email != in.Email || !user.IsActive || len(user.PasswordHash) != 0 || len(user.PasswordSalt) != 0 {
		t.Fatal("managed user was not a native non-login principal", err)
	}
	if _, err = db.GetUserByEmail(ctx, in.Email); err != sql.ErrNoRows {
		t.Fatal("human email lookup resolved managed principal", err)
	}
	if err = db.ActivateUser(ctx, user.ID); err != sql.ErrNoRows {
		t.Fatal("human verification path activated a managed user", err)
	}
	if _, err = db.CreateUserSession(ctx, CreateUserSessionParams{UserID: user.ID, ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("managed human session created")
	}
	if err = db.UpdateUserPassword(ctx, user.ID, []byte("fake"), []byte("fake"), 1, 1, 1); err == nil {
		t.Fatal("managed password material accepted")
	}
	if _, err = db.db.Exec(`UPDATE users SET auth_mode='local',installation_id=NULL,subject=NULL,password_hash=?,password_salt=? WHERE id=?`, []byte("x"), []byte("y"), user.ID); err == nil {
		t.Fatal("managed authentication identity changed")
	}
	in.Subject = "subject-2"
	other, err := db.ReconcileManagedUser(ctx, in)
	if err != nil || other.ID == result.ID {
		t.Fatal("email deduplicated distinct external principals", err)
	}
	library, err := db.GetVault(ctx, result.LibraryVault)
	if err != nil || library.Purpose != "library" || library.OwnerUserID != user.ID {
		t.Fatal("missing native personal library", err)
	}
	if _, err = db.CreateScopedSession(ctx, CreateScopedSessionParams{VaultID: library.ID, VaultRole: "proxy"}); err == nil {
		t.Fatal("library proxy session created")
	}
	if err = db.GrantVaultRole(ctx, "proxy-agent", "agent", library.ID, "proxy"); err == nil {
		t.Fatal("agent admitted to personal library")
	}
	if err = db.GrantVaultRole(ctx, other.ID, "user", library.ID, "admin"); err == nil {
		t.Fatal("another user admitted to personal library")
	}
	if err = db.GrantVaultRole(ctx, user.ID, "user", library.ID, "proxy"); err == nil {
		t.Fatal("library owner downgraded to proxy")
	}
	in.Subject = "subject-1"
	in.VaultGrants = []ManagedVaultGrant{{Vault: result.LibraryVault, Role: "admin"}}
	if _, err = db.ReconcileManagedUser(ctx, in); err == nil {
		t.Fatal("personal library accepted as group grant")
	}
	in.VaultGrants = []ManagedVaultGrant{{Vault: "default", Role: "admin"}}
	if _, err = db.ReconcileManagedUser(ctx, in); err == nil {
		t.Fatal("system vault accepted as group grant")
	}
	in.VaultGrants = nil
	in.Active = false
	if _, err = db.ReconcileManagedUser(ctx, in); err != nil {
		t.Fatal(err)
	}
	if user, err = db.GetUserByID(ctx, result.ID); err != nil || user.IsActive {
		t.Fatal("managed disablement failed")
	}
	if err = db.DeleteUser(ctx, result.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.GetUserByID(ctx, result.ID); err != nil {
		t.Fatal("managed deletion discarded ownership principal")
	}
}
