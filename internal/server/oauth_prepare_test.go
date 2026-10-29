package server

import (
	"context"
	"database/sql"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestOAuthValidationFailurePreventsListeners(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	ctx := context.Background()
	db, err := store.Open(filepath.Join(t.TempDir(), "vault.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer db.Close()
	vault, err := db.GetVault(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.GatewaySQL()
	if _, err := sqlDB.ExecContext(ctx, `INSERT INTO gateway_oauth_records(vault_id,kind,record_key,ciphertext,nonce)
		VALUES (?,'account','OAUTH_CORRUPT',?,?)`, vault.ID, []byte("corrupt-ciphertext"), make([]byte, 12)); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := New(listener.Addr().String(), db, make([]byte, 32), notify.New(nil), true,
		"http://127.0.0.1:12345", slog.New(slog.DiscardHandler))
	if err := s.Start(); err == nil || !strings.Contains(err.Error(), "validating OAuth model") {
		t.Fatal("server attempted to listen despite failed migration", err)
	}
	root := filepath.Join(t.TempDir(), "sockets")
	if err := s.AttachSocketSessions(root); err == nil || !strings.Contains(err.Error(), "validating OAuth model") {
		t.Fatal("socket listeners attempted restoration despite failed migration", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("failed migration created a socket-session directory")
	}
	if _, err := db.GetSetting(ctx, "gateway.oauth_model"); err != sql.ErrNoRows {
		t.Fatal("failed migration left a completion marker")
	}
}

func TestManagedHeadlessRejectsPopulatedEarlierForkBeforeSockets(t *testing.T) {
	f := newManagedFixture(t)
	ctx := context.Background()
	group, err := f.db.GetVault(ctx, "group-one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.db.SetCredential(ctx, group.ID, "EARLIER_FORK_KEY", []byte("synthetic-ciphertext"), make([]byte, 12)); err != nil {
		t.Fatal(err)
	}
	err = f.s.PrepareGateway(ctx)
	if err == nil || !strings.Contains(err.Error(), "offline adoption") {
		t.Fatal("populated group-owned headless state was silently supported", err)
	}
	root := filepath.Join(t.TempDir(), "sockets")
	if err = f.s.AttachSocketSessions(root); err == nil {
		t.Fatal("unsupported state restored sockets")
	}
	if _, err = os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("unsupported state touched socket root")
	}
	// Startup validation must neither move nor remove the credential.
	if _, err = f.db.GetCredential(ctx, group.ID, "EARLIER_FORK_KEY"); err != nil {
		t.Fatal("startup attempted state conversion", err)
	}
}
