package socketsessions

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func restart(t *testing.T, f *fixture) {
	t.Helper()
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	manager, err := New(f.root, f.db, f.manager.bound, slog.New(slog.NewJSONHandler(f.logs, nil)), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	f.manager = manager
	f.api = manager.Wrap(http.NotFoundHandler())
}

func TestRestartPreservesIdentityAndEgress(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	listed := f.call("GET", "/v1/socket-sessions", "").Body.String()
	token := f.manager.items[item.ID].token
	raw, err := f.db.GetSetting(context.Background(), stateKey)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(raw, token) || strings.Contains(raw, item.SocketPath) {
		t.Fatal("socket state was persisted without encryption")
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "rebound")
	}))
	defer upstream.Close()
	for i := 0; i < 2; i++ {
		restart(t, f)
		if got := f.call("GET", "/v1/socket-sessions", "").Body.String(); got != listed {
			t.Fatal("session metadata changed after restart")
		}
		if f.manager.items[item.ID].token != token {
			t.Fatal("restart changed the bound identity")
		}
		info, err := os.Stat(item.SocketPath)
		if err != nil || info.Mode().Perm() != 0666 {
			t.Fatal("socket was not rebound with mode 0666")
		}
		client := socketClient(t, item.SocketPath, f.ca)
		resp, err := client.Get(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != 200 || string(body) != "rebound" {
			t.Fatal("rebound socket did not preserve egress")
		}
		client.CloseIdleConnections()
	}
	if w := f.call("DELETE", "/v1/socket-sessions/"+item.ID, ""); w.Code != 204 {
		t.Fatalf("delete after restart returned %d", w.Code)
	}
	restart(t, f)
	if len(f.manager.items) != 0 {
		t.Fatal("deleted session resurrected on restart")
	}
	if _, err := os.Lstat(item.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted socket resurrected")
	}
}

func TestRestartReclaimsOnlyPersistedStaleSockets(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: item.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}
	restart(t, f)
	conn, err := net.Dial("unix", item.SocketPath)
	if err != nil {
		t.Fatal("persisted stale socket was not rebound")
	}
	conn.Close()
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(item.SocketPath, []byte("not a socket"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.root, f.db, f.manager.bound, slog.New(slog.DiscardHandler), make([]byte, 32)); err == nil {
		t.Fatal("rebind replaced a non-socket file")
	}
	if data, err := os.ReadFile(item.SocketPath); err != nil || string(data) != "not a socket" {
		t.Fatal("occupied socket path was modified")
	}
}

func TestMissingDirectoryIsLoggedAndRemainsDeletable(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(item.SocketPath)); err != nil {
		t.Fatal(err)
	}
	restart(t, f)
	if !strings.Contains(f.logs.text(), "session directory vanished") {
		t.Fatal("missing directory was not logged")
	}
	if _, err := os.Stat(item.SocketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing directory was recreated")
	}
	var listed struct{ Items []Item }
	if err := json.Unmarshal(f.call("GET", "/v1/socket-sessions", "").Body.Bytes(), &listed); err != nil ||
		len(listed.Items) != 1 || listed.Items[0].ID != item.ID {
		t.Fatal("host cannot reconcile skipped session")
	}
	if w := f.call("DELETE", "/v1/socket-sessions/"+item.ID, ""); w.Code != 204 {
		t.Fatalf("deleting skipped session returned %d", w.Code)
	}
}

func TestRestoreFailsClosed(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	if _, err := New(f.root, f.db, f.manager.bound, slog.New(slog.DiscardHandler), make([]byte, 32)); err == nil {
		t.Fatal("two managers acquired the same socket root")
	}
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	if _, err := New(f.root, f.db, f.manager.bound, slog.New(slog.DiscardHandler), wrongKey); err == nil {
		t.Fatal("wrong encryption key was accepted")
	}
	if err := f.db.DeleteSession(context.Background(), f.manager.items[item.ID].token); err != nil {
		t.Fatal(err)
	}
	restart(t, f)
	if len(f.manager.items) != 0 {
		t.Fatal("revoked scoped session was restored")
	}
}

func TestRestartRejectsChangedDirectory(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(item.SocketPath)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.root, f.db, f.manager.bound, slog.New(slog.DiscardHandler), make([]byte, 32)); err == nil {
		t.Fatal("rebind followed a directory replaced by an escaping symlink")
	}
}

func TestRestartDoesNotRestoreRevokedMembership(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	e := f.manager.items[item.ID]
	if err := f.manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.db.RevokeVaultAccess(context.Background(), e.owner, e.vaultID); err != nil {
		t.Fatal(err)
	}
	restart(t, f)
	if len(f.manager.items) != 0 {
		t.Fatal("socket was restored without its owner's vault membership")
	}
	if sess, _ := f.db.GetSession(context.Background(), e.token); sess != nil {
		t.Fatal("invalid owner's scoped token was not revoked")
	}
}

type failingPersistence struct{ Store }

func (failingPersistence) SetSetting(context.Context, string, string) error {
	return errors.New("test persistence failure")
}

func TestCreateRollsBackOnPersistenceFailure(t *testing.T) {
	f := setup(t)
	f.manager.store = failingPersistence{f.db}
	dir := filepath.Join(f.root, "new-session")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"vault": f.vault.Name, "dir": dir})
	if w := f.call("POST", "/v1/socket-sessions", string(body)); w.Code != 500 {
		t.Fatalf("unpersisted create returned %d", w.Code)
	}
	if _, err := os.Lstat(filepath.Join(dir, "egress.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unpersisted socket survived failed POST")
	}
	sessions, err := f.db.ListScopedSessionsByVault(context.Background(), f.vault.ID)
	if err != nil || len(sessions) != 0 || len(f.manager.items) != 0 {
		t.Fatal("unpersisted identity survived failed POST")
	}
}
