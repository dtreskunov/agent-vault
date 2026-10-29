package socketsessions

import (
	"context"
	"net"
	"os"
	"testing"
)

func TestManagedGroupDeletionRevokesSocketCapabilities(t *testing.T) {
	f := setup(t)
	first := f.create(t)
	second := f.create(t)
	firstToken := f.manager.items[first.ID].token
	if err := f.manager.RevokeVault(context.Background(), f.vault.ID); err != nil {
		t.Fatal(err)
	}
	if len(f.manager.items) != 0 {
		t.Fatal("group socket bindings remained in memory")
	}
	for _, item := range []Item{first, second} {
		if _, err := os.Lstat(item.SocketPath); !os.IsNotExist(err) {
			t.Fatal("group socket path remained", err)
		}
		if conn, err := net.Dial("unix", item.SocketPath); err == nil {
			conn.Close()
			t.Fatal("deleted group socket accepted a new client")
		}
	}
	if _, err := f.db.GetSession(context.Background(), firstToken); err == nil {
		t.Fatal("deleted group socket token remained active")
	}
	w := f.call("GET", "/v1/socket-sessions", "")
	if w.Code != 200 || w.Body.String() != "{\"items\":[]}\n" {
		t.Fatal("deleted socket bindings remained listed", w.Code, w.Body)
	}
}
