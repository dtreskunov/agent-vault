package mcpauth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

func TestMCPStateIsConsumedExactlyOnce(t *testing.T) {
	m, _, vault := testManager(t)
	a := newAuthority(t, m)
	started, err := m.Start(context.Background(), vault, a.server.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	code, _ := a.code(t, started)
	var success atomic.Int32
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := m.Complete(context.Background(), oauthrelay.Input{
				State: started.State, Code: code, Issuer: a.server.URL,
			}, nil)
			if err == nil && result.Status == "connected" {
				success.Add(1)
			}
		}()
	}
	group.Wait()
	if success.Load() != 1 || a.exchanges != 1 {
		t.Fatal("concurrent callbacks exchanged one authorization state more than once")
	}
}

func TestInvalidClientDuringCompletionRequiresNewSignIn(t *testing.T) {
	m, _, vault := testManager(t)
	a := newAuthority(t, m)
	started, err := m.Start(context.Background(), vault, a.server.URL+"/mcp")
	if err != nil {
		t.Fatal(err)
	}
	code, original := a.code(t, started)
	a.mu.Lock()
	a.invalid = true
	a.mu.Unlock()
	result, err := m.Complete(context.Background(), oauthrelay.Input{
		State: started.State, Code: code, Issuer: a.server.URL,
	}, nil)
	if err != nil || result.Status != "failed" || result.Code != "needs_reconnect" || a.registrations != 2 {
		t.Fatal("invalid_client did not perform one registration and require a new sign-in")
	}
	a.mu.Lock()
	a.invalid = false
	a.mu.Unlock()
	_, replacement := connect(t, m, vault, a)
	if replacement == original || a.registrations != 2 {
		t.Fatal("new sign-in did not reuse the replacement client")
	}
}
