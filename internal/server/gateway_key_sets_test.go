package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Infisical/agent-vault/internal/notify"
	"github.com/Infisical/agent-vault/internal/statickeys"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestKeySetHTTPPreconditionsIsolationAndInjection(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	db, err := store.Open(filepath.Join(t.TempDir(), "sets-api.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	v, _ := db.GetVault(ctx, "default")
	_, owner, err := db.CreateAgentWithGrantsAndToken(ctx, "sets-owner", "", "owner", []store.AgentVaultGrantSpec{{VaultID: v.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, member, err := db.CreateAgentWithGrantsAndToken(ctx, "sets-member", "", "member", []store.AgentVaultGrantSpec{{VaultID: v.ID, Role: "member"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New("127.0.0.1:0", db, make([]byte, 32), notify.New(nil), true, "http://127.0.0.1:12345", slog.New(slog.DiscardHandler))
	call := func(method, route, body, token, match, none string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, route, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if match != "" {
			r.Header.Set("If-Match", match)
		}
		if none != "" {
			r.Header.Set("If-None-Match", none)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	route := "/v1/vaults/default/key-sets/combined-key"
	body := `{"values":{"BEARER_KEY":"synthetic-bearer","API_KEY":"synthetic-api"},"service":{"host":"api.example.com","auth":{"type":"custom","headers":{"Authorization":"Bearer {{ BEARER_KEY }}","x-api-key":"{{ API_KEY }}"}}}}`
	for _, test := range []struct {
		token, match, none string
		status             int
	}{
		{"", "", "*", 401},
		{member.ID, "", "*", 403},
		{owner.ID, "", "", 428},
		{owner.ID, "*", "", 428},
		{owner.ID, "unquoted", "", 428},
		{owner.ID, `"x"`, "*", 428},
	} {
		if w := call("PUT", route, body, test.token, test.match, test.none); w.Code != test.status {
			t.Fatalf("precondition/auth returned %d, want %d", w.Code, test.status)
		}
		if w := call("PUT", route, body+" {}", owner.ID, "", "*"); w.Code != 400 {
			t.Fatal("trailing JSON was accepted")
		}
	}
	created := call("PUT", route, body, owner.ID, "", "*")
	if created.Code != 200 {
		t.Fatal(created.Code, created.Body)
	}
	if strings.Contains(created.Body.String(), "synthetic-") || created.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secret response or cacheable response")
	}
	var info statickeys.SetInfo
	if err := json.Unmarshal(created.Body.Bytes(), &info); err != nil || info.Revision == "" || created.Header().Get("ETag") != info.Revision {
		t.Fatal("missing safe revision")
	}
	if w := call("GET", route, "", member.ID, "", ""); w.Code != 200 {
		t.Fatal("member metadata read denied")
	}
	if w := call("PUT", route, body, owner.ID, "", "*"); w.Code != 412 {
		t.Fatal("create-only replay overwrote the set")
	}
	injected, err := s.CredentialProvider().Inject(ctx, v.ID, "api.example.com", 443, "/")
	if err != nil {
		t.Fatal(err)
	}
	if injected.Headers["Authorization"] != "Bearer synthetic-bearer" || injected.Headers["x-api-key"] != "synthetic-api" {
		t.Fatal("composite credentials were not injected distinctly")
	}
	other, err := db.CreateVault(ctx, "other")
	if err != nil {
		t.Fatal(err)
	}
	otherRoute := "/v1/vaults/other/key-sets/combined-key"
	if w := call("GET", otherRoute, "", member.ID, "", ""); w.Code != 403 {
		t.Fatal("member crossed vault boundaries")
	}
	if w := call("GET", otherRoute, "", owner.ID, "", ""); w.Code != 403 {
		t.Fatal("vault admin crossed vault boundaries")
	}
	_, otherAdmin, err := db.CreateAgentWithGrantsAndToken(ctx, "other-admin", "", "owner", []store.AgentVaultGrantSpec{{VaultID: other.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherCreated := call("PUT", otherRoute, strings.ReplaceAll(body, "synthetic-", "other-"), otherAdmin.ID, "", "*")
	if otherCreated.Code != 200 {
		t.Fatal(otherCreated.Code, otherCreated.Body)
	}
	if otherCreated.Header().Get("ETag") == info.Revision {
		t.Fatal("revision was not vault-bound")
	}
	if w := call("DELETE", otherRoute, "", otherAdmin.ID, info.Revision, ""); w.Code != 412 {
		t.Fatal("cross-vault revision was accepted")
	}
	otherInjected, err := s.CredentialProvider().Inject(ctx, other.ID, "api.example.com", 443, "/")
	if err != nil || otherInjected.Headers["x-api-key"] != "other-api" {
		t.Fatal("new vault key set was not persisted or isolated")
	}
	update := `{"values":{"API_KEY":"synthetic-new"},"service":{"host":"api.example.com","auth":{"type":"custom","headers":{"Authorization":"Bearer {{ BEARER_KEY }}","x-api-key":"{{ API_KEY }}"}}}}`
	edited := call("PUT", route, update, owner.ID, info.Revision, "")
	if edited.Code != 200 {
		t.Fatal(edited.Code, edited.Body)
	}
	var updated statickeys.SetInfo
	json.Unmarshal(edited.Body.Bytes(), &updated)
	if w := call("DELETE", route, "", owner.ID, info.Revision, ""); w.Code != 412 {
		t.Fatal("stale delete succeeded")
	}
	if w := call("DELETE", route, "", member.ID, updated.Revision, ""); w.Code != 403 {
		t.Fatal("member deleted credentials")
	}
	if w := call("DELETE", route, "", owner.ID, updated.Revision, ""); w.Code != 204 {
		t.Fatal(w.Code, w.Body)
	}
}

func TestKeySetConcurrentCreateIsOneAtomicWinner(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "false")
	db, err := store.Open(filepath.Join(t.TempDir(), "sets-race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	v, _ := db.GetVault(ctx, "default")
	_, token, err := db.CreateAgentWithGrantsAndToken(ctx, "sets-owner", "", "owner", []store.AgentVaultGrantSpec{{VaultID: v.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := New("127.0.0.1:0", db, make([]byte, 32), notify.New(nil), true, "http://127.0.0.1:12345", slog.New(slog.DiscardHandler))
	statuses := make(chan int, 2)
	var wait sync.WaitGroup
	for i := 0; i < 2; i++ {
		wait.Add(1)
		go func(i int) {
			defer wait.Done()
			body := fmt.Sprintf(`{"values":{"ONE_KEY":"synthetic-%d","TWO_KEY":"synthetic-%d"},"service":{"host":"race.example.com","auth":{"type":"custom","headers":{"Authorization":"Bearer {{ ONE_KEY }}","X-Second":"{{ TWO_KEY }}"}}}}`, i, i)
			r := httptest.NewRequest("PUT", "/v1/vaults/default/key-sets/race-key", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+token.ID)
			r.Header.Set("If-None-Match", "*")
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			statuses <- w.Code
		}(i)
	}
	wait.Wait()
	close(statuses)
	winners, conflicts := 0, 0
	for status := range statuses {
		if status == 200 {
			winners++
		} else if status == 412 {
			conflicts++
		} else {
			t.Fatalf("unexpected race result %d", status)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("create-only was not serialized")
	}
	injected, err := s.CredentialProvider().Inject(ctx, v.ID, "race.example.com", 443, "/")
	if err != nil || injected.Headers["Authorization"] != "Bearer "+injected.Headers["X-Second"] {
		t.Fatal("concurrent creation mixed key values")
	}
}
