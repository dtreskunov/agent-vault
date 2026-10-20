package socketsessions

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/blindtunnel"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
	"github.com/Infisical/agent-vault/internal/store"
)

type credentialStore struct{ store.Store }

func (credentialStore) UnmatchedHostPolicy(context.Context, string) (brokercore.UnmatchedHostPolicy, error) {
	return brokercore.PolicyPassthrough, nil
}

type fixture struct {
	manager *Manager
	db      *store.SQLStore
	api     http.Handler
	token   string
	vault   *store.Vault
	root    string
	ca      ca.Provider
	records chan requestlog.Record
	limits  *ratelimit.Registry
	logs    *lockedBuffer
}

type channelSink chan requestlog.Record

func (s channelSink) Record(_ context.Context, r requestlog.Record) { s <- r }

type lockedBuffer struct {
	mu sync.Mutex
	strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Builder.Write(p)
}

func (b *lockedBuffer) text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Builder.String()
}

func setup(t testing.TB) *fixture {
	t.Helper()
	t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", "true")
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "mitm")
	dir, err := os.MkdirTemp("", "av-socket-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	db, err := store.Open(filepath.Join(dir, "vault.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	vault, err := db.GetVault(context.Background(), "default")
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := db.CreateAgentWithGrantsAndToken(context.Background(), "host", "", "owner",
		[]store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "admin"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	provider, err := ca.New(key, ca.Options{Dir: filepath.Join(dir, "ca")})
	if err != nil {
		t.Fatal(err)
	}
	records := make(chan requestlog.Record, 10000)
	limits := ratelimit.New(ratelimit.DefaultsFor(ratelimit.ProfileDefault))
	logs := &lockedBuffer{}
	p := mitm.New("", mitm.Options{
		CA: provider, Sessions: brokercore.NewStoreSessionResolver(db),
		Credentials: brokercore.NewStoreCredentialProvider(credentialStore{db}, key),
		Logger:      slog.New(slog.NewJSONHandler(logs, nil)), LogSink: channelSink(records),
		RateLimit:     limits,
		ConnectPolicy: blindtunnel.Policy{Store: db}.Decide,
	})
	root := filepath.Join(dir, "sockets")
	manager, err := New(root, db, p.Bound, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := manager.Close(); err != nil {
			t.Error(err)
		}
	})
	return &fixture{manager, db, manager.Wrap(http.NotFoundHandler()), token.ID, vault, root, provider, records, limits, logs}
}

func (f *fixture) call(method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+f.token)
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	return w
}

func (f *fixture) create(t testing.TB) Item {
	t.Helper()
	dir, err := os.MkdirTemp(f.root, "session-")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]string{"vault": f.vault.Name, "label": "test", "dir": dir})
	w := f.call("POST", "/v1/socket-sessions", string(data))
	if w.Code != 201 {
		t.Fatalf("creating socket session: %d", w.Code)
	}
	var item Item
	if err := json.Unmarshal(w.Body.Bytes(), &item); err != nil {
		t.Fatal(err)
	}
	return item
}

func TestLifecycleAndValidation(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	info, err := os.Stat(item.SocketPath)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0666 {
		t.Fatal("missing socket or incorrect permissions")
	}
	sessions, err := f.db.ListScopedSessionsByVault(context.Background(), f.vault.ID)
	if err != nil || len(sessions) != 1 || sessions[0].VaultRole != "proxy" || sessions[0].ExpiresAt != nil {
		t.Fatal("socket identity is not an internally managed proxy session")
	}
	data, _ := json.Marshal(map[string]string{"vault": f.vault.Name, "dir": filepath.Dir(item.SocketPath)})
	if w := f.call("POST", "/v1/socket-sessions", string(data)); w.Code != 409 {
		t.Fatalf("duplicate directory: %d", w.Code)
	}
	w := f.call("GET", "/v1/socket-sessions", "")
	var result struct{ Items []Item }
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || len(result.Items) != 1 ||
		result.Items[0].Label != "test" || result.Items[0].CreatedAt.IsZero() {
		t.Fatal("invalid list response")
	}
	for _, dir := range []string{"relative", f.root, filepath.Join(f.root, "missing"), t.TempDir()} {
		data, _ := json.Marshal(map[string]string{"vault": "default", "dir": dir})
		if w := f.call("POST", "/v1/socket-sessions", string(data)); w.Code != 400 {
			t.Fatalf("invalid directory accepted: %d", w.Code)
		}
	}
	link := filepath.Join(f.root, "escape")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	data, _ = json.Marshal(map[string]string{"vault": "default", "dir": link})
	if w := f.call("POST", "/v1/socket-sessions", string(data)); w.Code != 400 {
		t.Fatalf("symlink escape: %d", w.Code)
	}
	for _, vault := range []string{"missing", "ungranted"} {
		if vault == "ungranted" {
			if _, err := f.db.CreateVault(context.Background(), vault); err != nil {
				t.Fatal(err)
			}
		}
		data, _ = json.Marshal(map[string]string{"vault": vault, "dir": filepath.Dir(item.SocketPath)})
		want := 404
		if vault == "ungranted" {
			want = 403
		}
		if w := f.call("POST", "/v1/socket-sessions", string(data)); w.Code != want {
			t.Fatalf("%s vault: %d", vault, w.Code)
		}
	}
	conn, err := net.Dial("unix", item.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if w := f.call("DELETE", "/v1/socket-sessions/"+item.ID, ""); w.Code != 204 {
		t.Fatalf("delete: %d", w.Code)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("active connection survived deletion")
	}
	if _, err := os.Stat(item.SocketPath); !os.IsNotExist(err) {
		t.Fatal("socket survived deletion")
	}
	if w := f.call("DELETE", "/v1/socket-sessions/"+item.ID, ""); w.Code != 404 {
		t.Fatalf("second delete: %d", w.Code)
	}
	sessions, _ = f.db.ListScopedSessionsByVault(context.Background(), f.vault.ID)
	if len(sessions) != 0 {
		t.Fatal("session survived deletion")
	}
}

func TestAuthenticationAndSocketIsolation(t *testing.T) {
	f := setup(t)
	r := httptest.NewRequest("GET", "/v1/socket-sessions", nil)
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("unauthenticated management succeeded")
	}
	item := f.create(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-injected" ||
			r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Vault") != "" {
			w.WriteHeader(418)
			return
		}
		io.WriteString(w, "injected")
	}))
	defer upstream.Close()
	ct, nonce, err := crypto.Encrypt([]byte("test-injected"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.SetCredential(context.Background(), f.vault.ID, "TEST_KEY", ct, nonce); err != nil {
		t.Fatal(err)
	}
	services := `[{"name":"test","host":"127.0.0.1","auth":{"type":"bearer","token":"TEST_KEY"}}]`
	if _, err := f.db.SetBrokerConfig(context.Background(), f.vault.ID, services); err != nil {
		t.Fatal(err)
	}
	client := socketClient(t, item.SocketPath, f.ca)
	for i := 0; i < 200; i++ {
		f.limits.Allow(ratelimit.TierAuth, "mitm:@")
		f.limits.Allow(ratelimit.TierAuth, "mitm:")
	}
	req, _ := http.NewRequest("GET", upstream.URL, nil)
	req.Header.Set("Proxy-Authorization", "Bearer invalid-host-token:other-vault")
	req.Header.Set("X-Vault", "other-vault")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("bound identity or injection failed: %d", resp.StatusCode)
	}
	select {
	case record := <-f.records:
		if record.VaultID != f.vault.ID || record.MatchedService != "test" {
			t.Fatal("request did not use bound vault logging")
		}
	case <-time.After(time.Second):
		t.Fatal("request not logged")
	}
}

func socketClient(t testing.TB, path string, provider ca.Provider) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(provider.RootPEM())
	proxy, _ := url.Parse("http://socket.invalid")
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: roots},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

var trustOnce sync.Once

func trustUpstream(t testing.TB, cert *x509.Certificate) {
	t.Helper()
	t.Setenv("GODEBUG", os.Getenv("GODEBUG")+",x509usefallbackroots=1")
	trustOnce.Do(func() {
		pool := x509.NewCertPool()
		pool.AddCert(cert)
		x509.SetFallbackRoots(pool)
	})
}

func TestConnectAndActiveRevocation(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" {
			t.Error("proxy identity leaked")
		}
		io.WriteString(w, "tls-ok")
	}))
	defer upstream.Close()
	trustUpstream(t, upstream.Certificate())
	client := socketClient(t, item.SocketPath, f.ca)
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "tls-ok" {
		t.Fatalf("TLS proxy request: %d", resp.StatusCode)
	}
	conn, err := net.Dial("unix", item.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := strings.TrimPrefix(upstream.URL, "https://")
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: rubbish\r\n\r\n", target, target)
	reader := bufio.NewReader(conn)
	connected, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || connected.StatusCode != 200 {
		t.Fatal("CONNECT did not use bound identity")
	}
	if w := f.call("DELETE", "/v1/socket-sessions/"+item.ID, ""); w.Code != 204 {
		t.Fatalf("deleting hijacked connection: %d", w.Code)
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("hijacked connection survived deletion")
	}
}
