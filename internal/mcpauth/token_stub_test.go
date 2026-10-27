package mcpauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/blindtunnel"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/ca"
	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestSyntheticRefreshThroughProxyNeverContactsProvider(t *testing.T) {
	m, db, vault := testManager(t)
	remote := &providerTransport{t: t}
	m.client.Transport = remote
	secret := "synthetic"
	if _, err := m.PutApp(context.Background(), "", "google", testAppInput("google", "google", &secret)); err != nil {
		t.Fatal(err)
	}
	start, err := m.StartAccount(context.Background(), vault, "google", []string{gmailReadScope}, "")
	if err != nil {
		t.Fatal(err)
	}
	connected, err := m.Complete(context.Background(), oauthrelay.Input{State: start.State, Code: "code"}, nil)
	if err != nil || connected.Status != "connected" {
		t.Fatal(err)
	}
	scope, err := db.CreateScopedSession(context.Background(), store.CreateScopedSessionParams{VaultID: vault, VaultRole: "proxy"})
	if err != nil {
		t.Fatal(err)
	}
	provider, err := ca.New(make([]byte, 32), ca.Options{Dir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	proxy := mitm.New("127.0.0.1:0", mitm.Options{CA: provider, Sessions: brokercore.NewStoreSessionResolver(db), BoundToken: scope.ID,
		Logger: slog.New(slog.DiscardHandler), LocalResponse: m.TokenResponse,
		ConnectPolicy: func(context.Context, string, string, int) (blindtunnel.Mode, error) { return blindtunnel.MITM, nil }})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- proxy.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		proxy.Shutdown(ctx)
		<-done
	})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(provider.RootPEM())
	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	refresh := func(key string, want int) {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {RefreshPlaceholderPrefix + key}, "client_id": {"stdio-placeholder"}}
		response, err := client.PostForm("https://oauth2.googleapis.com/token", form)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != want {
			t.Fatalf("stub status %d, want %d", response.StatusCode, want)
		}
		if strings.Contains(string(body), "synthetic-") {
			t.Fatal("real stored token exposed by stub")
		}
		if want == 200 {
			var token map[string]any
			json.Unmarshal(body, &token)
			if token["access_token"] != AccessPlaceholderPrefix+key || token["refresh_token"] != RefreshPlaceholderPrefix+key {
				t.Fatal("stub placeholder contract incorrect")
			}
		}
	}
	refresh(connected.Key, 200)
	refresh("unknown", 400)
	other, err := db.CreateVault(context.Background(), "stub-other")
	if err != nil {
		t.Fatal(err)
	}
	request, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {RefreshPlaceholderPrefix + connected.Key},
	}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := m.TokenResponse(context.Background(), other.ID, request)
	if err != nil || response.StatusCode != 400 {
		t.Fatal("cross-vault placeholder accepted")
	}
	response.Body.Close()
	if remote.exchanges != 1 || remote.refreshes != 0 {
		t.Fatal("synthetic refresh contacted upstream")
	}
	if err := m.Disconnect(context.Background(), vault, connected.Key); err != nil {
		t.Fatal(err)
	}
	refresh(connected.Key, 400)
}

func TestTokenHostAndNonPlaceholderPassThrough(t *testing.T) {
	m, _, vault := testManager(t)
	secret := "synthetic"
	if _, err := m.PutApp(context.Background(), "", "google", testAppInput("google", "google", &secret)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host string
		port int
		want bool
	}{{"oauth2.googleapis.com", 443, true}, {"oauth2.googleapis.com", 80, false}, {"evil.example.com", 443, false}} {
		if got, err := m.InterceptTokenHost(context.Background(), tc.host, tc.port); err != nil || got != tc.want {
			t.Fatal("token-host interception incorrect", err)
		}
	}
	form := "grant_type=refresh_token&refresh_token=ordinary-token"
	r, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := m.TokenResponse(context.Background(), vault, r)
	body, _ := io.ReadAll(r.Body)
	if err != nil || response != nil || string(body) != form {
		t.Fatal("ordinary refresh was not preserved")
	}
	for _, body := range []string{`{"ordinary":"%not-form-encoded"}`, strings.Repeat("ordinary-json-body", 10000)} {
		request, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/unrelated-path", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response, err := m.TokenResponse(context.Background(), vault, request)
		replayed, readErr := io.ReadAll(request.Body)
		request.Body.Close()
		if err != nil || readErr != nil || response != nil || string(replayed) != body {
			t.Fatal("ordinary non-token request was changed at a known authority")
		}
	}
}

func TestGenericTokenAuthoritiesRejectWrongEndpointsAcrossRestartAndDeletion(t *testing.T) {
	m, db, vault := testManager(t)
	ctx := context.Background()
	remote := &providerTransport{t: t}
	m.client.Transport = remote
	secret := "synthetic-secret"
	keys := map[string]string{}
	for _, id := range []string{"google", "github"} {
		if _, err := m.PutApp(ctx, "", id, testAppInput(id, id, &secret)); err != nil {
			t.Fatal(err)
		}
		start, err := m.StartAccount(ctx, vault, id, nil, "")
		if err != nil {
			t.Fatal(err)
		}
		result, err := m.Complete(ctx, oauthrelay.Input{State: start.State, Code: "code"}, nil)
		if err != nil || result.Status != "connected" {
			t.Fatal(err)
		}
		keys[id] = result.Key
	}
	empty, err := db.CreateVault(ctx, "empty-stub-vault")
	if err != nil {
		t.Fatal(err)
	}
	check := func(manager *Manager, vault, method, endpoint, key string, want int) {
		t.Helper()
		data := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {RefreshPlaceholderPrefix + key}}.Encode()
		request, err := http.NewRequest(method, endpoint, strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response, err := manager.TokenResponse(ctx, vault, request)
		if err != nil || response == nil {
			t.Fatal("known token authority failed to intercept", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != want || strings.Contains(string(body), "synthetic-") {
			t.Fatalf("stub did not enforce account/endpoint binding: status=%d want=%d", response.StatusCode, want)
		}
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("stub response can be cached")
		}
		if want == 200 {
			var token struct {
				Access  string `json:"access_token"`
				Refresh string `json:"refresh_token"`
			}
			if err := json.Unmarshal(body, &token); err != nil || token.Access != AccessPlaceholderPrefix+key || token.Refresh != RefreshPlaceholderPrefix+key {
				t.Fatal("stub response contains incorrect synthetic tokens")
			}
		}
	}
	github := "https://github.com/login/oauth/access_token"
	check(m, vault, "POST", github, keys["github"], 200)
	check(m, vault, "POST", "https://oauth2.googleapis.com/token", keys["google"], 200)
	check(m, vault, "POST", github, keys["google"], 400)
	check(m, vault, "POST", "https://oauth2.googleapis.com/token", keys["github"], 400)
	check(m, vault, "POST", github+"/", keys["github"], 400)
	check(m, vault, "POST", github+"-near-miss", keys["github"], 400)
	check(m, vault, "POST", github+"?different=endpoint", keys["github"], 400)
	check(m, vault, "GET", github, keys["github"], 400)
	check(m, vault, "POST", github, "OAUTH_UNKNOWN", 400)
	check(m, empty.ID, "POST", github, keys["github"], 400)
	if remote.refreshes != 0 || remote.exchanges != 2 {
		t.Fatal("synthetic refresh contacted a provider")
	}
	if err := m.DeleteApp(ctx, "", "github"); err != nil {
		t.Fatal(err)
	}
	sqlDB, dialect := db.GatewaySQL()
	restarted := New(db, NewRepository(sqlDB, dialect, make([]byte, 32)), m.config, m.logger)
	if intercept, err := restarted.InterceptTokenHost(ctx, "github.com", 443); err != nil || !intercept {
		t.Fatal("restart or app deletion forgot a known token authority")
	}
	check(restarted, vault, "POST", github, keys["github"], 400)
	check(restarted, empty.ID, "POST", github, keys["github"], 400)
}
