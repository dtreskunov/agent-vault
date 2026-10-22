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
	if _, err := m.PutApp(context.Background(), "", "google", AppInput{ClientID: "google", ClientSecret: &secret}); err != nil {
		t.Fatal(err)
	}
	start, err := m.StartProvider(context.Background(), vault, "google", []string{"gmail-read"}, "")
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
	if !InterceptTokenHost("oauth2.googleapis.com", 443) || InterceptTokenHost("oauth2.googleapis.com", 80) || InterceptTokenHost("evil.example.com", 443) {
		t.Fatal("token-host interception too broad")
	}
	m, _, vault := testManager(t)
	form := "grant_type=refresh_token&refresh_token=ordinary-token"
	r, _ := http.NewRequest("POST", "https://oauth2.googleapis.com/token", strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := m.TokenResponse(context.Background(), vault, r)
	body, _ := io.ReadAll(r.Body)
	if err != nil || response != nil || string(body) != form {
		t.Fatal("ordinary refresh was not preserved")
	}
}
