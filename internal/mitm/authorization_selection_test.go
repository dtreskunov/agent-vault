package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

type selectionProvider struct{ calls atomic.Int32 }

func (p *selectionProvider) Inject(ctx context.Context, _, _ string, _ int, _ string) (*brokercore.InjectResult, error) {
	p.calls.Add(1)
	if !slices.Equal(brokercore.RequestAuthorization(ctx), []string{"Bearer av-access:group-bound-selector"}) {
		return nil, brokercore.ErrServiceDisabled
	}
	return &brokercore.InjectResult{HTTPSOnly: true, Headers: map[string]string{"Authorization": "Bearer synthetic-selected-token"}}, nil
}

func TestOAuthSelectionReachesTLSInjectionAndRetry(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-selected-token" {
			t.Error("selector was forwarded instead of the selected credential")
		}
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	cp := &selectionProvider{}
	proxyURL, clientRoots, proxy := setupProxy(t, validTokenResolver("token", &brokercore.ProxyScope{VaultID: "group", VaultName: "group"}), cp)
	upstreamRoots := x509.NewCertPool()
	upstreamRoots.AddCert(upstream.Certificate())
	proxy.upstream.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: upstreamRoots}
	client := newTrustingClient(proxyURL, url.User("token"), clientRoots)
	request, _ := http.NewRequest(http.MethodGet, upstream.URL+"/items", nil)
	request.Header.Set("Authorization", "Bearer av-access:group-bound-selector")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || string(body) != "ok" || cp.calls.Load() != 2 {
		t.Fatal("selector was not retained across TLS forwarding and retry", response.StatusCode, cp.calls.Load())
	}
}
