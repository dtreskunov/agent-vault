package mitm

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestForwardQueryAuthenticationAndUnauthorizedBody(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var calls atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if values := r.URL.Query()["api_key"]; len(values) != 1 || values[0] != "synthetic &secret" {
					t.Error("query credential missing or ambiguous")
				}
				if r.URL.Query().Get("other") != "kept" {
					t.Error("unrelated parameter lost")
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "upstream-body")
			}))
			defer upstream.Close()
			host, _, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
			resolver := validTokenResolver("av_sess_ok", &brokercore.ProxyScope{VaultID: "v1", VaultName: "default", VaultRole: "proxy"})
			credentials := &fakeCredProvider{byHost: map[string]fakeInjectResult{
				host: {result: &brokercore.InjectResult{Query: map[string]string{"api_key": "synthetic &secret"}}},
			}}
			proxy, roots, _ := setupProxy(t, resolver, credentials)
			client := newTrustingClient(proxy, url.User("av_sess_ok"), roots)
			response, err := client.Get(upstream.URL + "/items?api_key=old&api_key=duplicate&other=kept")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil || string(body) != "upstream-body" || response.StatusCode != status || calls.Load() != 1 {
				t.Fatal("query request was retried or its response body lost", err)
			}
		})
	}
}

func TestQueryCredentialsAreRedactedFromTransportErrors(t *testing.T) {
	secret := "synthetic &secret"
	message := "upstream failed: " + secret + " " + url.QueryEscape(secret)
	got := redactQueryError(errors.New(message), map[string]string{"api_key": secret})
	if strings.Contains(got, secret) || strings.Contains(got, url.QueryEscape(secret)) || !strings.Contains(got, "[REDACTED]") {
		t.Fatal("transport error exposed a query credential")
	}
}
