package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTokenHeadersExchangeAndRefresh(t *testing.T) {
	grants := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pk_test_synthetic" || r.Header.Get("X-Public-Client") != "example" {
			t.Error("additional token headers missing")
		}
		form := parseForm(t, r)
		if form.Get("client_id") != "client" || form.Get("client_secret") != "synthetic-secret" {
			t.Error("additional headers replaced OAuth body credentials")
		}
		grants = append(grants, form.Get("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","token_type":"Bearer"}`)
	}))
	defer server.Close()
	headers := map[string]string{"authorization": "Bearer pk_test_synthetic", "X-Public-Client": "example"}
	if _, err := Exchange(context.Background(), ExchangeConfig{
		TokenURL: server.URL, ClientID: "client", ClientSecret: "synthetic-secret",
		Code: "code", RedirectURI: "https://app.example/callback", TokenHeaders: headers,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := Refresh(context.Background(), RefreshConfig{
		TokenURL: server.URL, ClientID: "client", ClientSecret: "synthetic-secret",
		RefreshToken: "synthetic-refresh", TokenHeaders: headers,
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(grants, ",") != "authorization_code,refresh_token" {
		t.Fatal("both token grant types were not exercised")
	}
}

func TestValidateTokenHeaders(t *testing.T) {
	for _, test := range []struct {
		name, method string
		headers      map[string]string
		valid        bool
	}{
		{name: "absent", valid: true},
		{name: "body credentials", method: "client_secret_post", headers: map[string]string{"Authorization": "Bearer pk_test_synthetic"}, valid: true},
		{name: "basic with other header", method: "client_secret_basic", headers: map[string]string{"X-Public-Client": "example"}, valid: true},
		{name: "basic conflict", method: "client_secret_basic", headers: map[string]string{"authorization": "Bearer pk_test_synthetic"}},
		{name: "case duplicates", headers: map[string]string{"X-Client": "one", "x-client": "two"}},
		{name: "invalid name", headers: map[string]string{"Bad Name": "value"}},
		{name: "empty name", headers: map[string]string{"": "value"}},
		{name: "pseudo header", headers: map[string]string{":authority": "value"}},
		{name: "line injection", headers: map[string]string{"X-Client": "synthetic-do-not-echo\r\nInjected: true"}},
		{name: "control character", headers: map[string]string{"X-Client": "synthetic-do-not-echo\x00"}},
		{name: "non-ASCII value", headers: map[string]string{"X-Client": "\u0085"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTokenHeaders(test.headers, test.method)
			if (err == nil) != test.valid {
				t.Fatalf("validation result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-do-not-echo") {
				t.Fatal("validation exposed a header value")
			}
		})
	}
	for _, name := range []string{
		"Host", "Content-Length", "Content-Type", "Content-Encoding", "Transfer-Encoding",
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
		"TE", "Trailer", "Upgrade", "Cookie", "Set-Cookie",
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateTokenHeaders(map[string]string{name: "value"}, "client_secret_post"); err == nil {
				t.Fatal("accepted a transport or cookie header")
			}
		})
	}
}

func TestTokenHeadersRejectBeforeSending(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()
	headers := map[string]string{"Authorization": "Bearer pk_test_synthetic"}
	if _, err := Exchange(context.Background(), ExchangeConfig{
		TokenURL: server.URL, TokenAuthMethod: "client_secret_basic", TokenHeaders: headers,
	}); err == nil {
		t.Fatal("conflicting headers reached exchange")
	}
	if _, err := Refresh(context.Background(), RefreshConfig{
		TokenURL: server.URL, TokenAuthMethod: "client_secret_basic", TokenHeaders: headers,
	}); err == nil {
		t.Fatal("conflicting headers reached refresh")
	}
	if called {
		t.Fatal("invalid header configuration sent a request")
	}
}
