package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicClientDoesNotSendIssuedSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("client_secret") != "" || r.Header.Get("Authorization") != "" || r.Form.Get("resource") != "https://mcp.example.com/mcp" {
			t.Error("public-client authentication or resource binding is incorrect")
		}
		fmt.Fprint(w, `{"access_token":"synthetic","token_type":"Bearer"}`)
	}))
	defer server.Close()
	if _, err := Exchange(context.Background(), ExchangeConfig{
		Client: server.Client(), TokenURL: server.URL, ClientID: "public", ClientSecret: "issued-but-unused",
		TokenAuthMethod: "none", Resource: "https://mcp.example.com/mcp",
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTokenResponseSizeIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("x", (1<<20)+1))
	}))
	defer server.Close()
	if _, err := Exchange(context.Background(), ExchangeConfig{Client: server.Client(), TokenURL: server.URL}); err == nil {
		t.Fatal("oversized OAuth response was accepted")
	}
}
