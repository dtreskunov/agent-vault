package oauthex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetadataContentTypes(t *testing.T) {
	for _, test := range []struct {
		content string
		valid   bool
	}{
		{"application/json", true}, {"application/json,application/json", true}, {"application/json; charset=utf-8, application/json", true},
		{"application/json,text/plain", false}, {"text/html", false}, {"", false},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", test.content)
			w.Write([]byte(`{"ok":true}`))
		}))
		_, err := getJSON[map[string]bool](context.Background(), server.Client(), server.URL, 4096)
		server.Close()
		if (err == nil) != test.valid {
			t.Fatalf("Content-Type %q validity=%t: %v", test.content, test.valid, err)
		}
	}
}
