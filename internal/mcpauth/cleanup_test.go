package mcpauth

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInvalidTokenDoesNotHideClientCleanupFailures(t *testing.T) {
	for _, operation := range []string{"client deletion", "GitHub token revocation"} {
		t.Run(operation, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(`{"error":"invalid_token"}`))
			}))
			defer server.Close()
			m := &Manager{client: server.Client(), logger: slog.Default()}
			request, err := http.NewRequest(http.MethodDelete, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.cleanupRequest(request, operation, "synthetic-client"); err == nil {
				t.Fatal("client cleanup failure was treated as successful token revocation")
			}
		})
	}
}
