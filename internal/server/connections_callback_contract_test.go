package server

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestManagedOAuthCompleteParentPayloadUsesNativeID(t *testing.T) {
	for _, declined := range []bool{false, true} {
		name := "code"
		if declined {
			name = "provider-error"
		}
		t.Run(name, func(t *testing.T) {
			f, _, c, state := setupManagedOAuth(t)
			flow, err := f.s.mcpOAuth.ConnectionFlow(context.Background(), state)
			if err != nil {
				t.Fatal(err)
			}
			input := map[string]string{"state": state, "iss": flow.Account.Issuer}
			if declined {
				input["error"] = "access_denied"
			} else {
				input["code"] = "code"
			}
			for _, identity := range []string{"", "owner"} {
				if identity == "" {
					delete(input, "user_id")
				} else {
					input["user_id"] = identity
				}
				body, _ := json.Marshal(input)
				w := f.call(http.MethodPost, "/v1/oauth/complete", string(body), "")
				if w.Code != http.StatusForbidden {
					t.Fatal("missing native ID or NanoClaw subject was accepted", w.Code, w.Body)
				}
			}
			input["user_id"] = f.user
			body, _ := json.Marshal(input)
			w := f.call(http.MethodPost, "/v1/oauth/complete", string(body), "")
			if w.Code != http.StatusOK {
				t.Fatal(w.Code, w.Body)
			}
			var result map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if result["connection_id"] != c.ID || result["key"] != nil || result["vault"] != nil {
				t.Fatal("completion did not return exactly the pending connection identity", result)
			}
			expected := "connected"
			if declined {
				expected = "failed"
				if result["code"] != "declined" {
					t.Fatal("provider decline was not explicit", result)
				}
			}
			if result["status"] != expected {
				t.Fatal("unexpected completion status", result)
			}
			if w = f.call(http.MethodPost, "/v1/oauth/complete", string(body), ""); w.Code != http.StatusBadRequest {
				t.Fatal("parent-style callback state was reusable", w.Code, w.Body)
			}
		})
	}
}
