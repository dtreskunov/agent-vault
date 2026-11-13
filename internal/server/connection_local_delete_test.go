package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/Infisical/agent-vault/internal/store"
)

func TestManagedConnectionLocalDeletion(t *testing.T) {
	for _, status := range []int{307, 503} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f, provider, c, state := setupManagedOAuth(t)
			ctx := context.Background()
			if w := f.complete(c, state, f.user); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			other := f.create(`{"label":"Keep this account","kind":"oauth_app","app_id":"test-app","scopes":["read"]}`)
			w := f.call("POST", f.base()+"/connections/"+other.ID+"/oauth/start", `{}`, "")
			var flow struct{ State string }
			if err := json.Unmarshal(w.Body.Bytes(), &flow); err != nil {
				t.Fatal(err)
			}
			if w = f.complete(other, flow.State, f.user); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			route := f.base() + "/connections/" + c.ID
			c, err := f.s.loadConnection(ctx, c.ID)
			if err != nil {
				t.Fatal(err)
			}
			if c.LocalOnlyRemovalAllowed {
				t.Fatal("local deletion advertised for an active account")
			}
			if w = f.call("DELETE", route+"?local_only=true", "", c.Revision); w.Code != 409 {
				t.Fatal("local deletion bypassed strict cleanup", w.Code, w.Body)
			}
			if w = f.call("PUT", route+"/grants/group-one", `{}`, c.Revision); w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			provider.mu.Lock()
			provider.cleanupStatus = status
			provider.mu.Unlock()
			if w = f.call("DELETE", route, "", ""); w.Code != 502 || !strings.Contains(w.Body.String(), "upstream_cleanup_failed") {
				t.Fatal("strict deletion hid upstream failure", w.Code, w.Body)
			}
			c, err = f.s.loadConnection(ctx, c.ID)
			if err != nil || c.Status != "disabled" || len(c.Grants) != 0 || !c.LocalOnlyRemovalAllowed {
				t.Fatal("failed cleanup did not retain an eligible disabled connection", c, err)
			}
			provider.mu.Lock()
			before := provider.revocations
			provider.mu.Unlock()
			for _, test := range []struct {
				query, revision string
				want            int
			}{
				{"?local_only=true", "", 428},
				{"?local_only=true", `"stale"`, 412},
				{"?local_only=false", c.Revision, 400},
				{"?local_only=true&local_only=true", c.Revision, 400},
			} {
				if w = f.call("DELETE", route+test.query, "", test.revision); w.Code != test.want {
					t.Fatal("invalid local deletion accepted", test, w.Code, w.Body)
				}
			}
			foreign, err := f.db.ReconcileManagedUser(ctx, store.ManagedUserInput{InstallationID: "install", Subject: "other-owner", Active: true, Role: "owner"})
			if err != nil {
				t.Fatal(err)
			}
			if w = f.call("DELETE", "/v1/managed-users/"+foreign.ID+"/connections/"+c.ID+"?local_only=true", "", c.Revision); w.Code != 403 {
				t.Fatal("another user removed an owned connection", w.Code, w.Body)
			}
			if w = f.call("DELETE", route+"?local_only=true", "", c.Revision); w.Code != 204 {
				t.Fatal("explicit local deletion failed", w.Code, w.Body)
			}
			if _, err = f.s.loadConnection(ctx, c.ID); !errors.Is(err, sql.ErrNoRows) {
				t.Fatal("removed connection remained visible", err)
			}
			db, _ := f.db.GatewaySQL()
			for _, query := range []string{
				`SELECT COUNT(*) FROM gateway_oauth_records WHERE vault_id=? AND account_key=?`,
				`SELECT COUNT(*) FROM credentials WHERE vault_id=? AND key=?`,
			} {
				var remaining int
				if err = db.QueryRowContext(ctx, query, c.library, c.ID).Scan(&remaining); err != nil || remaining != 0 {
					t.Fatal("encrypted account material remained after local deletion", remaining, err)
				}
			}
			var audits int
			if err = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM connection_audit WHERE connection_id=? AND action='delete_local'`, c.ID).Scan(&audits); err != nil || audits != 1 {
				t.Fatal("local removal was not distinctly audited", audits, err)
			}
			if account, err := f.s.mcpOAuth.ConnectionAccount(ctx, c.library, other.ID); err != nil || account == nil {
				t.Fatal("local removal damaged another account", err)
			}
			provider.mu.Lock()
			after := provider.revocations
			provider.mu.Unlock()
			if after != before {
				t.Fatal("local deletion contacted the provider", before, after)
			}
		})
	}
}
