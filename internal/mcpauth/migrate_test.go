package mcpauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
	"github.com/Infisical/agent-vault/internal/store"
)

func legacyApp(t *testing.T, m *Manager, vault, id, clientID string) Client {
	t.Helper()
	c := Client{Issuer: "https://github.com/login/oauth", ID: clientID, Secret: "synthetic-app-secret",
		AuthMethod: "client_secret_post", Kind: "app", UpdatedAt: time.Unix(1700000000, 0).UTC(), Source: "vault"}
	if vault == "" {
		c.Source = "install"
	}
	if err := m.repo.storeApp(context.Background(), m.repo.db, vault, id, c); err != nil {
		t.Fatal(err)
	}
	return c
}

func seedLegacyAccount(t *testing.T, m *Manager, db *store.SQLStore, vault, key string, client Client, sets, paths []string) Account {
	t.Helper()
	ctx := context.Background()
	label, now := "verified-login", time.Unix(1700000000, 0).UTC()
	a := Account{Provider: "github", Key: key, ScopeSets: sets, Issuer: client.Issuer, Client: client,
		Metadata: oauthex.AuthServerMeta{Issuer: client.Issuer, AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
			TokenEndpoint: "https://github.com/login/oauth/access_token"},
		Identity: &label, Subject: "verified-subject-" + key, Scopes: "repo", AccessToken: "synthetic-access-" + key,
		RefreshToken: "synthetic-refresh-" + key, ConnectedAt: &now, LastUsedAt: &now, UpdatedAt: now,
		ExpiresAt: time.Now().Add(time.Hour)}
	if err := m.repo.put(ctx, m.repo.db, vault, "account", key, &a, 0); err != nil {
		t.Fatal(err)
	}
	ct, nonce, err := crypto.Encrypt([]byte(a.AccessToken), m.repo.key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetCredential(ctx, vault, key, ct, nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := m.repo.db.ExecContext(ctx, `UPDATE credentials SET type='oauth_app' WHERE vault_id=? AND key=?`, vault, key); err != nil {
		t.Fatal(err)
	}
	services := readServices(t, db, vault)
	for i, path := range paths {
		services = append(services, broker.Service{Name: servicePrefix(a) + string(rune('a'+i)), Host: "api.github.com", Path: path,
			Auth: broker.Auth{Type: "bearer", Token: key}})
	}
	writeServices(t, db, vault, services)
	return a
}

func readServices(t *testing.T, db *store.SQLStore, vault string) []broker.Service {
	t.Helper()
	config, err := db.GetBrokerConfig(context.Background(), vault)
	if err != nil {
		t.Fatal(err)
	}
	var services []broker.Service
	if err := json.Unmarshal([]byte(config.ServicesJSON), &services); err != nil {
		t.Fatal(err)
	}
	for i := range services {
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
	}
	return services
}

func writeServices(t *testing.T, db *store.SQLStore, vault string, services []broker.Service) {
	t.Helper()
	data, err := json.Marshal(services)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.SetBrokerConfig(context.Background(), vault, string(data)); err != nil {
		t.Fatal(err)
	}
}

func databaseSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	queries := []string{
		`SELECT vault_id,kind,record_key,hex(ciphertext),hex(nonce),expires_at,account_key FROM gateway_oauth_records ORDER BY vault_id,kind,record_key`,
		`SELECT vault_id,key,type,hex(ciphertext),hex(nonce),updated_at FROM credentials ORDER BY vault_id,key`,
		`SELECT vault_id,services_json,updated_at FROM broker_configs ORDER BY vault_id`,
		`SELECT key,value,updated_at FROM instance_settings ORDER BY key`,
		`SELECT authority FROM gateway_oauth_token_authorities ORDER BY authority`,
	}
	var snapshot strings.Builder
	for _, query := range queries {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(cols))
			targets := make([]any, len(cols))
			for i := range values {
				targets[i] = &values[i]
			}
			if err := rows.Scan(targets...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&snapshot, values)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return snapshot.String()
}

func TestLegacyMigrationPreservesStateAndIsIdempotent(t *testing.T) {
	m, db, vault := testManager(t)
	ctx := context.Background()
	m.client.Transport = &providerTransport{t: t}
	other, err := db.CreateVault(ctx, "override-vault")
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := db.CreateVault(ctx, "unrelated-vault")
	if err != nil {
		t.Fatal(err)
	}
	install := legacyApp(t, m, "", "github", "install-client")
	override := legacyApp(t, m, other.ID, "github", "override-client")
	legacyApp(t, m, "", "unrelated-app", "unused-client")
	static := broker.Service{Name: "static-service", Host: "static.example.com", Auth: broker.Auth{Type: "passthrough"}}
	mcp := broker.Service{Name: "mcp-other", Host: "mcp.example.com", Path: "/mcp/*", Auth: broker.Auth{Type: "bearer", Token: "MCP_OTHER"}}
	for _, id := range []string{vault, other.ID, unrelated.ID} {
		writeServices(t, db, id, []broker.Service{static, mcp})
	}
	unrelatedConfig, _ := db.GetBrokerConfig(ctx, unrelated.ID)
	old := seedLegacyAccount(t, m, db, vault, "OAUTH_REPO", install, []string{"repo"}, []string{"/repos/*"})
	second := seedLegacyAccount(t, m, db, other.ID, "OAUTH_ISSUES", override, []string{"issues"}, []string{"/repos/*/issues/*", "/repos/*/pulls/*"})
	credential, err := db.GetCredential(ctx, vault, old.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := m.repo.Account(ctx, vault, old.Key)
	if err != nil {
		t.Fatal(err)
	}
	if got.AppID != "github" || got.Client.AppID != "github" || got.Client.Source != "install" ||
		got.Client.ID != install.ID || got.IdentityAdapter != "github" || !slices.Equal(got.APIHosts, []string{"api.github.com"}) {
		t.Fatalf("generic account metadata incorrect: %+v", got.Info())
	}
	if got.AccessToken != old.AccessToken || got.RefreshToken != old.RefreshToken || got.Subject != old.Subject ||
		!reflect.DeepEqual(got.Identity, old.Identity) || got.Scopes != old.Scopes || !slices.Equal(got.ScopeSets, old.ScopeSets) ||
		!got.UpdatedAt.Equal(old.UpdatedAt) || !got.ConnectedAt.Equal(*old.ConnectedAt) || !got.LastUsedAt.Equal(*old.LastUsedAt) {
		t.Fatal("migration changed existing authorization or identity")
	}
	afterCredential, _ := db.GetCredential(ctx, vault, old.Key)
	if !reflect.DeepEqual(credential, afterCredential) {
		t.Fatal("migration rewrote encrypted credential tokens or metadata")
	}
	afterUnrelated, _ := db.GetBrokerConfig(ctx, unrelated.ID)
	if !reflect.DeepEqual(unrelatedConfig, afterUnrelated) {
		t.Fatal("migration changed unrelated vault routing")
	}
	for _, entry := range []struct{ vault, key string }{{vault, old.Key}, {other.ID, second.Key}} {
		services := readServices(t, db, entry.vault)
		if len(services) != 3 || !reflect.DeepEqual(services[0], static) || !reflect.DeepEqual(services[1], mcp) {
			t.Fatal("migration replaced unrelated static or MCP services")
		}
		for _, path := range []string{"/user", "/user/", "/user/repos", "/search/repositories", "/search/issues", "/search/code",
			"/users/login/repos", "/orgs/org/repos", "/repos/owner/repo/branches", "/anything-else"} {
			matched, _ := broker.MatchService("api.github.com", 443, path, services)
			if matched == nil || matched.Auth.Token != entry.key || !matched.HTTPSOnly || matched.Path != "" {
				t.Fatalf("host-wide routing failed for %s", path)
			}
		}
		for _, host := range []string{"github.com", "api.github.com.evil.example", "other.github.com"} {
			if match, _ := broker.MatchService(host, 443, "/user", services); match != nil {
				t.Fatal("credential route matched unrelated host", host)
			}
		}
		if match, _ := broker.MatchService("api.github.com", 8443, "/user", services); match != nil {
			t.Fatal("credential route matched an unconfigured port")
		}
	}
	snapshot := databaseSnapshot(t, m.repo.db)
	if err := m.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if snapshot != databaseSnapshot(t, m.repo.db) {
		t.Fatal("repeated migration was not a byte-for-byte no-op")
	}
	if err := m.DeleteApp(ctx, "", "github"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.repo.Account(ctx, vault, old.Key); err != sql.ErrNoRows {
		t.Fatal("install app deletion retained its account")
	}
	if remaining, err := m.repo.Account(ctx, other.ID, second.Key); err != nil || remaining.Client.ID != override.ID {
		t.Fatal("install app deletion affected the vault override")
	}
	if services := readServices(t, db, vault); len(services) != 2 {
		t.Fatal("app deletion did not remove all generated routes")
	}
	if err := m.Disconnect(ctx, other.ID, second.Key); err != nil {
		t.Fatal(err)
	}
	if services := readServices(t, db, other.ID); len(services) != 2 {
		t.Fatal("disconnect retained migrated routes or removed unrelated services")
	}
	if intercept, err := m.InterceptTokenHost(ctx, "github.com", 443); err != nil || !intercept {
		t.Fatal("disconnect/app deletion lost token-authority interception")
	}
}

func TestLegacyMigrationConflictsRollBackEverything(t *testing.T) {
	for _, kind := range []string{"static", "mcp", "account", "ownership", "enabled", "missing"} {
		t.Run(kind, func(t *testing.T) {
			m, db, vault := testManager(t)
			ctx := context.Background()
			client := legacyApp(t, m, "", "github", "client")
			a := seedLegacyAccount(t, m, db, vault, "OAUTH_FIRST", client, []string{"issues"}, []string{"/repos/*/issues/*", "/repos/*/pulls/*"})
			services := readServices(t, db, vault)
			switch kind {
			case "static", "mcp":
				services = append(services, broker.Service{Name: kind + "-collision", Host: "api.github.com", Path: "/user",
					Auth: broker.Auth{Type: "passthrough"}})
			case "account":
				seedLegacyAccount(t, m, db, vault, "OAUTH_SECOND", client, []string{"repo"}, []string{"/repos/*"})
				services = readServices(t, db, vault)
			case "ownership":
				services[0].Auth.Token = "UNRELATED_KEY"
			case "enabled":
				services[0].Enabled = new(false)
			case "missing":
				services = nil
			}
			writeServices(t, db, vault, services)
			before := databaseSnapshot(t, m.repo.db)
			if err := m.Migrate(ctx); err == nil {
				t.Fatal("migration silently accepted conflict", kind)
			}
			if before != databaseSnapshot(t, m.repo.db) {
				t.Fatal("failed migration left partial data or policy expansion", kind)
			}
			if saved, err := m.repo.Account(ctx, vault, a.Key); err != nil || saved.AppID != "" {
				t.Fatal("failed migration changed the legacy account")
			}
		})
	}
}

func TestFreshGenericAccountRoutesDoNotDependOnScopes(t *testing.T) {
	for _, scopes := range [][]string{{"repo"}, {"read:user"}, {}, nil} {
		m, _, vault := testManager(t)
		m.client.Transport = &providerTransport{t: t}
		secret := "synthetic-secret"
		if _, err := m.PutApp(context.Background(), "", "arbitrary-app", testAppInput("github", "client", &secret)); err != nil {
			t.Fatal(err)
		}
		start, err := m.StartAccount(context.Background(), vault, "arbitrary-app", scopes, "")
		if err != nil {
			t.Fatal(err)
		}
		flow, err := m.repo.Flow(context.Background(), start.State)
		if err != nil {
			t.Fatal(err)
		}
		services, err := flow.Account.services()
		if err != nil || len(services) != 1 || services[0].Path != "" || services[0].Host != "api.github.com" {
			t.Fatal("scope strings unexpectedly restricted destination routing", err)
		}
		want := scopes
		if want == nil {
			want = []string{"repo"}
		}
		if !slices.Equal(flow.Account.RequestedScopes, want) {
			t.Fatal("omitted and explicitly empty scopes were conflated")
		}
	}
}
