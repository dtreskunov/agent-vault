package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestManagedGatewayNodeBridge runs an opt-in external host client against the
// real HTTP handler, native SQLite store and encrypted OAuth implementation.
func TestManagedGatewayNodeBridge(t *testing.T) {
	script := os.Getenv("AGENT_VAULT_NODE_INTEGRATION_SCRIPT")
	if script == "" {
		t.Skip("set AGENT_VAULT_NODE_INTEGRATION_SCRIPT to an external Node integration script")
	}
	script, err := filepath.Abs(script)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Fatal(err)
	}
	runner := os.Getenv("AGENT_VAULT_NODE_INTEGRATION_RUNNER")
	if runner == "" {
		runner = "node"
	}
	runner, err = exec.LookPath(runner)
	if err != nil {
		t.Fatal("selected Node integration runner is unavailable:", err)
	}
	server := httptest.NewUnstartedServer(nil)
	defer server.Close()
	f, provider, c, state := setupManagedOAuth(t, "http://"+server.Listener.Addr().String())
	if err := f.s.PrepareGateway(context.Background()); err != nil {
		t.Fatal(err)
	}
	flow, err := f.s.mcpOAuth.ConnectionFlow(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	var managementCalls atomic.Int64
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/managed-users") {
			managementCalls.Add(1)
		}
		f.s.Handler().ServeHTTP(w, r)
	})
	server.Start()
	response, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatal("test gateway did not become responsive:", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatal("test gateway did not become healthy:", response.StatusCode)
	}

	workspace, err := os.MkdirTemp(".", ".node-wire-")
	if err != nil {
		t.Fatal(err)
	}
	workspace, err = filepath.Abs(workspace)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(workspace) })
	for _, dir := range []string{"home", "config", "data", "scratch"} {
		if err := os.Mkdir(filepath.Join(workspace, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	tokenFile := filepath.Join(workspace, "scratch", "synthetic-host-token")
	if err := os.WriteFile(tokenFile, []byte(f.token+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	overrides := map[string]string{
		"HOME":                                  filepath.Join(workspace, "home"),
		"XDG_CONFIG_HOME":                       filepath.Join(workspace, "config"),
		"XDG_DATA_HOME":                         filepath.Join(workspace, "data"),
		"TMPDIR":                                filepath.Join(workspace, "scratch"),
		"AGENT_VAULT_ADDR":                      server.URL,
		"AGENT_VAULT_TOKEN_FILE":                tokenFile,
		"AGENT_VAULT_BOOTSTRAP_TOKEN_FILE":      tokenFile,
		"AGENT_VAULT_HEADLESS":                  "true",
		"AGENT_VAULT_REVEAL_DISABLED":           "true",
		"AGENT_VAULT_TEST_URL":                  server.URL,
		"AGENT_VAULT_TEST_TOKEN_FILE":           tokenFile,
		"AGENT_VAULT_TEST_WORKSPACE":            workspace,
		"AGENT_VAULT_TEST_USER_ID":              f.user,
		"AGENT_VAULT_TEST_LIBRARY_VAULT":        f.library,
		"AGENT_VAULT_TEST_INSTALLATION_ID":      "install",
		"AGENT_VAULT_TEST_SUBJECT":              "owner",
		"AGENT_VAULT_TEST_CONNECTION_ID":        c.ID,
		"AGENT_VAULT_TEST_STATE":                state,
		"AGENT_VAULT_TEST_CODE":                 "code",
		"AGENT_VAULT_TEST_ISSUER":               flow.Account.Issuer,
		"AGENT_VAULT_TEST_VAULT":                "group-one",
		"AGENT_VAULT_TEST_OTHER_VAULT":          "group-two",
		"AGENT_VAULT_TEST_APP_ID":               "test-app",
		"AGENT_VAULT_TEST_OAUTH_CLIENT_ID":      "test-client",
		"AGENT_VAULT_TEST_OAUTH_CLIENT_SECRET":  "synthetic-client-secret",
		"AGENT_VAULT_TEST_OAUTH_AUTHORIZE_URL":  flow.Account.Metadata.AuthorizationEndpoint,
		"AGENT_VAULT_TEST_OAUTH_TOKEN_URL":      flow.Account.Metadata.TokenEndpoint,
		"AGENT_VAULT_TEST_OAUTH_REVOCATION_URL": flow.Account.Metadata.RevocationEndpoint,
		"NANOCLAW_TEST_GATEWAY_URL":             server.URL,
		"NANOCLAW_TEST_GATEWAY_TOKEN_FILE":      tokenFile,
	}
	environment := make([]string, 0, len(overrides)+5)
	for _, name := range []string{"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ"} {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	for name, value := range overrides {
		environment = append(environment, name+"="+value)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, runner, script)
	command.Env, command.Dir = environment, workspace
	command.WaitDelay = 5 * time.Second
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("external Node gateway integration failed (%v):\n%s", err, output)
	}
	if len(output) != 0 {
		t.Logf("Node integration:\n%s", output)
	}
	if managementCalls.Load() == 0 {
		t.Fatal("external client did not call the real managed-user HTTP API")
	}
	if os.Getenv("AGENT_VAULT_NODE_VERIFY_CALLBACK") == "true" {
		completed, err := f.s.loadConnection(context.Background(), c.ID)
		if err != nil || completed.Status != "ready" || completed.Owner.ID != f.user {
			t.Fatal("external client did not complete the seeded native user's connection", err)
		}
	}
	provider.mu.Lock()
	revocations := provider.revocations
	provider.mu.Unlock()
	if revocations != 0 {
		t.Fatal("external client unexpectedly revoked the seeded connection")
	}
}
