package gatewayconfig

import "testing"

func TestHeadlessRequiresWriteOnlyCredentials(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "true")
	t.Setenv("AGENT_VAULT_MASTER_PASSWORD", "test")
	t.Setenv("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE", "/tmp/test-output")
	for _, value := range []string{"", "false", "invalid"} {
		t.Setenv("AGENT_VAULT_REVEAL_DISABLED", value)
		if err := Validate("127.0.0.1", false, false); err == nil {
			t.Fatal("headless startup accepted an unprotected instance")
		}
	}
}
