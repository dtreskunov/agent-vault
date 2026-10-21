package gatewayconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "password")
	if err := os.WriteFile(secret, []byte("test-password\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_VAULT_TEST_KEEP", "process")
	for _, key := range []string{"AGENT_VAULT_TEST_QUOTED", "AGENT_VAULT_TEST_LITERAL", "AGENT_VAULT_TEST_SECRET", "AGENT_VAULT_TEST_SECRET_FILE"} {
		t.Setenv(key, "")
		os.Unsetenv(key)
	}
	t.Setenv("NANOCLAW_TEST_PRIVATE", "unchanged")
	env := filepath.Join(dir, ".env")
	text := "NANOCLAW_TEST_PRIVATE=never-import\nOTHER=$(do-not-run)\n" +
		"AGENT_VAULT_TEST_KEEP=file\nexport AGENT_VAULT_TEST_QUOTED=\"hello world\" # comment\n" +
		"AGENT_VAULT_TEST_LITERAL='${literal}'\nAGENT_VAULT_TEST_SECRET_FILE=" + secret + "\n"
	if err := os.WriteFile(env, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Load(env); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"AGENT_VAULT_TEST_KEEP": "process", "AGENT_VAULT_TEST_QUOTED": "hello world",
		"AGENT_VAULT_TEST_LITERAL": "${literal}", "AGENT_VAULT_TEST_SECRET": "test-password",
		"NANOCLAW_TEST_PRIVATE": "unchanged",
	} {
		if os.Getenv(key) != want {
			t.Errorf("unexpected value for %s", key)
		}
	}
}

func TestSecretFileErrors(t *testing.T) {
	t.Setenv("AGENT_VAULT_TEST_SECRET", "plain")
	t.Setenv("AGENT_VAULT_TEST_SECRET_FILE", "/missing")
	if err := Load(""); err == nil || !strings.Contains(err.Error(), "only one") {
		t.Fatal("expected conflicting input error")
	}
	t.Setenv("AGENT_VAULT_TEST_SECRET", "")
	if err := Load(""); err == nil || !strings.Contains(err.Error(), "reading") {
		t.Fatal("expected missing input error")
	}
}

func TestValidate(t *testing.T) {
	t.Setenv("AGENT_VAULT_HEADLESS", "true")
	t.Setenv("AGENT_VAULT_REVEAL_DISABLED", "true")
	t.Setenv("AGENT_VAULT_MASTER_PASSWORD", "test")
	t.Setenv("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE", "/tmp/test-output")
	if err := Validate("127.0.0.1", false, false); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"0.0.0.0", "::1", "localhost"} {
		if Validate(host, false, false) == nil {
			t.Errorf("accepted noncontract host %s", host)
		}
	}
	if Validate("127.0.0.1", true, false) == nil {
		t.Fatal("accepted detached mode")
	}
	t.Setenv("AGENT_VAULT_MASTER_PASSWORD", "")
	if Validate("127.0.0.1", false, false) == nil {
		t.Fatal("accepted unattended passwordless startup")
	}
}

func TestParseValue(t *testing.T) {
	for raw, want := range map[string]string{
		"plain # comment": "plain", "'hello world'": "hello world",
		`"escaped \"value\""`: `escaped "value"`, "'#' # comment": "#", "": "",
	} {
		got, err := parseValue(raw)
		if err != nil || got != want {
			t.Errorf("parseValue(%q) failed", raw)
		}
	}
	for _, raw := range []string{`"unterminated`, "'bad' trailing"} {
		if _, err := parseValue(raw); err == nil {
			t.Error("expected parse error")
		}
	}
}
