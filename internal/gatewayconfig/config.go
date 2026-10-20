// Package gatewayconfig loads the headless gateway's narrowly scoped environment.
package gatewayconfig

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var namePattern = regexp.MustCompile(`^AGENT_VAULT_[A-Z0-9_]+$`)

// Load never evaluates shell expressions or imports non-Agent-Vault variables.
// Existing process variables take precedence over the file.
func Load(path string) error {
	if path != "" {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening env file: %w", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 4096), 1<<20)
		for line := 1; scanner.Scan(); line++ {
			text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(scanner.Text()), "export "))
			key, value, found := strings.Cut(text, "=")
			key = strings.TrimSpace(key)
			if !strings.HasPrefix(key, "AGENT_VAULT_") {
				continue
			}
			if !found || !namePattern.MatchString(key) {
				return fmt.Errorf("invalid Agent Vault assignment at env line %d", line)
			}
			value, err = parseValue(value)
			if err != nil {
				return fmt.Errorf("invalid value for %s at env line %d", key, line)
			}
			if _, exists := os.LookupEnv(key); !exists {
				if err := os.Setenv(key, value); err != nil {
					return fmt.Errorf("setting %s: %w", key, err)
				}
			}
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("reading env file: %w", err)
		}
	}
	for _, entry := range os.Environ() {
		key, path, _ := strings.Cut(entry, "=")
		// BOOTSTRAP_TOKEN_FILE is an output path, not a secret-file input.
		if !strings.HasPrefix(key, "AGENT_VAULT_") || !strings.HasSuffix(key, "_FILE") ||
			key == "AGENT_VAULT_BOOTSTRAP_TOKEN_FILE" || path == "" {
			continue
		}
		target := strings.TrimSuffix(key, "_FILE")
		if os.Getenv(target) != "" {
			return fmt.Errorf("set only one of %s and %s", target, key)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", key, err)
		}
		value := strings.TrimRight(string(data), "\r\n")
		if value == "" {
			return fmt.Errorf("%s contains an empty value", key)
		}
		if err := os.Setenv(target, value); err != nil {
			return fmt.Errorf("setting %s: %w", target, err)
		}
		if err := os.Unsetenv(key); err != nil {
			return err
		}
	}
	return nil
}

func parseValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if raw[0] == '\'' || raw[0] == '"' {
		quote := raw[0]
		end := 1
		for ; end < len(raw); end++ {
			if quote == '"' && raw[end] == '\\' {
				end++
				continue
			}
			if raw[end] == quote {
				break
			}
		}
		if end >= len(raw) {
			return "", fmt.Errorf("unterminated quote")
		}
		if rest := strings.TrimSpace(raw[end+1:]); rest != "" && !strings.HasPrefix(rest, "#") {
			return "", fmt.Errorf("unexpected trailing text")
		}
		if quote == '\'' {
			return raw[1:end], nil
		}
		return strconv.Unquote(raw[:end+1])
	}
	if i := strings.Index(raw, " #"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw), nil
}

func Headless() bool { return os.Getenv("AGENT_VAULT_HEADLESS") == "true" }

func Validate(host string, detach, passwordStdin bool) error {
	if v := os.Getenv("AGENT_VAULT_HEADLESS"); v != "" && v != "true" && v != "false" {
		return fmt.Errorf("AGENT_VAULT_HEADLESS must be true or false")
	}
	if !Headless() {
		return nil
	}
	if host != "127.0.0.1" {
		return fmt.Errorf("headless gateway listeners must bind to 127.0.0.1")
	}
	if detach {
		return fmt.Errorf("headless gateway requires foreground mode; use a service manager")
	}
	if !passwordStdin && os.Getenv("AGENT_VAULT_MASTER_PASSWORD") == "" {
		return fmt.Errorf("headless gateway requires AGENT_VAULT_MASTER_PASSWORD[_FILE] or --password-stdin")
	}
	if os.Getenv("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE") == "" {
		return fmt.Errorf("headless gateway requires AGENT_VAULT_BOOTSTRAP_TOKEN_FILE")
	}
	return nil
}
