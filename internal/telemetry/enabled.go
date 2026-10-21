//go:build !notelemetry

package telemetry

import (
	"log/slog"
	"os"
	"strings"
)

// Enabled requires explicit opt-in. The environment takes precedence over flags.
func Enabled(flag bool) bool {
	switch strings.ToLower(os.Getenv("AGENT_VAULT_TELEMETRY")) {
	case "":
		return flag
	case "true", "1":
		return true
	case "false", "0":
		return false
	default:
		slog.Warn("invalid AGENT_VAULT_TELEMETRY value; telemetry disabled")
		return false
	}
}

func IsDisabled() bool { return !Enabled(false) }
