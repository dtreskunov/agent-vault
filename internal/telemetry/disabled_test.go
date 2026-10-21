//go:build notelemetry

package telemetry

import "testing"

func TestBuildTagCannotEnableTelemetry(t *testing.T) {
	t.Setenv("AGENT_VAULT_TELEMETRY", "true")
	if Enabled(true) || !IsDisabled() || MachineID() != "" || New("synthetic-key", "test") != nil {
		t.Fatal("notelemetry build retained telemetry functionality")
	}
	var disabled *Telemetry
	disabled.CaptureEvent("unused", "unused", nil)
	disabled.Identify("unused", nil)
	disabled.Alias("unused", "unused")
	disabled.Close()
}
