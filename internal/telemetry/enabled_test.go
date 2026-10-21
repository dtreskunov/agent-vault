//go:build !notelemetry

package telemetry

import "testing"

func TestTelemetryRequiresOptIn(t *testing.T) {
	for _, test := range []struct {
		env  string
		flag bool
		want bool
	}{
		{"", false, false}, {"", true, true},
		{"true", false, true}, {"true", true, true},
		{"1", false, true}, {"false", true, false}, {"0", true, false},
		{"FALSE", true, false}, {"invalid", true, false},
	} {
		t.Setenv("AGENT_VAULT_TELEMETRY", test.env)
		if got := Enabled(test.flag); got != test.want {
			t.Errorf("env %q, flag %t: got %t, want %t", test.env, test.flag, got, test.want)
		}
	}
}
