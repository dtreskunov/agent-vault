//go:build notelemetry

package telemetry

type Telemetry struct{}

func New(string, string) *Telemetry { return nil }

func (*Telemetry) CaptureEvent(string, string, map[string]string) {}
func (*Telemetry) Identify(string, map[string]string)             {}
func (*Telemetry) Alias(string, string)                           {}
func (*Telemetry) Close()                                         {}

func Enabled(bool) bool { return false }
func IsDisabled() bool  { return true }
func MachineID() string { return "" }
