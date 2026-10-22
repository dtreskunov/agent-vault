package mcpauth

import (
	"context"
	"flag"
	"net"
	"testing"
	"time"
)

var liveOAuth = flag.Bool("live-oauth", false, "probe public GitHub OAuth metadata without credentials")

func TestLiveGitHubProbe(t *testing.T) {
	if !*liveOAuth {
		t.Skip("opt-in public metadata probe")
	}
	resolver := net.DefaultResolver
	m, _, vault := testManager(t)
	net.DefaultResolver = resolver
	// The ordinary fixture's resolver is intentionally loopback-only.
	m.client = guardedClient()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	probe, err := m.Probe(ctx, vault, "https://api.githubcopilot.com/mcp/")
	if err != nil {
		t.Fatal(err)
	}
	if !probe.OAuth || probe.Code != "registration_unsupported" || probe.Provider != "github" {
		t.Fatalf("unexpected probe metadata: %+v", probe)
	}
}
