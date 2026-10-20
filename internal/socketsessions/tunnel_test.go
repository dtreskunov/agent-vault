package socketsessions

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBlindTunnelPreservesTLS(t *testing.T) {
	f := setup(t)
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "tunnel")
	item := f.create(t)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "end-to-end")
	}))
	defer upstream.Close()
	// Trust only the upstream certificate, not the gateway CA.
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	client := socketClient(t, item.SocketPath, f.ca)
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "end-to-end" ||
		!resp.TLS.PeerCertificates[0].Equal(upstream.Certificate()) {
		t.Fatal("unmatched TLS connection was intercepted")
	}
	transport.CloseIdleConnections()
	select {
	case record := <-f.records:
		if record.Method != "CONNECT" || record.Status != 200 || record.VaultID != f.vault.ID {
			t.Fatal("tunnel audit record missing")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel did not finish")
	}
	if text := f.logs.text(); !strings.Contains(text, `"decision":"tunnel"`) ||
		!strings.Contains(text, `"bytes_sent":`) || !strings.Contains(text, `"duration_ms":`) {
		t.Fatal("tunnel metadata was not logged")
	}
}

func TestBlindTunnelBufferedBytesAndHalfClose(t *testing.T) {
	f := setup(t)
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "tunnel")
	item := f.create(t)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		body, err := io.ReadAll(conn)
		if err == nil {
			_, err = conn.Write(append([]byte("echo:"), body...))
		}
		done <- err
	}()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: item.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	target := upstream.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nbuffered-payload", target, target)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("tunnel not established")
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(reader)
	if err != nil || string(body) != "echo:buffered-payload" {
		t.Fatalf("buffered bytes or half-close lost: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-f.records:
	case <-time.After(time.Second):
		t.Fatal("no tunnel record")
	}
	for _, line := range strings.Split(strings.TrimSpace(f.logs.text()), "\n") {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		if record["decision"] == "tunnel" &&
			(record["bytes_sent"] != float64(len("buffered-payload")) || record["bytes_received"] != float64(len("echo:buffered-payload"))) {
			t.Fatal("incorrect tunnel byte accounting")
		}
	}
}

func TestDenyAndNetworkGuardBeforeHijack(t *testing.T) {
	f := setup(t)
	item := f.create(t)
	for _, test := range []struct {
		mode, target, private string
		want                  int
	}{
		{"deny", "unmatched.example.com:443", "true", 403},
		{"tunnel", "127.0.0.1:443", "false", 502},
		{"tunnel", "169.254.169.254:80", "true", 502},
		{"tunnel", "example.com:0", "true", 400},
		{"tunnel", "example.com:65536", "true", 400},
	} {
		t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", test.mode)
		t.Setenv("AGENT_VAULT_ALLOW_PRIVATE_RANGES", test.private)
		t.Setenv("AGENT_VAULT_NETWORK_ALLOWLIST", "")
		conn, err := net.Dial("unix", item.SocketPath)
		if err != nil {
			t.Fatal(err)
		}

		conn.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", test.target, test.target)
		resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
		conn.Close()
		if err != nil || resp.StatusCode != test.want {
			t.Fatalf("%s %s failed, err %v", test.mode, test.target, err)
		}
	}
	// A path-scoped service prevents blindly tunnelling all other paths on that host.
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "deny")
	if _, err := f.db.SetBrokerConfig(context.Background(), f.vault.ID,
		`[{"name":"scoped","host":"example.com/private/*","auth":{"type":"passthrough"}}]`); err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("unix", item.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Second))
	fmt.Fprint(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"})
	if err != nil || resp.StatusCode != 200 {
		t.Fatal("path-scoped service was treated as unmatched")
	}
}

func TestDeleteHalfClosedBlindTunnel(t *testing.T) {
	f := setup(t)
	t.Setenv("AGENT_VAULT_UNMATCHED_HOST_MODE", "tunnel")
	item := f.create(t)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: item.SocketPath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	target := upstream.Addr().String()
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: "CONNECT"}); err != nil {
		t.Fatal(err)
	}
	var peer net.Conn
	select {
	case peer = <-accepted:
		defer peer.Close()
	case <-time.After(time.Second):
		t.Fatal("upstream was not dialed")
	}
	conn.CloseWrite()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAll(peer); err != nil {
		t.Fatal("half-close was not propagated")
	}
	if w := f.call("DELETE", "/v1/socket-sessions/"+item.ID, ""); w.Code != 204 {
		t.Fatalf("deleting half-closed tunnel: %d", w.Code)
	}
	select {
	case <-f.records:
	case <-time.After(time.Second):
		t.Fatal("half-closed tunnel leaked after deletion")
	}
}
