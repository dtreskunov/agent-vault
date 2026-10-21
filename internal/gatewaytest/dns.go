// Package gatewaytest provides local fixtures for gateway integration tests.
package gatewaytest

import (
	"context"
	"errors"
	"net"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// UseLoopbackDNS keeps non-parallel tests independent of the host's DNS aliases.
func UseLoopbackDNS(t testing.TB) {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if err := query.Unpack(buffer[:n]); err != nil {
				t.Errorf("decoding test DNS query: %v", err)
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{
				ID: query.ID, Response: true, Authoritative: true, RecursionAvailable: true,
			}, Questions: query.Questions}
			for _, question := range query.Questions {
				if question.Name.String() != "localhost.localdomain." {
					response.Header.RCode = dnsmessage.RCodeNameError
					continue
				}
				if question.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{
						Header: dnsmessage.ResourceHeader{Name: question.Name, Class: dnsmessage.ClassINET, TTL: 60},
						Body:   &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}},
					})
				}
			}
			packet, err := response.Pack()
			if err != nil {
				t.Errorf("encoding test DNS reply: %v", err)
				continue
			}
			if _, err := listener.WriteTo(packet, peer); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Errorf("sending test DNS reply: %v", err)
			}
		}
	}()
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", listener.LocalAddr().String())
		},
	}
	t.Cleanup(func() {
		net.DefaultResolver = original
		listener.Close()
		<-done
	})
}
