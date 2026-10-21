package gatewaytest

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestLoopbackDNSWithoutHostAliases(t *testing.T) {
	UseLoopbackDNS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := net.DefaultResolver.Dial(ctx, "udp", "unused")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	connection.SetDeadline(time.Now().Add(2 * time.Second))
	name, err := dnsmessage.NewName("localhost.localdomain.")
	if err != nil {
		t.Fatal(err)
	}
	query, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 1},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
	}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write(query); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 512)
	n, err := connection.Read(buffer)
	if err != nil {
		t.Fatal(err)
	}
	var reply dnsmessage.Message
	if err := reply.Unpack(buffer[:n]); err != nil || len(reply.Answers) != 1 {
		t.Fatal("test DNS responder did not supply its own loopback answer")
	}
	answer, ok := reply.Answers[0].Body.(*dnsmessage.AResource)
	if !ok || answer.A != [4]byte{127, 0, 0, 1} {
		t.Fatal("test DNS did not return the intended loopback address")
	}
}
