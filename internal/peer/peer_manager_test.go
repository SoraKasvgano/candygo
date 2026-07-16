package peer

import (
	"net"
	"testing"
)

func TestIsStunResponseUsesPortAndContent(t *testing.T) {
	manager := &PeerManager{
		stun: Stun{
			address: &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 3478},
		},
	}

	responseFromAnotherIP := &net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 3478}
	if !manager.isStunResponse([]byte{0x01, 0x01}, responseFromAnotherIP) {
		t.Fatal("expected STUN success response content from the configured port to be accepted")
	}

	wrongPort := &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 3479}
	if manager.isStunResponse([]byte{0x01, 0x01}, wrongPort) {
		t.Fatal("expected STUN response from a different port to be rejected")
	}

	if manager.isStunResponse([]byte{0x01, 0x00}, responseFromAnotherIP) {
		t.Fatal("expected non-STUN-success content to be rejected")
	}
}
