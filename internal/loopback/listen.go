package loopback

import (
	"fmt"
	"net"
)

const AutomaticAddress = "127.0.0.1:0"

// Listen binds only to a loopback interface. For the automatic default it
// falls back to IPv6 when an older or hardened host disables IPv4 loopback.
func Listen(address string) (net.Listener, error) {
	listener, err := net.Listen("tcp", address)
	if err == nil || address != AutomaticAddress {
		return listener, err
	}

	fallback, fallbackErr := net.Listen("tcp6", "[::1]:0")
	if fallbackErr == nil {
		return fallback, nil
	}
	return nil, fmt.Errorf("IPv4 loopback: %v; IPv6 loopback: %v", err, fallbackErr)
}
