//go:build linux

package diagnostic

import "testing"

func TestDecodeGatewayHex(t *testing.T) {
	// Valid little-endian field decodes to dotted IPv4.
	if got, err := decodeGatewayHex("0101A8C0"); err != nil || got != "192.168.1.1" {
		t.Errorf("decodeGatewayHex(0101A8C0) = (%q,%v), want 192.168.1.1", got, err)
	}
	// All-zero gateway (an on-link default route) decodes to 0.0.0.0.
	if got, err := decodeGatewayHex("00000000"); err != nil || got != "0.0.0.0" {
		t.Errorf("decodeGatewayHex(zero) = (%q,%v), want 0.0.0.0", got, err)
	}
	// Non-hex input is an error, not a panic.
	if _, err := decodeGatewayHex("ZZZZ"); err == nil {
		t.Error("decodeGatewayHex(non-hex) should error")
	}
	// Wrong byte length (2 bytes, not 4) is an error.
	if _, err := decodeGatewayHex("0101"); err == nil {
		t.Error("decodeGatewayHex(short) should error")
	}
}
