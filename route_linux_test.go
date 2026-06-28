//go:build linux

package main

import (
	"io"
	"strings"
	"testing"
)

const routeHeader = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"

// gw 0101A8C0 (little-endian) decodes to 192.168.1.1; 0201A8C0 -> 192.168.1.2.
func TestParseDefaultRoute(t *testing.T) {
	tests := []struct {
		name      string
		in        string
		wantIP    string
		wantFound bool
	}{
		{
			name:      "normal default route",
			in:        routeHeader + "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			wantIP:    "192.168.1.1",
			wantFound: true,
		},
		{
			name:      "no default route (connected route only)",
			in:        routeHeader + "eth0\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n",
			wantFound: false,
		},
		{
			name:      "header only",
			in:        routeHeader,
			wantFound: false,
		},
		{
			name:      "empty",
			in:        "",
			wantFound: false,
		},
		{
			name: "malformed short row is skipped, default still found",
			in: routeHeader +
				"garbage row too short\n" +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			wantIP:    "192.168.1.1",
			wantFound: true,
		},
		{
			name: "lowest metric wins",
			in: routeHeader +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\t0\t0\t0\n" +
				"wlan0\t00000000\t0201A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			wantIP:    "192.168.1.2",
			wantFound: true,
		},
		{
			name: "metric tie returns first",
			in: routeHeader +
				"eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n" +
				"wlan0\t00000000\t0201A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n",
			wantIP:    "192.168.1.1",
			wantFound: true,
		},
		{
			name:      "destination zero but nonzero mask (0.0.0.0/8) is not default",
			in:        routeHeader + "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t000000FF\t0\t0\t0\n",
			wantFound: false,
		},
		{
			name:      "default candidate without RTF_UP is skipped",
			in:        routeHeader + "eth0\t00000000\t0101A8C0\t0000\t0\t0\t100\t00000000\t0\t0\t0\n",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, found, err := parseDefaultRoute(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v", found, tt.wantFound)
			}
			if found && ip != tt.wantIP {
				t.Fatalf("ip = %q, want %q", ip, tt.wantIP)
			}
		})
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

// A read error must surface as err (distinct from "no default route").
func TestParseDefaultRouteReadError(t *testing.T) {
	ip, found, err := parseDefaultRoute(errReader{})
	if err == nil {
		t.Fatal("expected a read error, got nil")
	}
	if found || ip != "" {
		t.Fatalf("on error want (\"\", false), got (%q, %v)", ip, found)
	}
}
