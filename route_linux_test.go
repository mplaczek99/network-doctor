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

const arpHeader = "IP address       HW type     Flags       HW address            Mask     Device\n"

// parseARPComplete: a complete entry (ATF_COM 0x2, non-zero MAC) for the gateway
// IP is reachable; incomplete flag, zero MAC, or absent IP is not.
func TestParseARPComplete(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ip   string
		want bool
	}{
		{
			name: "complete entry for gateway",
			in:   arpHeader + "192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n",
			ip:   "192.168.1.1",
			want: true,
		},
		{
			name: "incomplete entry (flags 0x0) is not reachable",
			in:   arpHeader + "192.168.1.1      0x1         0x0         00:00:00:00:00:00     *        wlan0\n",
			ip:   "192.168.1.1",
			want: false,
		},
		{
			name: "complete flag but zero MAC is not reachable",
			in:   arpHeader + "192.168.1.1      0x1         0x2         00:00:00:00:00:00     *        wlan0\n",
			ip:   "192.168.1.1",
			want: false,
		},
		{
			name: "gateway IP absent from table",
			in:   arpHeader + "192.168.1.9      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0\n",
			ip:   "192.168.1.1",
			want: false,
		},
		{
			name: "header only",
			in:   arpHeader,
			ip:   "192.168.1.1",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseARPComplete(strings.NewReader(tt.in), tt.ip)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
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
