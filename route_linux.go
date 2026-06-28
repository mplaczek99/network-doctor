//go:build linux

package main

import (
	"bufio"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// rtfUp is the RTF_UP flag in /proc/net/route's Flags column: the route is up.
const rtfUp = 0x1

// atfCom is the ATF_COM flag in /proc/net/arp's Flags column: a complete entry
// (we have the gateway's MAC, i.e. we've talked to it at L2).
const atfCom = 0x2

// zeroMAC is an incomplete/unresolved ARP hardware address.
const zeroMAC = "00:00:00:00:00:00"

// gatewayReachable reports whether the default gateway has a complete ARP entry
// — proof of recent L2 contact, without ICMP/raw sockets. No default route or no
// entry -> (false, nil); an unreadable table -> err.
func gatewayReachable() (bool, error) {
	gw, found, err := defaultRoute()
	if err != nil || !found {
		return false, err
	}
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return false, err
	}
	defer f.Close()
	return parseARPComplete(f, gw)
}

// parseARPComplete scans /proc/net/arp for ip with ATF_COM set and a non-zero
// MAC. Never panics; malformed rows are skipped.
//
// Columns: IP address  HW type  Flags  HW address  Mask  Device
func parseARPComplete(r io.Reader, ip string) (bool, error) {
	sc := bufio.NewScanner(r)
	headerSkipped := false
	for sc.Scan() {
		if !headerSkipped {
			headerSkipped = true // first line is the column header
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 || fields[0] != ip {
			continue
		}
		flags, err := strconv.ParseInt(fields[2], 0, 64) // "0x2"
		if err != nil {
			continue
		}
		if flags&atfCom != 0 && fields[3] != zeroMAC {
			return true, nil
		}
	}
	return false, sc.Err()
}

// defaultRoute opens the kernel IPv4 routing table and returns the gateway of
// the default route, if any. An open/read error is returned as err; a readable
// table with no default route is (\"\", false, nil).
func defaultRoute() (ip string, found bool, err error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", false, err
	}
	defer f.Close()
	return parseDefaultRoute(f)
}

// parseDefaultRoute parses /proc/net/route. A default route requires
// Destination (col 1) == 00000000 AND Mask/Genmask (col 7) == 00000000 (a
// nonzero mask like 0.0.0.0/8 is NOT default) AND RTF_UP set in Flags (col 3).
// Among candidates it picks the lowest Metric. It never panics; malformed rows
// are skipped. Parse failure -> err; valid table, no default -> found==false.
//
// Columns: Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
func parseDefaultRoute(r io.Reader) (ip string, found bool, err error) {
	sc := bufio.NewScanner(r)
	headerSkipped := false
	bestMetric := int64(-1)
	for sc.Scan() {
		line := sc.Text()
		if !headerSkipped {
			headerSkipped = true // first line is the column header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 11 {
			continue // malformed / short row — skip, don't fail
		}
		dest, mask, flagsHex, metricStr := fields[1], fields[7], fields[3], fields[6]
		if dest != "00000000" || mask != "00000000" {
			continue
		}
		flags, ferr := strconv.ParseInt(flagsHex, 16, 64)
		if ferr != nil || flags&rtfUp == 0 {
			continue
		}
		metric, merr := strconv.ParseInt(metricStr, 10, 64)
		if merr != nil {
			continue
		}
		gw, gerr := decodeGatewayHex(fields[2])
		if gerr != nil {
			continue // unparseable gateway — skip this row
		}
		if !found || metric < bestMetric {
			ip, found, bestMetric = gw, true, metric
		}
	}
	if serr := sc.Err(); serr != nil {
		return "", false, serr
	}
	return ip, found, nil
}

// decodeGatewayHex turns the little-endian 8-hex-digit Gateway field into a
// dotted IPv4 string.
func decodeGatewayHex(h string) (string, error) {
	b, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	if len(b) != 4 {
		return "", strconv.ErrSyntax
	}
	return net.IPv4(b[3], b[2], b[1], b[0]).String(), nil
}
