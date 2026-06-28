//go:build linux

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
)

// rtfUp is the RTF_UP flag in /proc/net/route's Flags column: the route is up.
const rtfUp = 0x1

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
	v := binary.LittleEndian.Uint32(b)
	var ip [4]byte
	binary.BigEndian.PutUint32(ip[:], v)
	return net.IP(ip[:]).String(), nil
}
