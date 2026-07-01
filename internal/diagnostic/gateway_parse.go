package diagnostic

import (
	"bufio"
	"io"
	"net"
	"strconv"
	"strings"
)

// parseDarwinRoute extracts the gateway from `route -n get -inet default`
// output: the "gateway:" line's value, accepted only when it parses as IPv4
// (rejects link#N and interface names).
func parseDarwinRoute(r io.Reader) (string, bool, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(k) != "gateway" {
			continue
		}
		gw := strings.TrimSpace(v)
		if ip := net.ParseIP(gw); ip != nil && ip.To4() != nil {
			return gw, true, nil
		}
		return "", false, nil
	}
	return "", false, sc.Err()
}

// parseWindowsRoute extracts the default gateway from `route print -4`. A row
// counts only when it has the five-column Active Routes shape — destination
// 0.0.0.0, netmask 0.0.0.0, IPv4 gateway, IPv4 interface, numeric metric —
// which structurally excludes the four-column Persistent Routes section and
// "On-link" rows without any locale-dependent header matching. Lowest metric
// wins.
func parseWindowsRoute(r io.Reader) (string, bool, error) {
	sc := bufio.NewScanner(r)
	best, found := "", false
	bestMetric := int64(0)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 5 || f[0] != "0.0.0.0" || f[1] != "0.0.0.0" {
			continue
		}
		gw, ifip := net.ParseIP(f[2]), net.ParseIP(f[3])
		if gw == nil || gw.To4() == nil || ifip == nil || ifip.To4() == nil {
			continue
		}
		metric, err := strconv.ParseInt(f[4], 10, 64)
		if err != nil {
			continue
		}
		if !found || metric < bestMetric {
			best, found, bestMetric = f[2], true, metric
		}
	}
	if err := sc.Err(); err != nil {
		return "", false, err
	}
	return best, found, nil
}
