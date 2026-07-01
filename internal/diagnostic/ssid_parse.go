package diagnostic

import "strings"

// parseAirportSSID parses `networksetup -getairportnetwork <iface>`:
// "Current Wi-Fi Network: <name>". Anything else (errors, "not associated",
// future tooling churn) yields "".
func parseAirportSSID(out string) string {
	for _, ln := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "Current Wi-Fi Network:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// parseNetshSSID extracts iface's SSID from `netsh wlan show interfaces`.
// Blocks are blank-line separated; a block matches only when some line's
// *value* (text after the first ':', trimmed) equals iface — value comparison,
// so the localized "Name" label is never consulted. Within the matching block
// the line whose key is exactly "SSID" wins (netsh does not translate that
// label; the exact match excludes "BSSID"). No fallback: netsh lists only WLAN
// interfaces, so a wired/VPN iface never acquires a Wi-Fi SSID.
func parseNetshSSID(out, iface string) string {
	var blocks [][]string
	var cur []string
	for _, ln := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(ln) == "" {
			if len(cur) > 0 {
				blocks = append(blocks, cur)
				cur = nil
			}
			continue
		}
		cur = append(cur, ln)
	}
	if len(cur) > 0 {
		blocks = append(blocks, cur)
	}
	for _, block := range blocks {
		if !blockHasValue(block, iface) {
			continue
		}
		for _, ln := range block {
			if k, v, ok := strings.Cut(ln, ":"); ok && strings.TrimSpace(k) == "SSID" {
				return strings.TrimSpace(v)
			}
		}
	}
	return ""
}

func blockHasValue(block []string, want string) bool {
	for _, ln := range block {
		if _, v, ok := strings.Cut(ln, ":"); ok && strings.TrimSpace(v) == want {
			return true
		}
	}
	return false
}
