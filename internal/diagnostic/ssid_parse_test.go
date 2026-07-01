package diagnostic

import "testing"

func TestParseAirportSSID(t *testing.T) {
	if got := parseAirportSSID("Current Wi-Fi Network: HomeNet 5G\n"); got != "HomeNet 5G" {
		t.Errorf("got %q, want HomeNet 5G", got)
	}
	if got := parseAirportSSID("You are not associated with an AirPort network.\n"); got != "" {
		t.Errorf("not associated: got %q, want empty", got)
	}
	if got := parseAirportSSID("networksetup: en5 is not a Wi-Fi interface.\n"); got != "" {
		t.Errorf("non-wifi iface: got %q, want empty", got)
	}
}

// Two-adapter capture: the block is selected by *value* match on the interface
// name, and the exact "SSID" key excludes BSSID.
const netshTwoAdapters = "There are 2 interfaces on the system:\r\n" +
	"\r\n" +
	"    Name                   : Wi-Fi\r\n" +
	"    Description            : Intel(R) Wi-Fi 6 AX201 160MHz\r\n" +
	"    GUID                   : 12345678-1234-1234-1234-123456789abc\r\n" +
	"    Physical address       : aa:bb:cc:dd:ee:ff\r\n" +
	"    State                  : connected\r\n" +
	"    SSID                   : HomeNet\r\n" +
	"    BSSID                  : 11:22:33:44:55:66\r\n" +
	"    Radio type             : 802.11ax\r\n" +
	"\r\n" +
	"    Name                   : Wi-Fi 2\r\n" +
	"    State                  : connected\r\n" +
	"    SSID                   : OtherNet\r\n" +
	"    BSSID                  : 66:55:44:33:22:11\r\n"

// Non-English capture (German labels): the localized "Name" label is never
// consulted — the block still matches by value, and "SSID" is untranslated.
const netshGerman = "Es gibt 1 Schnittstelle auf dem System:\r\n" +
	"\r\n" +
	"    Name                   : WLAN\r\n" +
	"    Beschreibung           : Intel Wireless\r\n" +
	"    Status                 : Verbunden\r\n" +
	"    SSID                   : CafeNetz\r\n" +
	"    BSSID                  : aa:bb:cc:11:22:33\r\n"

func TestParseNetshSSID(t *testing.T) {
	if got := parseNetshSSID(netshTwoAdapters, "Wi-Fi"); got != "HomeNet" {
		t.Errorf("Wi-Fi: got %q, want HomeNet", got)
	}
	if got := parseNetshSSID(netshTwoAdapters, "Wi-Fi 2"); got != "OtherNet" {
		t.Errorf("Wi-Fi 2: got %q, want OtherNet", got)
	}
	// No fallback: an Ethernet/VPN iface must never acquire a Wi-Fi SSID.
	if got := parseNetshSSID(netshTwoAdapters, "Ethernet"); got != "" {
		t.Errorf("Ethernet: got %q, want empty", got)
	}
	if got := parseNetshSSID(netshGerman, "WLAN"); got != "CafeNetz" {
		t.Errorf("German locale: got %q, want CafeNetz", got)
	}
	if got := parseNetshSSID("", "Wi-Fi"); got != "" {
		t.Errorf("empty output: got %q, want empty", got)
	}
}
