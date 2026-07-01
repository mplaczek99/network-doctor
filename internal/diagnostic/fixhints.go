package diagnostic

// Per-GOOS fix hints for failures whose remedy is OS-specific. goos is a
// parameter so all branches are testable from one OS.

func ifaceFix(goos string) string {
	switch goos {
	case "darwin":
		return "bring up an interface — turn on Wi-Fi or plug in a cable (`networksetup -listallhardwareports`)"
	case "windows":
		return "bring up an interface — enable Wi-Fi/Ethernet in Settings → Network & internet"
	default:
		return "bring up an interface (cable/Wi-Fi) or `ip link set <iface> up`"
	}
}

func dnsFix(goos string) string {
	switch goos {
	case "darwin":
		return "name resolution failing — check DNS in System Settings → Network (`networksetup -getdnsservers Wi-Fi`)"
	case "windows":
		return "name resolution failing — check DNS in `ipconfig /all` or Settings → Network & internet"
	default:
		return "name resolution failing — check /etc/resolv.conf / DNS"
	}
}
