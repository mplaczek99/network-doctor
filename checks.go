package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Status is the binary outcome of a check. No Warn — nothing produces it, so
// exit-code and presentation semantics stay binary.
type Status int

const (
	Pass Status = iota
	Fail
)

// Result is what a Check reports: an outcome, a human-readable detail, and a
// remediation hint shown only on failure.
type Result struct {
	Status Status
	Detail string
	Fix    string
}

// Check is one diagnostic. Run must honor ctx (timeout/cancel) and never panic.
type Check struct {
	Name string
	Run  func(ctx context.Context) Result
}

// checkTimeout bounds every individual check. The model wires this into a
// per-check context.WithTimeout.
const checkTimeout = 4 * time.Second

// probeHost is the single host used by both name-resolution and internet
// checks, so a blocked unrelated host can't cause a false negative.
const probeHost = "connectivitycheck.gstatic.com"

// httpClient is dedicated to the internet check:
//   - Timeout bounds the whole request as a backstop to ctx.
//   - CheckRedirect refuses redirects: a captive portal 30x/200 must not be
//     mistaken for a real 204.
//   - Proxy nil: we test host connectivity, not a proxy.
//   - DialContext forces tcp4 for IPv4-only consistency.
var httpClient = &http.Client{
	Timeout: checkTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp4", addr)
		},
	},
}

// checks returns the fixed, ordered diagnostic chain. Order is the narrative:
// the first Fail read top-down is the earliest observed symptom.
func checks() []Check {
	return []Check{
		{Name: "Link", Run: checkLink},
		{Name: "IP address", Run: checkIP},
		{Name: "Gateway", Run: checkGateway},
		{Name: "Name resolution", Run: checkResolve},
		{Name: "Internet", Run: checkInternet},
	}
}

// checkLink: at least one non-loopback interface that is up and running.
func checkLink(ctx context.Context) Result {
	ifaces, err := net.Interfaces()
	if err != nil {
		return Result{Fail, "cannot list interfaces: " + err.Error(), "check permissions / network stack"}
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifi.Flags&net.FlagUp != 0 && ifi.Flags&net.FlagRunning != 0 {
			return Result{Pass, "interface " + ifi.Name + " is up", ""}
		}
	}
	return Result{Fail, "no interface up", "bring up an interface (cable/Wi-Fi) or `ip link set <iface> up`"}
}

// checkIP: at least one non-loopback, non-link-local IPv4 address.
func checkIP(ctx context.Context) Result {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return Result{Fail, "cannot list addresses: " + err.Error(), "check network stack"}
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip4 := ipnet.IP.To4()
		if ip4 == nil {
			continue // not IPv4 (rejects IPv6)
		}
		if ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
			continue // reject 127/8 and 169.254/16
		}
		return Result{Pass, "have IPv4 " + ip4.String(), ""}
	}
	return Result{Fail, "no usable IPv4 address", "no usable IPv4 (DHCP?) — check DHCP / static config"}
}

// checkGateway: an IPv4 default route exists. Distinguishes an unreadable route
// table (internal error) from a readable table with no default route.
func checkGateway(ctx context.Context) Result {
	gw, found, err := defaultRoute()
	if err != nil {
		return Result{Fail, "cannot read route table: " + err.Error(), "internal: /proc/net/route unreadable"}
	}
	if !found {
		return Result{Fail, "no IPv4 default route", "add a default route / check gateway (DHCP?)"}
	}
	return Result{Pass, "default route via " + gw, ""}
}

// checkResolve: resolve the same host the internet check hits, IPv4-only.
// Honestly tests system name resolution (/etc/hosts + resolvers), not pure DNS.
func checkResolve(ctx context.Context) Result {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", probeHost)
	if err != nil {
		return Result{Fail, "cannot resolve " + probeHost + ": " + err.Error(), "name resolution failing — check /etc/resolv.conf / DNS"}
	}
	if len(ips) == 0 {
		return Result{Fail, "no IPv4 address for " + probeHost, "name resolution failing — no A record returned"}
	}
	return Result{Pass, probeHost + " resolves to " + ips[0].String(), ""}
}

// checkInternet: HTTP GET the generate_204 endpoint; require status exactly 204.
// A captive portal returning 200+body (or a redirect) is correctly a Fail.
func checkInternet(ctx context.Context) Result {
	url := "http://" + probeHost + "/generate_204"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{Fail, "cannot build request: " + err.Error(), "internal error"}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return Result{Fail, "request failed: " + err.Error(), "no internet — check upstream connectivity"}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return Result{Fail, fmt.Sprintf("unexpected status %d", resp.StatusCode), "no internet / captive portal — open a browser to sign in"}
	}
	return Result{Pass, "reached internet (204)", ""}
}
