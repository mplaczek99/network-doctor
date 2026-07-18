package diagnostic

import (
	"net"
	"strconv"
)

// Diagnose computes the plain-English verdict from current-generation native
// probe state only (tool output never feeds in). First-fail ordering + combination
// rules. Returns "Running diagnostics…" until every probe in order has a result.
// A completed run always returns a verdict.
func Diagnose(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) string {
	for _, id := range order {
		if _, ok := res[id]; !ok {
			return "Running diagnostics…"
		}
	}
	pass := func(id ProbeID) bool { return res[id].Status == StatusPass }
	fail := func(id ProbeID) bool { return res[id].Status == StatusFail }
	warn := func(id ProbeID) bool { return res[id].Status == StatusWarn }
	has := func(id ProbeID) bool { _, ok := res[id]; return ok }
	directOK := func() bool {
		r := res[ProbeInternet]
		return r.Status == StatusPass || r.Status == StatusWarn && !r.downgraded
	}

	if fail(ProbeIface) {
		return "No usable network interface — the link is down."
	}

	prx := has(ProbeProxy) && pass(ProbeProxy)
	prxDown := has(ProbeProxy) && fail(ProbeProxy)

	if t == nil {
		ip, dn := pass(ProbeInternet), pass(ProbeDNS)
		switch {
		case ip && dn && prxDown:
			return "Online directly — but the configured environment proxy is unreachable, so apps that honor HTTP(S)_PROXY will fail."
		case ip && dn:
			return "Online — direct TCP egress and DNS both work."
		case warn(ProbeInternet) && res[ProbeInternet].downgraded && dn && prx:
			return "Online via the environment proxy — direct egress is blocked (proxy-only network)."
		case warn(ProbeInternet) && dn:
			return "Online but degraded — direct egress is impaired (see the ! row for details)."
		case warn(ProbeInternet) && !dn:
			return "Internet egress works (degraded) but DNS resolution is failing."
		case ip && !dn:
			return "Internet egress works but DNS resolution is failing."
		case !ip && dn:
			return "DNS resolves but there's no direct TCP egress (proxy-only or filtered network?)."
		default:
			return "Offline — neither direct egress nor DNS is working."
		}
	}

	host := t.Host
	hp := net.JoinHostPort(host, strconv.Itoa(t.Port)) // brackets IPv6 literals
	switch {
	case fail(ProbeDNS):
		v := "Cannot resolve " + host + " — DNS failure."
		if directOK() {
			v += " (The general internet is reachable.)"
		}
		return v
	case fail(ProbeTargetTCP):
		if directOK() {
			return hp + " is unreachable though DNS and the general internet work — remote port closed, firewall, or VPN routing."
		}
		if prx {
			return hp + " is unreachable directly, but the environment proxy has egress — proxy-only network; route traffic through the proxy."
		}
		return host + " resolves but neither it nor the general internet is reachable — local egress problem."
	case has(ProbeTLS) && fail(ProbeTLS):
		return "TCP reaches " + hp + " but the TLS handshake fails — bad/expired cert, clock skew, or MITM proxy."
	case has(ProbeHTTPS) && fail(ProbeHTTPS):
		return "TLS is fine but no HTTPS response from " + hp + " — application-layer or proxy block."
	case has(ProbeHTTP) && fail(ProbeHTTP):
		if t.Proto == ProtoTLSHTTP {
			return "HTTPS works but no HTTP response from " + net.JoinHostPort(host, "80") + " — the redirect/plain-HTTP endpoint may be blocked."
		}
		return "No HTTP response from " + hp + " — application-layer or proxy block."
	case (has(ProbeSSH) && fail(ProbeSSH)) || (has(ProbeSMTP) && fail(ProbeSMTP)):
		return hp + " accepts TCP but the service banner check failed."
	case (has(ProbeSSH) && warn(ProbeSSH)) || (has(ProbeSMTP) && warn(ProbeSMTP)):
		return hp + " accepts TCP but sent no service banner."
	case fail(ProbeInternet) || (warn(ProbeInternet) && res[ProbeInternet].downgraded):
		return "The target works but direct internet egress is blocked (proxy-only or filtered network?)."
	case prxDown && directOK():
		return "The target and direct egress work, but the configured environment proxy is unreachable — apps that honor HTTP(S)_PROXY will fail."
	case warn(ProbeInternet):
		return "The target works but direct internet egress is degraded (see the ! row for details)."
	default:
		return "All checks passed — " + hp + " looks healthy."
	}
}

// DowngradeEgress rewrites a direct-egress failure to Warn once another path
// has proven the network usable: the target TCP connect succeeded, the
// environment proxy tunnels traffic, or — in generic mode, where DNS is the
// only other network path — DNS answered. Call it once, after every probe has
// a result; degraded-but-functional must not read as an outage.
func DowngradeEgress(res map[ProbeID]ProbeResult) {
	r, ok := res[ProbeInternet]
	if !ok || r.Status != StatusFail {
		return
	}
	other, hasTarget := res[ProbeTargetTCP]
	if !hasTarget {
		other = res[ProbeDNS]
	}
	prx, hasProxy := res[ProbeProxy]
	otherOK := other.Status == StatusPass || other.Status == StatusWarn
	proxyOK := hasProxy && prx.Status == StatusPass
	if !otherOK && !proxyOK {
		return
	}
	r.Status = StatusWarn
	r.downgraded = true
	if otherOK {
		r.Detail += " — but another path works"
	} else {
		r.Detail += " — but the environment proxy works"
	}
	res[ProbeInternet] = r
}
