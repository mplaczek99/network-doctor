package diagnostic

import "fmt"

// Diagnose computes the plain-English verdict from current-generation native
// probe state only (tool facts never feed in). First-fail ordering + combination
// rules. Returns "Running diagnostics…" until every probe in order has a result.
// A completed target with no failures returns an empty string because the
// successful probe rows already communicate the outcome.
func Diagnose(t *Target, order []ProbeID, res map[ProbeID]ProbeResult) string {
	for _, id := range order {
		if _, ok := res[id]; !ok {
			return "Running diagnostics…"
		}
	}
	pass := func(id ProbeID) bool { return res[id].Status == StatusPass }
	fail := func(id ProbeID) bool { return res[id].Status == StatusFail }
	has := func(id ProbeID) bool { _, ok := res[id]; return ok }

	if fail(ProbeIface) {
		return "No usable network interface — the link is down."
	}

	if t == nil {
		ip, dn := pass(ProbeInternet), pass(ProbeDNS)
		switch {
		case ip && dn:
			return "Online — direct TCP egress and DNS both work."
		case ip && !dn:
			return "Internet egress works but DNS resolution is failing."
		case !ip && dn:
			return "DNS resolves but there's no direct TCP egress (proxy-only or filtered network?)."
		default:
			return "Offline — neither direct egress nor DNS is working."
		}
	}

	host := t.Host
	hp := fmt.Sprintf("%s:%d", host, t.Port)
	switch {
	case fail(ProbeDNS):
		v := "Cannot resolve " + host + " — DNS failure."
		if pass(ProbeInternet) {
			v += " (The general internet is reachable.)"
		}
		return v
	case fail(ProbeTargetTCP):
		if pass(ProbeInternet) {
			return hp + " is unreachable though DNS and the general internet work — remote port closed, firewall, or VPN routing."
		}
		return host + " resolves but neither it nor the general internet is reachable — local egress problem."
	case has(ProbeTLS) && fail(ProbeTLS):
		return "TCP reaches " + hp + " but the TLS handshake fails — bad/expired cert, clock skew, or MITM proxy."
	case has(ProbeHTTPS) && fail(ProbeHTTPS):
		return "TLS is fine but no HTTPS response from " + hp + " — application-layer or proxy block."
	case has(ProbeHTTP) && fail(ProbeHTTP):
		if t.Proto == ProtoTLSHTTP {
			return "HTTPS works but no HTTP response from " + host + ":80 — the redirect/plain-HTTP endpoint may be blocked."
		}
		return "No HTTP response from " + hp + " — application-layer or proxy block."
	case (has(ProbeSSH) && fail(ProbeSSH)) || (has(ProbeSMTP) && fail(ProbeSMTP)):
		return hp + " accepts TCP but the service banner check failed."
	default:
		return ""
	}
}
