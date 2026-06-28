package ui

import (
	"github.com/mplaczek99/network-doctor/internal/diagnostic"
	"github.com/mplaczek99/network-doctor/internal/textsafe"
)

// Private aliases keep the UI implementation focused on presentation while
// making the package boundary explicit in one place.
type (
	Target      = diagnostic.Target
	Proto       = diagnostic.Proto
	Status      = diagnostic.Status
	ProbeID     = diagnostic.ProbeID
	ProbeResult = diagnostic.ProbeResult
	Probe       = diagnostic.Probe
)

const (
	ProtoHTTP = diagnostic.ProtoHTTP

	StatusPass = diagnostic.StatusPass
	StatusFail = diagnostic.StatusFail
	StatusSkip = diagnostic.StatusSkip
	StatusNA   = diagnostic.StatusNA

	pIface     = diagnostic.ProbeIface
	pInternet  = diagnostic.ProbeInternet
	pDNS       = diagnostic.ProbeDNS
	pTargetTCP = diagnostic.ProbeTargetTCP
	pTLS       = diagnostic.ProbeTLS
	pHTTP      = diagnostic.ProbeHTTP
	pHTTPS     = diagnostic.ProbeHTTPS

	probeTimeout = diagnostic.ProbeTimeout
)

var (
	parseTarget = diagnostic.ParseTarget
	buildProbes = diagnostic.BuildProbes
	diagnose    = diagnostic.Diagnose
	sanitize    = textsafe.Clean
)
