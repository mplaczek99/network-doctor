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
	FailClass   = diagnostic.FailClass
	ProbeID     = diagnostic.ProbeID
	ProbeResult = diagnostic.ProbeResult
	Probe       = diagnostic.Probe
)

const (
	ProtoNone    = diagnostic.ProtoNone
	ProtoTLSHTTP = diagnostic.ProtoTLSHTTP
	ProtoHTTP    = diagnostic.ProtoHTTP
	ProtoSSH     = diagnostic.ProtoSSH
	ProtoSMTP    = diagnostic.ProtoSMTP

	StatusPass = diagnostic.StatusPass
	StatusFail = diagnostic.StatusFail
	StatusSkip = diagnostic.StatusSkip
	StatusNA   = diagnostic.StatusNA

	FailNone    = diagnostic.FailNone
	FailTimeout = diagnostic.FailTimeout
	FailRefused = diagnostic.FailRefused
	FailNoRoute = diagnostic.FailNoRoute
	FailDNS     = diagnostic.FailDNS
	FailTLS     = diagnostic.FailTLS
	FailOther   = diagnostic.FailOther

	pIface     = diagnostic.ProbeIface
	pInternet  = diagnostic.ProbeInternet
	pDNS       = diagnostic.ProbeDNS
	pTargetTCP = diagnostic.ProbeTargetTCP
	pTLS       = diagnostic.ProbeTLS
	pHTTP      = diagnostic.ProbeHTTP
	pSSH       = diagnostic.ProbeSSH
	pSMTP      = diagnostic.ProbeSMTP

	probeTimeout = diagnostic.ProbeTimeout
)

var (
	parseTarget = diagnostic.ParseTarget
	buildProbes = diagnostic.BuildProbes
	diagnose    = diagnostic.Diagnose
	sanitize    = textsafe.Clean
)
