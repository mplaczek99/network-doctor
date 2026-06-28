package main

import (
	"strings"
	"testing"
)

func TestNormalizeTarget(t *testing.T) {
	tests := map[string]string{
		"github.com":          "github.com",
		"https://github.com":  "github.com",
		"http://github.com/":  "github.com",
		"  github.com/ ":      "github.com",
		"https://github.com/": "github.com",
	}
	for in, want := range tests {
		if got := normalizeTarget(in); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

// No target -> the generic local+internet chain. A target -> the local-infra
// prefix plus per-host probes naming that host.
func TestChecksTargetChain(t *testing.T) {
	if got := len(checks("")); got != 5 {
		t.Fatalf("no-target chain len = %d, want 5", got)
	}

	cs := checks("github.com")
	if len(cs) != 9 {
		t.Fatalf("target chain len = %d, want 9", len(cs))
	}
	names := make([]string, len(cs))
	for i, c := range cs {
		names[i] = c.Name
	}
	joined := strings.Join(names, "\n")
	for _, want := range []string{"DNS github.com", "TCP github.com:443", "TLS github.com", "HTTP github.com", "SSH github.com:22"} {
		if !strings.Contains(joined, want) {
			t.Errorf("target chain missing %q; got:\n%s", want, joined)
		}
	}
}

// github.com gets the ssh-over-443 fallback; other hosts get the generic hint.
func TestSSHFix(t *testing.T) {
	if !strings.Contains(sshFix("github.com"), "ssh.github.com") {
		t.Error("github sshFix should mention the ssh.github.com:443 fallback")
	}
	if strings.Contains(sshFix("example.com"), "ssh.github.com") {
		t.Error("generic sshFix must not hardcode github")
	}
}
