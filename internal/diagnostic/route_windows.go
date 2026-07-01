//go:build windows

package diagnostic

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// defaultRoute asks the OS for the IPv4 default route via the built-in
// `route` tool (built-ins preferred over native APIs; the value is
// display-only and degrades to empty).
func defaultRoute(ctx context.Context) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "route", "print", "-4").Output()
	if err != nil {
		return "", false, err
	}
	// Console output is OEM code page; make invalid bytes visible, not silent.
	return parseWindowsRoute(strings.NewReader(strings.ToValidUTF8(string(out), "?")))
}
