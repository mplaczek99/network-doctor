//go:build darwin

package diagnostic

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// defaultRoute asks the OS for the IPv4 default route via the built-in
// `route` tool (built-ins preferred over native APIs; the value is
// display-only and degrades to empty).
func defaultRoute(ctx context.Context) (string, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "route", "-n", "get", "-inet", "default").Output()
	if err != nil {
		return "", false, err
	}
	return parseDarwinRoute(bytes.NewReader(out))
}
