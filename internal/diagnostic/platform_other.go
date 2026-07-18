//go:build !linux && !darwin && !windows

package diagnostic

import "context"

// Unsupported GOOSes compile with the cosmetic SSID field empty (untested
// targets; see PLAN.md "Out of scope").

func ssid(context.Context, string) string { return "" }
