//go:build !linux && !darwin && !windows

package diagnostic

import "context"

// Unsupported GOOSes compile with the cosmetic gateway/SSID fields empty
// (untested targets; see PLAN.md "Out of scope").

func defaultRoute(context.Context) (string, bool, error) { return "", false, nil }

func ssid(context.Context, string) string { return "" }
