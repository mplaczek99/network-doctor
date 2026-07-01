# Plan Review Log: Cross-platform support (Linux + macOS + Windows)
Act 1 (grill) complete — plan locked with the user. MAX_ROUNDS=5.

## Round 1 — Codex
- **Blocker:** [jobs.go](/home/mplaczek/network-doctor/internal/ui/jobs.go:99) uses Unix-only `Setpgid`, `Getpgid`, and signals, so Windows will not compile. **Fix:** split process setup/cancellation into Unix and Windows build-tagged files, with Windows Job Object or `Process.Kill` handling.

- **Blocker:** `pathping` commonly exceeds the global 12-second timeout in [jobs.go](/home/mplaczek/network-doctor/internal/ui/jobs.go:76), guaranteeing premature termination. **Fix:** add a per-tool timeout field and give `pathping` a duration consistent with its flags.

- **High:** Windows command output uses an OEM code page, while `textsafe.Clean` drops invalid UTF-8; localized output and non-ASCII SSIDs can be corrupted. **Fix:** decode Windows subprocess output using the active code page before parsing or sanitizing.

- **High:** The `netsh` and `nslookup` parsers rely on localized labels (`Name`, `SSID`, `Address`, `Average`); “stable in practice” is not a correctness strategy. **Fix:** use locale-independent output/API mechanisms or explicitly document English-only support and test representative locales.

- **High:** The proposed `nslookup` parser can miss normal Windows output using `Addresses:` followed by indented continuation addresses. **Fix:** model the entire post-`Name:` stanza and validate every candidate with `net.ParseIP(...).To4()`.

- **High:** Falling back to the first SSID when the requested interface is not matched can report another adapter’s network. **Fix:** return empty when named interface blocks exist but none matches; only fallback when the output has no usable interface identities.

- **Medium:** macOS `route` may return `link#N` or another non-IP gateway, but the plan does not require validation. **Fix:** accept gateway values only when `net.ParseIP(value).To4()` succeeds.

- **Medium:** Windows command displays remain POSIX-formatted (`LC_ALL=C`, single-quote escaping), so exported and shown commands are not copy-pasteable. **Fix:** make display rendering GOOS-aware or omit environment prefixes and shell quoting from Windows displays.

- **Medium:** Gateway and SSID failures are silently collapsed into empty values, hiding missing executables, timeouts, permissions, and parser drift. **Fix:** preserve a sanitized diagnostic reason in probe details or debug/export output without failing the probe.

- **Medium:** Pure parser fixtures do not verify command lookup, deadline cancellation, encoding, or Windows process termination. **Fix:** add injectable command runners plus platform-specific wrapper and cancellation tests in CI.

- **Low:** The claim that unmatched build tags leave “Linux as default” is false; unsupported GOOS targets get undefined `ssid` and `defaultRoute`. **Fix:** add an `!linux && !darwin && !windows` stub or state explicitly that other targets intentionally fail to build.

VERDICT: REVISE
### Claude's response (round 1)
Accepted (plan revised):
- Both blockers verified in source and fixed in plan: jobs.go process-group code split into `procgroup_unix.go` / `procgroup_windows.go` (Windows: no-op setup + `Process.Kill()`; Job Objects named as upgrade path — Windows tool set spawns no descendant trees); per-tool `Timeout` field, pathping = 90 s.
- nslookup parsing replaced with locale-independent strategy: split on first blank line (skips resolver stanza), collect all tokens where `net.ParseIP(tok).To4() != nil` — also resolves the `Addresses:` continuation-line finding.
- netsh SSID selection: one SSID → use it; multiple → require iface Name match, else empty (never report another adapter's network).
- macOS gateway validated with `net.ParseIP(v).To4()` (rejects `link#N`).
- Display strings GOOS-aware: Windows drops `LC_ALL=C ` prefix, uses double-quote quoting.
- Unsupported-GOOS stub file added (`!linux && !darwin && !windows`) — plan's earlier "Linux remains default" claim was wrong, corrected.
- CI gains per-OS real-exec smoke tests (no panic, honors deadline) covering lookup/cancel/kill paths.

Rejected (with reasons):
- Full OEM code-page transcoding (x/text + GetOEMCP): display-only corruption risk on non-English systems for garnish-level data; all load-bearing parsing made locale-independent instead; limitation documented in README. (Codex's own alternative fix — "explicitly document English-only support" — adopted for Windows ping facts.)
- Injectable command-runner abstraction: interface with one implementation for ~10-line wrappers; real-exec CI smoke tests cover the same surface without the abstraction.
- Plumbing gateway/SSID failure reasons into probe details/export: both values are cosmetic garnish whose absence is self-evident and indistinguishable-by-design from the legitimate empty state; err returns exist in signatures if ever needed.

## Round 2 — Codex
Most prior findings are addressed, but material issues remain:

- **Blocker, newly found:** `--toolbox` leaves `m.ctx == nil`; launching a tool calls `context.WithTimeout(nil, ...)` and panics. **Fix:** initialize the context in toolbox mode or make `startTool` substitute `context.Background()`.
- **High:** Single-SSID fallback can label an Ethernet, VPN, or virtual interface with an unrelated Wi-Fi SSID. **Fix:** require interface-name matching whenever interface identity is available; otherwise return empty.
- **High:** OEM-code-page handling remains rejected, so non-ASCII SSIDs and the core raw-output pane can be corrupted despite the "run correctly on Windows" goal. **Fix:** decode Windows subprocess output before sanitization, at least for SSID and streamed tool output.
- **Medium:** One double-quote renderer cannot be both cmd.exe- and PowerShell-pasteable; curl's `%{...}` format is particularly unsafe under cmd expansion. **Fix:** target one documented shell—preferably PowerShell—and implement its exact quoting rules.
- **Medium:** `//go:build unix` plus a Windows file still leaves non-Unix/non-Windows targets without `setProcGroup`/`killGroup`, contradicting the unsupported-GOOS compile promise. **Fix:** add a `!unix && !windows` process fallback or withdraw that promise.
- **Medium:** Real built-in smoke tests cannot reliably prove deadline cancellation because the commands may finish before the deadline. **Fix:** use the existing re-executed test helper to deterministically test cancellation on every CI OS; reserve live commands for availability smoke tests.

VERDICT: REVISE

### Claude's response (round 2)
Accepted (plan revised):
- Toolbox nil-ctx blocker verified in source (model.go: ctx only set on scheduleMsg; handleKey launches tools unguarded) — pre-existing panic, fixed in plan via lazy ctx init in `launchTool` + regression test.
- SSID selection rewritten: blank-line block split + *value* match on iface (locale-independent, no reliance on localized `Name` label); single-SSID fallback dropped entirely — Ethernet/VPN ifaces can never acquire a Wi-Fi SSID since netsh lists only WLAN interfaces and non-matching output returns "".
- Windows display quoting targets PowerShell explicitly (single-quote literal, `'` doubled — keeps curl `%{…}` inert); cmd.exe paste explicitly unsupported and documented.
- Added `!unix && !windows` procgroup stub — compile-everywhere claim now holds program-wide.
- Cancellation testing moved to the existing re-exec helper (`jobs_test.go` startHelper) run untagged on all three CI OSes; live-command tests demoted to availability smoke only.

Rejected (held from round 1, reason strengthened):
- OEM code-page transcoding: cannot recover non-OEM-representable SSIDs (netsh itself emits `?`); only benefit is softer mangling of localized letters in a display-only pane on non-English Windows; codepage→decoder dependency disproportionate. Compromise adopted instead: sanitizer must visibly *replace* (not silently delete) invalid bytes; README documents the limitation. All load-bearing parsing is locale-independent by construction.

## Round 3 — Codex
Prior blockers are substantially addressed. New remaining issues:

- **High:** PowerShell 5.1 aliases `curl` to `Invoke-WebRequest`, so the advertised copy-paste command will reject curl flags. **Fix:** use and display `curl.exe` on Windows.
- **High:** Numeric matching across all `route print -4` output can select an inactive Persistent Route. **Fix:** require the five-column active-route shape, including a valid IPv4 interface column, and fixture-test competing persistent defaults.
- **Medium:** The plan changes concurrent subprocess cancellation but omits the repository's race-test gate. **Fix:** run `go test -race ./...` at least on Linux CI and before handoff.
- **Medium:** Replacing invalid UTF-8 globally in `textsafe.Clean` changes Linux/macOS banner and error sanitization too. **Fix:** perform visible byte replacement at the Windows subprocess boundary, or explicitly test and document the global behavior change.

The OEM-code-page limitation remains unresolved but is now an explicit, documented tradeoff rather than an accidental omission.

VERDICT: REVISE

### Claude's response (round 3)
All four accepted, nothing rejected:
- Windows `c` tool uses and displays `curl.exe` (bypasses PS 5.1 `curl` alias).
- `route print -4` parsing now requires the five-column Active Routes shape (gateway AND interface columns parse as IPv4, metric numeric) — structurally excludes the Persistent Routes section without locale-dependent header matching; fixture added for a competing persistent default.
- CI Linux leg gains `go test -race ./...`; also run locally before handoff.
- Invalid-UTF-8 replacement scoped to the Windows subprocess boundary only (`strings.ToValidUTF8` on streamed lines + wrapper output when GOOS==windows); `textsafe.Clean` and Unix sanitization semantics untouched.

## Round 4 — Codex
All prior material findings are addressed:

- Windows uses `curl.exe`.
- Route parsing excludes persistent routes structurally.
- Race testing is included.
- Invalid UTF-8 replacement is Windows-boundary-only.
- Toolbox context, cancellation, SSID association, quoting, timeouts, and build tags are covered.

No new material flaws found. The documented OEM/localization limitations are explicit, bounded tradeoffs.

VERDICT: APPROVED
