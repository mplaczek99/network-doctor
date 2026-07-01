# Plan: Cross-platform support (Linux + macOS + Windows)
_Locked via grill — by Claude + mplaczek. Revised after Codex review rounds 1–3._

## Goal
network-doctor currently builds and fully works only on Linux. Make it build and
run correctly on Linux, macOS, and Windows. The native probe engine (checks.go,
diagnosis, TUI) is already pure Go and portable; the work is confined to the
platform-specific surfaces: the job runner's process-group handling,
default-gateway lookup, Wi-Fi SSID lookup, the drill-down tool table, and
fix-hint strings. On macOS and Windows the new implementations prefer OS
built-in commands (user's explicit preference) over native APIs, because both
values they feed (gateway, SSID) are display-only and already degrade
gracefully to empty. Existing native Linux implementations stay untouched.

## Approach
1. **Job runner portability (`internal/ui/jobs.go`) — Windows compile blocker.**
   `syscall.SysProcAttr{Setpgid: true}` and `killGroup` (`Getpgid`/`Kill`/`SIGKILL`)
   are Unix-only. Split into `procgroup_unix.go` (`//go:build unix` — current
   behavior, covers linux+darwin) exposing `setProcGroup(cmd)` and
   `killGroup(cmd)`, and `procgroup_windows.go` where `setProcGroup` is a no-op
   and kill is `cmd.Process.Kill()`. Windows built-ins (ping/tracert/pathping/
   netstat/nslookup/curl) don't spawn descendant trees, so plain Kill suffices;
   `// ponytail:` comment names Job Objects as the upgrade path if a tree-killing
   need appears.
2. **Per-tool timeout.** Global `toolTimeout = 12s` would kill pathping mid-run.
   Add `Timeout time.Duration` to `Tool` (zero = 12 s default), plumb through
   `startTool`; pathping gets 90 s, consistent with its bounded flags.
   While in `launchTool`: fix the pre-existing `--toolbox` panic — `m.ctx` is only
   initialized on `scheduleMsg`, so launching a tool before the first `r` passes a
   nil parent to `context.WithTimeout` (model.go:292). Initialize `m.ctx` lazily in
   `launchTool` exactly as `scheduleMsg` does, plus a regression test.
3. **Gateway (display-only detail in `internetProbe`).**
   - Shared signature becomes `defaultRoute(ctx context.Context) (ip string, found bool, err error)`. Linux impl (`/proc/net/route`) ignores ctx; only the checks.go call site changes.
   - `route_darwin.go`: exec `route -n get -inet default` via `exec.CommandContext` capped at min(ctx, 2 s); parse the `gateway:` line; accept the value only if `net.ParseIP(v).To4() != nil` (rejects `link#N` and names).
   - `route_windows.go`: exec `route print -4` the same way; accept only rows with the five-column Active Routes shape — destination `0.0.0.0`, netmask `0.0.0.0`, gateway parses as IPv4, *interface column parses as IPv4*, metric numeric — which structurally excludes the four-column Persistent Routes section (locale-independent, no header matching); pick lowest metric. Fixture includes a competing persistent default route.
   - Parsers are pure `func(io.Reader) (string, bool, error)` in **untagged** `internal/diagnostic/gateway_parse.go`, fixture-tested on any OS.
4. **SSID (display-only, already "" when wired/unknown).**
   - Shared signature becomes `ssid(ctx context.Context, iface string) string`; `ifaceProbe` passes its ctx; Linux ioctl impl ignores it.
   - `ssid_darwin.go`: exec `networksetup -getairportnetwork <iface>` (iface is already `enX`); parse the `Current Wi-Fi Network: <name>` line; anything else → "".
   - `ssid_windows.go`: exec `netsh wlan show interfaces`; split output into blank-line-separated blocks; a block matches only if some line's *value* (text after the first `:`, trimmed) equals iface — value comparison, so no reliance on the localized `Name` label. From the matching block take the line whose key (text before `:`, trimmed) is exactly `SSID` (excludes `BSSID`; the `SSID` label itself is not translated). No fallback: no matching block → "" — netsh lists only WLAN interfaces, so an Ethernet/VPN iface correctly never acquires a Wi-Fi SSID.
   - Parsers pure + untagged in `internal/diagnostic/ssid_parse.go`, fixture-tested (fixtures include a two-adapter netsh capture and a non-English one). All parsed SSIDs pass through `textsafe.Clean`.
5. **Drill-down tool table (`internal/ui/tools.go`).**
   - `toolsFor(t *Target)` becomes `toolsFor(t *Target, goos string)`; production passes `runtime.GOOS`; tests exercise all three tables from one OS. Same hotkeys everywhere:

     | Key | Linux (unchanged) | macOS | Windows |
     |-----|-------------------|-------|---------|
     | i | `ip route` | `netstat -rn` | `route print -4` |
     | s | `ss -tunp` | `netstat -an -p tcp` | `netstat -ano` |
     | p | `ping -c 4 -W 2 <h>` | `ping -c 4 <h>` (BSD `-W` is ms; omit) | `ping -n 4 -w 2000 <h>` |
     | d | `dig +time=2 +tries=1 <h>` | same as Linux (dig ships) | `nslookup <h>` |
     | c | `curl … -o /dev/null` | same | `curl.exe` explicitly — `Bin` and display both, so the pasted command bypasses PowerShell 5.1's `curl`→`Invoke-WebRequest` alias (ships since Win10 1803) |
     | t | `traceroute -w 2 -q 1 -m 20 <h>` | same as Linux | `tracert -w 2000 -h 20 <h>` |
     | m | `mtr --report --report-cycles 5 <h>` | same (brew-only; `Available()` hides it) | `pathping -h 20 -q 5 -p 100 -w 500 <h>`, Timeout 90 s |

   - curl's `-o /dev/null` becomes `-o` + `os.DevNull` (`NUL` on Windows). `LC_ALL=C` env still set everywhere (harmless on Windows).
   - **Display strings GOOS-aware, Windows targets PowerShell (documented):** omit the `LC_ALL=C ` display prefix and quote PowerShell-literal style — single quotes, embedded `'` doubled — which also keeps curl's `%{…}` format string inert (cmd.exe `%` expansion is explicitly not supported; one shell, exact rules). Unix keeps current POSIX single-quote style. Display-only; argv execution is unchanged and never shell-interpreted.
   - `Available()`/`exec.LookPath` already handles PATHEXT on Windows; no change.
6. **Fact extraction (`extractFacts`).** Gains a `goos` param; stays best-effort (no facts ≠ failure; raw sanitized output authoritative).
   - Existing ping parser already matches macOS output (`round-trip min/avg/max`, `packet loss`).
   - Windows ping: parse `(X% loss)` and `Average = Xms` (English-locale only, documented).
   - nslookup: locale-independent strategy — skip the resolver's own stanza by splitting on the first blank line, then collect every whitespace-separated token in the remainder for which `net.ParseIP(tok).To4() != nil`. Handles `Address:`, `Addresses:`, and indented continuation lines without label matching.
7. **Fix hints.** Replace the two Linux-isms in checks.go (`ip link set <iface> up`, `/etc/resolv.conf`) with a small per-GOOS lookup: Linux keeps current text; macOS suggests Wi-Fi/cable + `networksetup`; Windows suggests Settings → Network or `ipconfig /all`.
8. **Unsupported GOOS stubs — complete set.** `//go:build !linux && !darwin && !windows` file providing `defaultRoute`/`ssid` zero-value stubs, **and** `//go:build !unix && !windows` file providing no-op `setProcGroup` + plain-`Kill` `killGroup`, so the compile-everywhere claim holds for the whole program, not just the diagnostic package.
9. **CI.** `.github/workflows/ci.yml`: matrix `[ubuntu-latest, macos-latest, windows-latest]`, stable Go, `go vet ./...`, `go build ./...`, `go test ./...`, plus `go test -race ./...` on the Linux leg (the plan touches concurrent subprocess cancellation; race gate also run locally before handoff). Two test layers, no mocking abstraction:
   - **Cancellation/kill correctness**: the existing re-exec test helper in `jobs_test.go` (`startHelper`) already tests `startTool` deterministically — ensure those tests are untagged so the CI matrix runs them on all three OSes; they exercise the per-OS `killGroup` path deterministically (a live `ping` may finish before any deadline, so live commands prove nothing about cancellation).
   - **Availability smoke**: per-OS tests that really exec the built-ins on the runner (no WLAN/default-route assumptions — assert only: returns without panic within deadline, output string sane). Covers command lookup and wrapper plumbing.
10. **Manual smoke test** on the user's real macOS and Windows machines: generic mode, one target-mode run, each drill-down hotkey — validates live flag behavior and TUI rendering CI can't.
11. Run `graphify update .` after code lands (project rule); README gains a platform-support note including the localization caveat below.

## Key decisions & tradeoffs
- **Exec OS built-ins over native APIs on macOS/Windows** (grill Q2): gateway and SSID are cosmetic and degrade to empty; native alternatives cost `x/net/route`, iphlpapi plumbing, or cgo+CoreWLAN for zero user-visible gain. Linux stays native.
- **Hybrid layout** (grill Q4): build tags only on thin exec/syscall wrappers; parsers and the tool table are portable `goos`-parameterized pure functions, fixture-tested from one OS.
- **Windows kill = `Process.Kill()`, not Job Objects** (Codex R1): the Windows tool set spawns no descendant trees; Job Objects are the documented upgrade path.
- **English-locale parsing for Windows ping facts; locale-independent strategies (numeric cells, blank-line split + ParseIP, untranslated `SSID` label, block value-match) everywhere else** (Codex R1+R2): full OEM-code-page transcoding (x/text + GetOEMCP) rejected and held on re-review — it cannot recover non-OEM-representable SSIDs (netsh already emits `?` for those), only softens localized-letter mangling in a display pane on non-English Windows; a codepage→decoder dependency is disproportionate to that. Compromise adopted: invalid-byte replacement (`strings.ToValidUTF8(s, "?")`) applied **only at the Windows subprocess boundary** (streamed tool lines + SSID/gateway wrapper output on `runtime.GOOS == "windows"`), so Linux/macOS banner and error sanitization semantics are untouched; README documents the limitation.
- **Windows `m` → pathping** (grill Q3) with 90 s per-tool timeout (Codex R1). **Windows `d` → nslookup** over Resolve-DnsName.
- **Per-OS fix hints over generic text** (grill Q5).
- **ctx plumbed into gateway/SSID wrappers** with `exec.CommandContext` + ~2 s cap.
- **No injectable command-runner abstraction** (Codex R1 partial reject): wrappers are ~10 lines each; real-exec smoke tests in the CI matrix cover lookup/deadline/kill without adding an interface with one implementation.
- **Gateway/SSID failures stay silently empty** (Codex R1 reject): both are cosmetic garnish whose absence is self-evident and identical to the legitimate "no route/no Wi-Fi" state; plumbing failure reasons into details/export adds noise to every probe for debug info nobody asked for.
- **CI matrix + one-time manual smoke** (grill Q6).

## Risks / open questions
- **Windows localization/encoding**: console tools emit OEM code page; non-ASCII localized text renders as visible replacement characters in the raw output pane and Windows ping facts may extract nothing on non-English systems. Accepted + documented; all *load-bearing* parsing (route cells, SSID label + block value-match, nslookup ParseIP) is locale-independent.
- **macOS SSID tooling churn**: Apple removed `airport`; `networksetup -getairportnetwork` works today; future failure degrades to empty Network field (accepted in grill).
- **pathping runtime** (~30–60 s) is slow for a TUI pane even with the 90 s cap; output streams live via the existing job runner.
- `netstat -an -p tcp` on macOS lacks the process info `ss -tunp` shows; accepted asymmetry.

## Out of scope
- Release/distribution automation (goreleaser, prebuilt binaries) — grill Q7.
- Native API implementations (x/net/route, iphlpapi, CoreWLAN) and OEM code-page transcoding.
- IPv6, happy-eyeballs, any probe-engine behavior change.
- First-class support for other GOOSes (they compile via the stub with empty cosmetic fields; untested).
