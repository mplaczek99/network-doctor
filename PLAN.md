# Plan: Network Doctor — Go TUI network diagnostic runner
_Locked via grill — by Claude + mplaczek_ · revised after Codex rounds 1–5 (MAX_ROUNDS)

## Goal
A terminal UI (Go, Bubble Tea) that runs an ordered chain of network diagnostic
checks and reports pass/fail with a remediation hint per failure — a "doctor"
that both diagnoses and prescribes. v1 is a Linux-only, IPv4-only template,
structured so checks (especially the OS-specific route reader) can be swapped
for cross-platform/IPv6 variants later. No root, no external binaries, stdlib
for everything except the TUI libs.

## Approach
1. `go mod init github.com/mplaczek/network-doctor`; `go 1.26` in `go.mod`. Add
   pinned deps and commit `go.sum`:
   `github.com/charmbracelet/bubbletea`, `.../lipgloss`, `.../bubbles/spinner`.
2. `checks.go` — contract (note: **no `Warn`** — nothing produces it):
   ```go
   type Status int // Pass, Fail
   type Result struct { Status Status; Detail string; Fix string }
   type Check struct { Name string; Run func(ctx context.Context) Result }
   ```
   Five checks, fixed order, each honoring `ctx` (timeout):
   1. **Link** — `net.Interfaces()`; need a non-loopback iface with
      `FlagUp`+`FlagRunning`. Fail → "no interface up."
   2. **IP** — `net.InterfaceAddrs()`; require a non-loopback, non-link-local
      **IPv4** addr (reject 169.254/16 and IPv6). Fail → "no usable IPv4 (DHCP?)."
   3. **Gateway** — default route via `route_linux.go`. Fail → "no IPv4 default
      route." Distinguish *route table unreadable* (internal error) from *no
      route* in the Detail/Fix.
   4. **Name resolution** — `net.DefaultResolver.LookupIP(ctx, "ip4",
      "connectivitycheck.gstatic.com")` — resolve the SAME host the Internet
      check hits (require an A/IPv4 result, consistent with IPv4-only), so a
      blocked unrelated host can't cause a false negative. (Honestly: tests
      system name resolution — `/etc/hosts` + configured resolvers — not pure
      DNS.) Fail → "name resolution failing."
   5. **Internet** — HTTP GET `http://connectivitycheck.gstatic.com/generate_204`,
      require status **exactly 204**. Fail → "no internet / captive portal."
      Uses `http.NewRequestWithContext` + a dedicated client (see below).

   All checks share `const checkTimeout = 4 * time.Second`.
3. `route_linux.go` (`//go:build linux`) — parse `/proc/net/route`:
   - Columns: `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU
     Window IRTT`. Skip the header line; a default route requires Destination
     (col 1) == `00000000` **AND** Mask/Genmask (col 7) == `00000000` (a nonzero
     mask like `0.0.0.0/8` is NOT default) **AND** `RTF_UP` set (Flags & 0x1).
     Among all such candidates pick the one with the **lowest Metric**; decode
     its Gateway (little-endian hex → dotted IPv4).
   - Never panic on malformed input; pure, table-testable signature
     `parseDefaultRoute(r io.Reader) (ip string, found bool, err error)` — parse
     errors (`err != nil`) are distinct from a valid table with no default route
     (`found == false, err == nil`). A thin `defaultRoute()` wrapper opens
     `/proc/net/route` and delegates (its open/read error → `err`). The Gateway
     check maps `err != nil` to an internal-error Detail, `!found` to "no IPv4
     default route."
   - Ships a **table-driven** test (`route_linux_test.go`): normal default
     route, no default route, header-only, malformed row, metric tie, empty,
     **and Destination `00000000` with nonzero Mask `000000FF` (0.0.0.0/8) →
     `found==false`** — asserting the `(ip, found, err)` triple for each.
4. `httpcheck` client (in `checks.go`) — a package-level `*http.Client`:
   - `Timeout: checkTimeout`; `CheckRedirect: func(...) error { return http.ErrUseLastResponse }`
     (do NOT follow redirects — a captive portal 30x/200 must not look like 204);
   - dedicated `Transport` with `Proxy: nil` (test host connectivity, not proxy)
     and a `DialContext` that forces network **`tcp4`** (IPv4-only consistency);
     `defer resp.Body.Close()` after every successful GET.
5. `model.go` — Bubble Tea model. **Cancel ownership rule: no `tea.Cmd` ever
   writes model state — all context/cancel lifecycle happens synchronously in
   `Update`.**
   - State: `[]struct{ Check; *Result }` (nil = pending); in-flight index;
     `spinner.Model`; `generation int`; the active check's `context.Context` +
     `context.CancelFunc`; `running bool`.
   - `Init()` returns ONLY a start command — `func() tea.Msg { return
     startCheckMsg{0, 0} }`. It sets no state (value semantics: Init's receiver
     isn't persisted) and creates no context (a cmd can't store one).
   - `Update(startCheckMsg{idx,gen})` is the **single place state transitions**:
     ignore if `gen != generation`; else **create `context.WithTimeout(checkTimeout)`
     and store its ctx+cancel in the model synchronously**, set `inFlight=idx`;
     capture `wasRunning := m.running`; set `m.running=true`; build
     `cmds := []tea.Cmd{runCheck(ctx,idx,gen)}` and **append `m.spinner.Tick`
     only if `!wasRunning`** (seed the tick exactly once on a real idle→running
     edge — no duplicate chains); return `tea.Batch(cmds...)`. Everything is a
     `tea.Cmd`, never a raw msg.
   - `runCheck` cmd: runs `Check.Run(ctx)`, returns `checkDoneMsg{idx, gen, Result}`.
     It reads ctx but never writes model state.
   - `Update(checkDoneMsg{idx,gen,res})`: accept **only if `running &&
     gen == generation && idx == inFlight`** — otherwise ignore (stale gen or
     wrong index can't cancel/store against the active check). On accept:
     **call+clear the stored cancel**, store `res`. If more checks remain, return
     a `startCheckMsg{idx+1, gen}` cmd; else `running=false` (tick chain stops).
   - Spinner: forward `spinner.TickMsg` to `spinner.Update` and reschedule its
     cmd **only while `running`** — chain self-terminates after the final result.
   - Keys: `r` → call+clear active cancel, bump `generation`, reset all results
     to pending, `inFlight=0`, return a `startCheckMsg{0, newGen}` cmd. It does
     NOT touch `running` or seed a tick — the `startCheckMsg` handler decides:
     an active rerun (`running` still true) reuses the live tick chain; a rerun
     after completion (`running==false`) seeds exactly one new tick.
     `q`/`ctrl+c` → call+clear active cancel, `tea.Quit`.
   - `View`: one line per check — glyph + name + detail; failed checks show an
     indented `→ Fix: …`. Glyphs: spinner (pending), `✓` green pass, `✗` red
     fail (lipgloss styles).
6. `main.go` — build `[]Check`, `tea.NewProgram(...)`. Capture
   `final, err := p.Run()`; type-assert `final` to the model. Exit code:
   `err != nil` → 1; any result `Fail` → 1; any result still pending/cancelled
   (early quit) → 1; else 0. `os.Exit(code)`.

## Key decisions & tradeoffs
- **No root, no raw ICMP, no shelling out.** Gateway check confirms an IPv4
  default route exists; real reachability is proven downstream by checks 4–5. A
  present-but-dead gateway passes 3, fails 4/5 — accepted, keeps it root-free.
- **Linux-only + IPv4-only v1** via `/proc/net/route`. OS-specific code isolated
  to `route_linux.go` (build tag) so `route_darwin.go` / IPv6 / netlink drop in
  later. No abstraction built now (YAGNI) — file isolation only.
- **Func-field check, not interface.** One behavior; no interface needed.
- **Sequential, run-all, no skip.** Ordered narrative; first Fail read top-down
  is the **earliest observed symptom** (not a guaranteed root cause — see
  limitations).
- **HTTP correctness:** context-aware request, no redirects, no proxy, body
  closed, status must be exactly 204.
- **Rerun/quit safety:** generation counter ignores stale msgs AND the active
  context is cancelled, so rapid `r` / early quit don't accumulate live work.
- **Exit code** is computed from the **final model returned by `Run()`**
  (Bubble Tea's value-update means the original model var is stale); `Run` error
  and any incomplete run both count as failure (nonzero).
- **No `Warn`.** Removed from the schema — nothing produces it; keeps exit and
  presentation semantics binary.

## Known limitations (v1, deliberate)
- Link/IP checks inspect the host **globally** (`net.Interfaces` /
  `InterfaceAddrs`), not specifically the default-route interface. On
  multi-homed / Docker / VPN hosts this can yield an optimistic pass. Deferred:
  associating these checks with the default-route iface adds coupling that
  breaks the link→ip→gateway narrative; revisit if it outgrows template status.
- `/proc/net/route` reflects only the IPv4 main routing table — not IPv6, not
  policy routing. The Gateway claim is scoped accordingly.

## Risks / open questions
- `generate_204` endpoint availability assumption; a captive portal returning
  200+body is correctly a Fail (intended).

## Out of scope
- No config file, no flags (maybe `--version` only).
- No logging, telemetry, or persistence.
- No live dashboard / continuous monitoring.
- No cross-platform or IPv6 support in v1 (structure allows it later).
- No real ICMP ping; no root/raw sockets; no external binaries; no netlink.
- Tests limited to: the table-driven `parseDefaultRoute(io.Reader)` test, and
  `model_test.go` driving `Update` directly (no goroutines): stale-gen ignored;
  wrong-index ignored; correct gen stores result + advances; cancel called +
  cleared on completion / `r` / `q` (sentinel CancelFunc records invocation,
  assert `ctx.Err()==context.Canceled` + field nil); spinner restart on `r`
  (`running` set + tick re-batched). No live network or full program-loop tests
  — add when it grows past template.
