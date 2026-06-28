# network-doctor

A terminal UI that diagnoses your network connectivity from the link layer up
and tells you what to fix when something is broken.

It runs five checks in order — each one a prerequisite for the next — so the
first ✗ you read top-down is the earliest point your connection breaks.

```
Network Doctor

✓ Link — interface wlan0 is up
✓ IP address — have IPv4 192.168.1.42
✓ Gateway — default route via 192.168.1.1
✗ Name resolution — cannot resolve connectivitycheck.gstatic.com: ...
    → Fix: name resolution failing — check /etc/resolv.conf / DNS
✗ Internet — request failed: ...
    → Fix: no internet — check upstream connectivity

r: rerun · q: quit
```

## Checks

| # | Check | Passes when | Notes |
|---|-------|-------------|-------|
| 1 | **Link** | A non-loopback interface is up and running | cable/Wi-Fi present |
| 2 | **IP address** | You hold a non-loopback, non-link-local IPv4 | rejects `127/8` and `169.254/16` (no-DHCP) |
| 3 | **Gateway** | An IPv4 default route exists | read from `/proc/net/route`, lowest metric |
| 4 | **Name resolution** | The probe host resolves to an IPv4 | system resolution: `/etc/hosts` + resolvers |
| 5 | **Internet** | `GET /generate_204` returns exactly `204` | a captive portal's `200`/redirect is a Fail |

The probe host is `connectivitycheck.gstatic.com`. Resolution and the internet
check hit the same host so a single blocked host can't cause a misleading
result. Every check is IPv4-only and bounded by a 4-second timeout.

## Install

Requires Go 1.26+. **Linux only** — the gateway check parses `/proc/net/route`.

```sh
go install github.com/mplaczek99/network-doctor@latest
```

Or build from a clone:

```sh
git clone https://github.com/mplaczek99/network-doctor
cd network-doctor
go build -o network-doctor .
```

## Usage

```sh
network-doctor
```

| Key | Action |
|-----|--------|
| `r` | rerun all checks |
| `q` / `Ctrl-C` | quit |

### Exit code

- `0` — every check passed.
- `1` — any check failed, or you quit before all checks finished.

This makes it usable in scripts and health gates:

```sh
network-doctor || echo "network is down"
```

## Built with

[Bubble Tea](https://github.com/charmbracelet/bubbletea),
[Bubbles](https://github.com/charmbracelet/bubbles), and
[Lip Gloss](https://github.com/charmbracelet/lipgloss).

## Tests

```sh
go test ./...
```
