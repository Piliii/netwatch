# netwatch

A local, layered network + service health monitor. Single Python script, no
external dependencies (stdlib only — `tomllib`, `curses`, `urllib`,
`subprocess`). Runs as a `systemd --user` service; the monitoring/check path
itself needs no root. The `--tui`'s VPN up/down action is the one exception
— see below.

## Why

Most "is my stuff up" scripts either ping one thing or fire N unrelated
alerts the moment your internet or VPN blips. netwatch runs checks in
dependency order — internet, then DNS, then VPN, then your actual targets —
so a single real failure is reported once instead of cascading into a wall
of false alarms.

## Quick start

```sh
git clone <this repo>
cd netwatch
cp targets.example.toml targets.toml   # edit to your own domains/services
./netwatch.py                          # one-shot check, human-readable report
./netwatch.py --watch --interval 30    # run continuously, desktop-notify on transitions
./netwatch.py --tui                    # live dashboard (reads the --watch service's output)
```

No `pip install` needed — everything is Python stdlib.

## Architecture

```
netwatch.py           All logic: checks, reporting, watch loop, TUI
targets.example.toml  Template config — copy to targets.toml and edit
targets.toml           Your own list of domains/services to watch (gitignored,
                        netwatch never writes to it, only reads it)
.state.json            Last-known up/down/skipped per check (for transition detection)
.latest.json           Full snapshot of the most recent cycle (for --tui to read)
netwatch.log            Append-only, transitions only (not every cycle)
```

To run continuously as a systemd user service:

```
~/.config/systemd/user/netwatch.service
```

pointed at `netwatch.py --watch --interval 30` (unbuffered via `python3
-u`), then:

```sh
systemctl --user enable --now netwatch
systemctl --user status netwatch
```

## The layered check cascade

Checks run in dependency order, each gated on the previous one, so a single
real failure is reported once instead of cascading into N unrelated-looking
alerts:

```
internet (ping 1.1.1.1)
  -> dns (resolve cloudflare.com via system resolver)
    -> vpn (wg0 interface LOWER_UP + ping the gateway, 10.8.0.1)
      -> vpn_dns (resolve cloudflare.com via `dig @10.8.0.1`)
        -> targets (from targets.toml)
```

A target is only actually probed once its required upstream layer is
healthy; otherwise it's `skipped` (yellow `?`), never counted as a failure.
`kind = "public"` targets need only `internet`; `kind = "internal"` targets
(self-hosted, VPN-only) need `vpn` + `vpn_dns` too, and are expected to
resolve through the VPN's own DNS rather than the public one — that's the
whole point of the `internal` distinction, not just a label.

VPN health is inferred from interface state + gateway reachability, not
`wg show`'s handshake-freshness data (which needs root/`CAP_NET_ADMIN`) —
enough signal without running the service as root or granting extra
capabilities.

## Config (`targets.toml`)

User-maintained by design, not auto-discovered. You add/remove entries
yourself; netwatch only ever reads this file.

`[network]` holds the probe hosts/IPs (internet probe, DNS test hostname,
VPN interface/gateway/DNS-server) — defaults match a common WireGuard setup
(`wg0`, gateway `10.8.0.1`) but are all overridable. `[[targets]]` is a
repeatable table: `name`, `url`, `kind` (`"public"` | `"internal"`).

## HTTP checks

Plain `urllib` GET with a default TLS context (so a broken/expired cert
shows up as a failure, which is the point). A 4xx response counts as *up*
(the server answered); only 5xx or a connection-level failure counts as
down — mirrors what a human means by "is the site down," not literal status
code purity.

The up/down decision and `detail` string (e.g. `HTTP 200`) come from the
HTTP GET itself, but the `latency_ms` shown is *not* that GET's round-trip
time — it's overwritten by `ping()` against the target's host. Falls back to
the HTTP GET's own elapsed time if the host doesn't answer ICMP at all
(firewalled, ICMP disabled, etc.).

## Ping latency (`ping()`)

Used for `internet`, `vpn` (gateway), and every target's displayed latency.
Sends 7 ICMP echoes (`-i 0.2`, the fastest interval allowed without root)
and reports the average RTT of the 6 readings *after* the first, not the
first one and not the subprocess's wall-clock time — the first echo is
routinely inflated by a cold ARP/route-cache lookup and isn't representative
of steady-state latency. Up/down is unaffected — still `ping`'s own exit
code, true as long as at least one of the 7 replies came back.

## Watch mode / notifications

`--watch` loops forever, and on every cycle:
1. Writes `.latest.json` (full snapshot — this is what `--tui` reads).
2. Compares each check's collapsed state (`up`/`down`/`skipped`) against
   `.state.json`'s last-seen value; only fires a `notify-send` desktop
   notification (and appends to `netwatch.log`) on an actual `up<->down`
   transition. Transitioning into/out of `skipped` never notifies — an
   upstream outage already generated its own alert.
3. Persists the new collapsed state back to `.state.json`.

Notifications go through `notify-send` (checked for existence via
`shutil.which` first — a no-op, not a crash, on a machine without a
notification daemon).

## TUI (`--tui`)

Reads `.latest.json` in a `curses` loop (default 2 s redraw) — **runs no
checks of its own**, purely a viewer for whatever the background `--watch`
service last wrote. This means opening/closing the TUI never doubles up
network probes, and multiple TUI instances could run at once with no
contention. If `.latest.json` is stale (>75 s old, i.e. the service missed
~2+ cycles at the default 30 s interval), the header flags "service may be
stopped" rather than silently showing old data as current. `q`/`Q`/Esc
quits.

Checks render in two labeled sections: **Network**
(`internet`/`dns`/`vpn`/`vpn_dns` — the fixed layer cascade) and **Targets**
(everything from `targets.toml`).

`u`/`U` and `d`/`D` bring/take the VPN up or down (`systemctl start/stop
wg-quick@<vpn_interface>`), each gated behind a `y`/`n` confirm prompt so a
stray keystroke can't drop the tunnel. This is the one place netwatch needs
root: it shells out via `sudo -n systemctl ...` — `-n` (non-interactive)
means it fails fast with an error shown in the TUI rather than hanging on a
password prompt curses can't render. Requires a passwordless sudoers rule
scoped to exactly `systemctl start/stop wg-quick@<interface>` on your
machine; without it every attempt fails cleanly. Every attempt (success or
failure) is written to `netwatch.log` as an `ACTION` line, same as automatic
up/down transitions.

`c`/`C`, `i`/`I`, and `t`/`T` run the three ad hoc checks below
(`--check-domain`, `--check-ip`, `--mtr`) against a domain/IP/host typed in
on the spot, without leaving the TUI. Any keypress dismisses the result
overlay; empty input at the prompt cancels without running anything. These
checks never touch `.latest.json` or `.state.json` — same "reads only,
never writes to shared state" rule as everything else in the TUI.

## Ad hoc single-target checks (`--check-domain` / `--check-ip` / `--mtr`)

Independent of `targets.toml` and the layered cascade — for "what's going on
with this one domain/IP right now" rather than continuous watching. Neither
is gated on any upstream layer; they just run directly against the given
domain/IP.

`--check-domain <domain>`: DNS resolution (all A/AAAA via
`socket.getaddrinfo`), `ping()`, HTTP *and* HTTPS probes, and TLS cert
details (issuer, subject, expiry date + days remaining, via
`ssl.getpeercert()` on a direct connection to port 443). Exit code reflects
only DNS + ping (the "is this even resolvable and alive" essentials);
HTTP/HTTPS/TLS are reported but don't affect it, since a domain need not run
a webserver at all.

`--check-ip <ip>`: reverse DNS (`socket.gethostbyaddr`, absence rendered as
a yellow `?` — most IPs legitimately have no PTR record, that's not a
failure), `ping()`, and a TCP connect test (stdlib `socket.create_connection`,
no external port-scan tool) against common ports (22, 53, 80, 443, 3389).
Exit code reflects only ping.

`--mtr <host>` (`--mtr-cycles`, default 10): hop-by-hop path check via `mtr
--report --report-cycles N <host>`. A plain ping only tells you whether the
far end responds; this is for "which hop along the route is actually
dropping packets or adding latency." No root needed — rides the kernel's
unprivileged ICMP socket support (`net.ipv4.ping_group_range`), the same as
`ping` elsewhere. Takes noticeably longer than the other two checks (~10-15 s
at the default 10 cycles, since `mtr` paces cycles roughly 1/s) — this is
the cost of the extra signal, not a bug.

All three support `--json` for machine-readable output, same as the
one-shot cascade mode.

## Privacy

State is a small local JSON file (last-known status per check); nothing is
sent anywhere except the HTTP GET to each configured target URL and the
DNS/ping probes needed to run the checks themselves. `--check-domain`,
`--check-ip`, and `--mtr` follow the same policy: local tools only
(`socket`, `ssl`, `ping`, `mtr`, TCP connect) — no WHOIS, no GeoIP/ASN, no
third-party lookup service.

## Known gaps

- Single machine only — no aggregation across devices, no remote view.
- The continuous `targets.toml` cascade has no TLS cert-expiry check of its
  own; an expired/broken cert there just shows up as a generic HTTP-check
  failure. `--check-domain` (above) covers this for one-off lookups, not
  for continuous watch/notify.
- `--json` (one-shot) and `--watch`/`--tui` (continuous) are the only
  continuous-monitoring modes; no historical graphing/retention beyond the
  transition log.

## License

MIT — see [LICENSE](LICENSE).
