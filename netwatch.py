#!/usr/bin/env python3
"""Layered network + service health monitor.

Checks, in dependency order, so a failure is attributed to its real cause
instead of every downstream symptom firing at once:

    internet -> dns -> vpn (interface + gateway ping) -> vpn_dns -> targets

A target is only actually probed once its required upstream layer is
healthy; otherwise it's reported "skipped", not "down" — a dead VPN shows up
once, as "vpn: down", rather than as N unrelated site-down alerts.

Public targets need only `internet`; `internal` (VPN-only) targets need
`vpn` + `vpn_dns` as well, and are resolved through the VPN's own DNS server
rather than the public resolver.

Edit targets.toml (next to this file) to add/remove watched domains —
netwatch never writes to it.

Usage:
    ./netwatch.py                    one-shot check, human-readable report
    ./netwatch.py --json             one-shot check, JSON to stdout
    ./netwatch.py --watch            loop forever, desktop-notify on
                                      up<->down transitions only
    ./netwatch.py --watch --interval 30
    ./netwatch.py --tui              live curses dashboard — reads the
                                      running --watch service's last
                                      snapshot, runs no checks of its own,
                                      safe to open/close anytime. q to quit.
                                      From inside --tui: c/i/t run the
                                      three one-off checks below against
                                      a domain/IP/host you type in, shown
                                      in an overlay (any key dismisses).
    ./netwatch.py --check-domain example.com
                                      one-off: DNS, ping, HTTP/HTTPS, TLS
                                      cert expiry for a domain not in
                                      targets.toml
    ./netwatch.py --check-ip 1.2.3.4
                                      one-off: reverse DNS, ping, common
                                      TCP port connectivity for an IP
    ./netwatch.py --mtr example.com
                                      one-off: hop-by-hop path check (mtr
                                      --report) — which hop is dropping
                                      packets or adding latency

Privacy: state is a small local JSON file (last-known status per check),
nothing is sent anywhere except the HTTP GET to each configured target URL
and the DNS/ping probes needed to run the checks themselves. --check-domain,
--check-ip, and --mtr are the same policy: local tools only (socket, ssl,
ping, mtr, TCP connect) — no WHOIS, no GeoIP/ASN, no third-party lookup
service.
"""

import argparse
import ipaddress
import json
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "targets.toml"
STATE_PATH = BASE_DIR / ".state.json"
LATEST_PATH = BASE_DIR / ".latest.json"
LOG_PATH = BASE_DIR / "netwatch.log"


@dataclass
class CheckResult:
    name: str
    ok: bool
    detail: str
    latency_ms: float | None = None
    skipped: bool = False
    expected: bool = False  # down, but for a known/benign reason (e.g. Rocket League's own VPN toggle)
    group: str = "target"  # "network" for the internet/dns/vpn/vpn_dns layer checks, "target" for targets.toml entries


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        sys.exit(f"Missing config: {CONFIG_PATH} — see targets.toml.example conventions in the repo.")
    with open(CONFIG_PATH, "rb") as f:
        return tomllib.load(f)


def ping(host: str, count: int = 7, timeout: int = 2) -> tuple[bool, float | None]:
    """Send `count` probes, not just one — a lone dropped ICMP packet (Wi-Fi
    retransmit, a brief scheduler stall) shouldn't flip a check to "down"
    for a full cycle. `ping`'s own exit code is 0 as long as at least one
    reply came back, so this is a free "any response counts" check.

    Latency is the average RTT of every reading after the first, not the
    first one itself or the subprocess's wall-clock time — the first echo is
    routinely inflated by a cold ARP/route-cache lookup and isn't
    representative of steady-state latency. `-i 0.2` (the fastest interval
    allowed without root) keeps 7 packets quick."""
    try:
        r = subprocess.run(
            ["ping", "-c", str(count), "-i", "0.2", "-W", str(timeout), host],
            capture_output=True,
            text=True,
            timeout=count * 0.2 + timeout + 2,
        )
        times = [float(m) for m in re.findall(r"time=([\d.]+)", r.stdout)]
        latency = round(sum(times[1:]) / len(times[1:]), 1) if len(times) >= 2 else None
        return r.returncode == 0, latency
    except Exception:
        return False, None


def resolve(host: str, server: str | None = None, timeout: int = 3) -> tuple[bool, str]:
    """Resolve `host` via the system resolver, or via `server` (using dig) if given."""
    if server is None:
        try:
            ip = socket.getaddrinfo(host, None)[0][4][0]
            return True, ip
        except socket.gaierror as e:
            return False, str(e)
    try:
        r = subprocess.run(
            ["dig", "+time=2", "+tries=1", "+short", f"@{server}", host],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        answer = [line for line in r.stdout.strip().splitlines() if line]
        if r.returncode == 0 and answer:
            return True, answer[-1]
        return False, "no answer"
    except Exception as e:
        return False, str(e)


def interface_up(name: str) -> bool:
    try:
        r = subprocess.run(
            ["ip", "-o", "link", "show", name], capture_output=True, text=True, timeout=3
        )
        return r.returncode == 0 and "LOWER_UP" in r.stdout
    except Exception:
        return False


def rocket_league_running() -> bool:
    """Same detection as ~/.local/bin/rocket-league-vpn-watch.sh, which stops
    wg-quick@wg0 while Rocket League is running (lower latency) — so a
    `vpn: down` here is a side effect of that script, not a real outage."""
    try:
        r = subprocess.run(
            ["pgrep", "-f", "-i", r"RocketLeague\.exe"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return r.returncode == 0
    except Exception:
        return False


def http_check(url: str, timeout: int = 8) -> tuple[bool, str, float | None]:
    req = Request(url, headers={"User-Agent": "netwatch/1.0"}, method="GET")
    ctx = ssl.create_default_context()
    t0 = time.monotonic()
    try:
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            elapsed = round((time.monotonic() - t0) * 1000, 1)
            return True, f"HTTP {resp.status}", elapsed
    except HTTPError as e:
        elapsed = round((time.monotonic() - t0) * 1000, 1)
        # The server answered at all, which is the thing we're actually
        # checking — a 4xx still means it's up. Only 5xx counts as down.
        return e.code < 500, f"HTTP {e.code}", elapsed
    except URLError as e:
        elapsed = round((time.monotonic() - t0) * 1000, 1)
        return False, str(e.reason), elapsed
    except Exception as e:
        return False, str(e), None


def run_checks(cfg: dict) -> list[CheckResult]:
    net = cfg.get("network", {})
    internet_probe = net.get("internet_probe", "1.1.1.1")
    dns_probe_host = net.get("dns_probe_host", "cloudflare.com")
    vpn_interface = net.get("vpn_interface", "wg0")
    vpn_gateway = net.get("vpn_gateway")
    vpn_dns_server = net.get("vpn_dns_server")

    results: list[CheckResult] = []

    ok, latency = ping(internet_probe)
    results.append(CheckResult("internet", ok, f"ping {internet_probe}", latency, group="network"))
    internet_ok = ok

    if internet_ok:
        ok, detail = resolve(dns_probe_host)
        results.append(CheckResult("dns", ok, f"resolve {dns_probe_host} -> {detail}", group="network"))
    else:
        results.append(CheckResult("dns", False, "skipped: no internet", skipped=True, group="network"))

    vpn_ok = False
    if vpn_gateway:
        if not internet_ok:
            results.append(CheckResult("vpn", False, "skipped: no internet", skipped=True, group="network"))
        elif interface_up(vpn_interface):
            ok, latency = ping(vpn_gateway)
            detail = (
                f"{vpn_interface} up, ping {vpn_gateway}"
                if ok
                else f"{vpn_interface} up, gateway {vpn_gateway} unreachable"
            )
            results.append(CheckResult("vpn", ok, detail, latency, group="network"))
            vpn_ok = ok
        else:
            rl = rocket_league_running()
            detail = f"{vpn_interface} is down"
            if rl:
                detail += " (Rocket League running)"
            results.append(CheckResult("vpn", False, detail, expected=rl, group="network"))

    if vpn_dns_server:
        if not internet_ok:
            results.append(CheckResult("vpn_dns", False, "skipped: no internet", skipped=True, group="network"))
        elif vpn_ok:
            ok, detail = resolve(dns_probe_host, server=vpn_dns_server)
            results.append(
                CheckResult("vpn_dns", ok, f"resolve via {vpn_dns_server} -> {detail}", group="network")
            )
        else:
            results.append(CheckResult("vpn_dns", False, "skipped: VPN down", skipped=True, group="network"))

    for t in cfg.get("targets", []):
        name, url, kind = t["name"], t["url"], t.get("kind", "public")
        if kind == "internal":
            if not vpn_ok:
                results.append(CheckResult(name, False, "skipped: VPN down", skipped=True))
                continue
        elif not internet_ok:
            results.append(CheckResult(name, False, "skipped: no internet", skipped=True))
            continue
        ok, detail, latency = http_check(url)
        host = urlparse(url).hostname
        if host:
            _, ping_avg = ping(host)
            if ping_avg is not None:
                latency = ping_avg
        results.append(CheckResult(name, ok, detail, latency))

    return results


# ── Ad hoc single-target checks (--check-domain / --check-ip) ─────────────
# Independent of targets.toml and the layered cascade above — for "what's
# going on with this one domain/IP right now" rather than continuous
# watching. Local tools only, same privacy policy as the rest of netwatch:
# no WHOIS, no GeoIP/ASN, no third-party service.

COMMON_PORTS = [22, 53, 80, 443, 3389]  # ssh, dns, http, https, rdp


def tcp_connect(host: str, port: int, timeout: float = 2.0) -> dict:
    t0 = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"open": True, "latency_ms": round((time.monotonic() - t0) * 1000, 1)}
    except Exception as e:
        return {"open": False, "error": str(e)}


def tls_cert_info(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Issuer/subject/expiry of the cert `host` actually presents on `port`.
    Fills the "no TLS cert-expiry check" gap noted in the known gaps below —
    the layered `targets` cascade only sees cert problems indirectly, as a
    generic HTTP failure."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
        expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        return {
            "ok": True,
            "subject": subject.get("commonName", host),
            "issuer": issuer.get("organizationName", issuer.get("commonName", "?")),
            "expires": expires.isoformat(),
            "days_remaining": (expires - datetime.now(timezone.utc)).days,
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}


def check_domain(domain: str) -> dict:
    """Essential one-off checks for a single domain: DNS, ping, HTTP/HTTPS,
    TLS cert expiry. Not gated on any upstream layer — this is meant for
    ad hoc "is example.com okay" lookups, not the continuous cascade."""
    result: dict = {"domain": domain}

    try:
        addrs = sorted({info[4][0] for info in socket.getaddrinfo(domain, None)})
        result["dns"] = {"ok": True, "addresses": addrs}
    except socket.gaierror as e:
        result["dns"] = {"ok": False, "error": str(e)}

    ok, latency = ping(domain)
    result["ping"] = {"ok": ok, "latency_ms": latency}

    for scheme in ("http", "https"):
        ok, detail, latency = http_check(f"{scheme}://{domain}")
        result[scheme] = {"ok": ok, "detail": detail, "latency_ms": latency}

    result["tls"] = tls_cert_info(domain)
    return result


def check_ip(ip: str) -> dict:
    """Essential one-off checks for a single IP: reverse DNS, ping, and TCP
    connect against a small fixed set of common ports (COMMON_PORTS) — no
    external port-scan tool, just stdlib socket.connect."""
    result: dict = {"ip": ip}

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        result["rdns"] = {"ok": True, "hostname": hostname}
    except socket.herror as e:
        result["rdns"] = {"ok": False, "error": str(e)}

    ok, latency = ping(ip)
    result["ping"] = {"ok": ok, "latency_ms": latency}

    result["ports"] = {port: tcp_connect(ip, port) for port in COMMON_PORTS}
    return result


def print_domain_report(result: dict):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"netwatch — domain check: {result['domain']} — {now}")
    print("─" * 48)

    dns = result["dns"]
    if dns["ok"]:
        print(f"{_GREEN}✔{_RESET} {'dns':<10} {_DIM}{', '.join(dns['addresses'])}{_RESET}")
    else:
        print(f"{_RED}✖{_RESET} {'dns':<10} {_DIM}{dns['error']}{_RESET}")

    p = result["ping"]
    mark, color = ("✔", _GREEN) if p["ok"] else ("✖", _RED)
    lat = f"  {p['latency_ms']:.0f}ms" if p["latency_ms"] is not None else ""
    print(f"{color}{mark}{_RESET} {'ping':<10} {_DIM}{'reachable' if p['ok'] else 'unreachable'}{_RESET}{lat}")

    for scheme in ("http", "https"):
        r = result[scheme]
        mark, color = ("✔", _GREEN) if r["ok"] else ("✖", _RED)
        lat = f"  {r['latency_ms']:.0f}ms" if r["latency_ms"] is not None else ""
        print(f"{color}{mark}{_RESET} {scheme:<10} {_DIM}{r['detail']}{_RESET}{lat}")

    tls = result["tls"]
    if tls["ok"]:
        days = tls["days_remaining"]
        color = _GREEN if days > 14 else _YELLOW if days > 0 else _RED
        print(
            f"{color}✔{_RESET} {'tls':<10} "
            f"{_DIM}{tls['subject']} issued by {tls['issuer']}, "
            f"expires {tls['expires'][:10]} ({days}d){_RESET}"
        )
    else:
        print(f"{_RED}✖{_RESET} {'tls':<10} {_DIM}{tls['error']}{_RESET}")
    print("─" * 48)


def print_ip_report(result: dict):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"netwatch — IP check: {result['ip']} — {now}")
    print("─" * 48)

    rdns = result["rdns"]
    if rdns["ok"]:
        print(f"{_GREEN}✔{_RESET} {'rdns':<10} {_DIM}{rdns['hostname']}{_RESET}")
    else:
        print(f"{_YELLOW}?{_RESET} {'rdns':<10} {_DIM}no reverse record ({rdns['error']}){_RESET}")

    p = result["ping"]
    mark, color = ("✔", _GREEN) if p["ok"] else ("✖", _RED)
    lat = f"  {p['latency_ms']:.0f}ms" if p["latency_ms"] is not None else ""
    print(f"{color}{mark}{_RESET} {'ping':<10} {_DIM}{'reachable' if p['ok'] else 'unreachable'}{_RESET}{lat}")

    print(f"{_DIM}ports{_RESET}")
    for port, info in result["ports"].items():
        if info["open"]:
            lat = f"  {info['latency_ms']:.0f}ms" if info.get("latency_ms") is not None else ""
            print(f"  {_GREEN}open  {_RESET} {port}{lat}")
        else:
            print(f"  {_DIM}closed {port}{_RESET}")
    print("─" * 48)


def mtr_report(host: str, cycles: int = 10, timeout: float = 30.0) -> dict:
    """Hop-by-hop path check via `mtr --report`. A plain ping only tells you
    whether the far end responds; this pinpoints which hop along the route
    is dropping packets or adding latency. No root needed — like ping()
    elsewhere in this file, it rides the kernel's unprivileged ICMP socket
    support (net.ipv4.ping_group_range) rather than mtr running setuid."""
    try:
        r = subprocess.run(
            ["mtr", "--report", "--report-cycles", str(cycles), host],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except Exception as e:
        return {"host": host, "ok": False, "error": str(e), "hops": []}

    if r.returncode != 0:
        return {"host": host, "ok": False, "error": (r.stderr or r.stdout).strip(), "hops": []}

    hops = []
    for line in r.stdout.splitlines():
        parts = line.split()
        # Report lines are exactly: "N.|--  host  loss%  Snt  Last  Avg  Best  Wrst  StDev"
        if len(parts) != 9 or not parts[0].split(".")[0].isdigit():
            continue
        hop_num, hop_host, loss, _snt, _last, avg, _best, _wrst, _stdev = parts
        hops.append({
            "hop": int(hop_num.split(".")[0]),
            "host": hop_host,
            "loss_pct": float(loss.rstrip("%")),
            "avg_ms": None if avg == "?" else float(avg),
        })
    return {"host": host, "ok": True, "hops": hops}


def print_mtr_report(result: dict):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"netwatch — hops to {result['host']} — {now}")
    print("─" * 48)
    if not result["ok"]:
        print(f"{_RED}✖{_RESET} {_DIM}{result['error']}{_RESET}")
        print("─" * 48)
        return
    for h in result["hops"]:
        loss = h["loss_pct"]
        color = _GREEN if loss == 0 else _YELLOW if loss < 20 else _RED
        avg = f"{h['avg_ms']:.1f}ms" if h["avg_ms"] is not None else "?"
        print(f"{color}{h['hop']:>2}{_RESET}  {h['host']:<32} {_DIM}{loss:>5.1f}% loss{_RESET}  {avg}")
    print("─" * 48)


# ── Reporting ─────────────────────────────────────────────────────────────

_GREEN, _RED, _YELLOW, _DIM, _RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def print_report(results: list[CheckResult]):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    width = max((len(r.name) for r in results), default=8) + 2
    print(f"netwatch — {now}")

    def _section(title: str, rows: list[CheckResult]):
        if not rows:
            return
        print(f"{_DIM}{title}{_RESET}")
        for r in rows:
            if r.skipped:
                mark, color = "?", _YELLOW
            elif r.ok:
                mark, color = "✔", _GREEN
            elif r.expected:
                mark, color = "!", _YELLOW
            else:
                mark, color = "✖", _RED
            lat = f"  {r.latency_ms:.0f}ms" if r.latency_ms is not None else ""
            print(f"{color}{mark}{_RESET} {r.name:<{width}} {_DIM}{r.detail}{_RESET}{lat}")

    print("─" * 48)
    _section("Network", [r for r in results if r.group == "network"])
    print("─" * 48)
    _section("Targets", [r for r in results if r.group == "target"])
    print("─" * 48)
    failed = [r for r in results if not r.ok and not r.skipped and not r.expected]
    if failed:
        print(f"{_RED}{len(failed)} check(s) failed:{_RESET} " + ", ".join(r.name for r in failed))
    else:
        print(f"{_GREEN}All systems normal.{_RESET}")


def results_to_dict(results: list[CheckResult]) -> dict:
    return {
        "timestamp": datetime.now().isoformat(),
        "checks": [
            {
                "name": r.name,
                "ok": r.ok,
                "skipped": r.skipped,
                "expected": r.expected,
                "detail": r.detail,
                "latency_ms": r.latency_ms,
                "group": r.group,
            }
            for r in results
        ],
    }


# ── Watch mode: notify only on state transitions ────────────────────────

def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            return {}
    return {}


def save_state(state: dict):
    STATE_PATH.write_text(json.dumps(state, indent=2))


def save_latest(results: list[CheckResult]):
    """Full snapshot of the most recent cycle, for --tui (or anything else)
    to read without running its own checks."""
    LATEST_PATH.write_text(json.dumps(results_to_dict(results), indent=2))


def notify(title: str, body: str, urgency: str = "normal"):
    if not shutil.which("notify-send"):
        return
    try:
        subprocess.run(
            ["notify-send", "-u", urgency, "-a", "netwatch", title, body],
            capture_output=True,
            timeout=5,
        )
    except Exception:
        pass


def log_line(line: str):
    try:
        with open(LOG_PATH, "a") as f:
            f.write(f"{datetime.now().isoformat()} {line}\n")
    except Exception:
        pass


try:
    # Optional, machine-local, not part of the public repo (see .gitignore) —
    # sudoers scoping for the systemctl call is specific to one box. Its
    # absence just means the TUI's u/d VPN controls don't appear.
    from netwatch_vpn import vpn_action
except ImportError:
    vpn_action = None


def status_of(r: CheckResult) -> str:
    """Collapse ok/skipped/failed into one of three states for transition tracking."""
    if r.skipped:
        return "skipped"
    return "up" if r.ok else "down"


def run_watch(cfg: dict, interval: float):
    state = load_state()
    print(f"netwatch watching (interval={interval:.0f}s, Ctrl+C to stop)")
    try:
        while True:
            results = run_checks(cfg)
            for r in results:
                current = status_of(r)
                previous = state.get(r.name)
                if previous is not None and previous != current and current != "skipped":
                    if current == "down":
                        notify(f"\U0001f534 {r.name} is down", r.detail, urgency="critical")
                        log_line(f"DOWN {r.name}: {r.detail}")
                    elif current == "up" and previous == "down":
                        notify(f"\U0001f7e2 {r.name} recovered", r.detail)
                        log_line(f"UP {r.name}: {r.detail}")
                state[r.name] = current
            save_state(state)
            save_latest(results)
            print_report(results)
            print()
            time.sleep(interval)
    except KeyboardInterrupt:
        pass


# ── TUI: live view of the running --watch service's latest snapshot ───────
# Reads .latest.json rather than running its own checks, so opening/closing
# the TUI never doubles up on network probes against the background service.

def run_tui(refresh: float, vpn_interface: str):
    import curses

    def _safe_addstr(win, y, x, text, attr=0):
        h, w = win.getmaxyx()
        if 0 <= y < h and x < w:
            try:
                win.addstr(y, x, text[: max(0, w - x - 1)], attr)
            except curses.error:
                pass

    def _prompt(stdscr, label: str) -> str | None:
        """Blocking text input on the status line — used for the on-demand
        domain/IP/hop checks below. Temporarily drops nodelay so getstr()
        actually waits for Enter instead of returning immediately."""
        h, w = stdscr.getmaxyx()
        _safe_addstr(stdscr, h - 2, 0, " " * (w - 1), curses.A_REVERSE)
        _safe_addstr(stdscr, h - 2, 0, f" {label}", curses.A_REVERSE)
        stdscr.refresh()
        curses.curs_set(1)
        curses.echo()
        stdscr.nodelay(False)
        stdscr.timeout(-1)
        try:
            raw = stdscr.getstr(h - 2, len(label) + 1, 60)
            text = raw.decode("utf-8", "ignore").strip()
        except Exception:
            text = ""
        curses.noecho()
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(int(refresh * 1000))
        return text or None

    def _domain_overlay(result: dict) -> list[tuple[str, int]]:
        lines: list[tuple[str, int]] = [(f"Domain check: {result['domain']}", 0)]
        dns = result["dns"]
        lines.append(
            (f"  dns      {', '.join(dns['addresses'])}", 1) if dns["ok"]
            else (f"  dns      {dns['error']}", 2)
        )
        p = result["ping"]
        lat = f" {p['latency_ms']:.0f}ms" if p["latency_ms"] is not None else ""
        lines.append((f"  ping     {'reachable' if p['ok'] else 'unreachable'}{lat}", 1 if p["ok"] else 2))
        for scheme in ("http", "https"):
            r = result[scheme]
            lat = f" {r['latency_ms']:.0f}ms" if r["latency_ms"] is not None else ""
            lines.append((f"  {scheme:<8} {r['detail']}{lat}", 1 if r["ok"] else 2))
        tls = result["tls"]
        if tls["ok"]:
            days = tls["days_remaining"]
            pair = 1 if days > 14 else 3 if days > 0 else 2
            lines.append((f"  tls      {tls['subject']} via {tls['issuer']}, expires {tls['expires'][:10]} ({days}d)", pair))
        else:
            lines.append((f"  tls      {tls['error']}", 2))
        return lines

    def _ip_overlay(result: dict) -> list[tuple[str, int]]:
        lines: list[tuple[str, int]] = [(f"IP check: {result['ip']}", 0)]
        rdns = result["rdns"]
        lines.append((f"  rdns     {rdns['hostname']}", 1) if rdns["ok"] else (f"  rdns     no reverse record", 3))
        p = result["ping"]
        lat = f" {p['latency_ms']:.0f}ms" if p["latency_ms"] is not None else ""
        lines.append((f"  ping     {'reachable' if p['ok'] else 'unreachable'}{lat}", 1 if p["ok"] else 2))
        lines.append(("  ports", 0))
        for port, info in result["ports"].items():
            if info["open"]:
                lines.append((f"    {port:<6} open   {info['latency_ms']:.0f}ms", 1))
            else:
                lines.append((f"    {port:<6} closed", 0))
        return lines

    def _mtr_overlay(result: dict) -> list[tuple[str, int]]:
        lines: list[tuple[str, int]] = [(f"Hops to {result['host']}", 0)]
        if not result["ok"]:
            lines.append((f"  {result['error']}", 2))
            return lines
        for hop in result["hops"]:
            loss = hop["loss_pct"]
            pair = 1 if loss == 0 else 3 if loss < 20 else 2
            avg = f"{hop['avg_ms']:.1f}ms" if hop["avg_ms"] is not None else "?"
            lines.append((f"  {hop['hop']:>2}  {hop['host']:<32} {loss:>5.1f}% loss  {avg}", pair))
        return lines

    def _draw(stdscr):
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_GREEN, -1)
        curses.init_pair(2, curses.COLOR_RED, -1)
        curses.init_pair(3, curses.COLOR_YELLOW, -1)
        stdscr.nodelay(True)
        stdscr.timeout(int(refresh * 1000))

        pending_up: bool | None = None  # awaiting y/n confirm for vpn up(True)/down(False)
        status_msg = ""
        status_until = 0.0
        overlay: list[tuple[str, int]] | None = None  # set by c/i/t, cleared by any keypress

        while True:
            key = stdscr.getch()
            now = time.monotonic()

            if overlay is not None:
                if key != -1:
                    overlay = None
            elif pending_up is not None:
                if key in (ord("y"), ord("Y")):
                    ok, detail = vpn_action(vpn_interface, pending_up)
                    status_msg = f"{'OK' if ok else 'FAILED'}: {detail}"
                    log_line(f"ACTION vpn {'up' if pending_up else 'down'}: {detail}")
                    status_until = now + 4
                    pending_up = None
                elif key != -1:
                    status_msg, status_until, pending_up = "cancelled", now + 2, None
            elif key in (ord("q"), ord("Q"), 27):  # 27 = Esc
                break
            elif vpn_action is not None and key in (ord("d"), ord("D")):
                pending_up = False
            elif vpn_action is not None and key in (ord("u"), ord("U")):
                pending_up = True
            elif key in (ord("c"), ord("C")):
                domain = _prompt(stdscr, "Domain to check (Enter to cancel): ")
                if domain:
                    overlay = _domain_overlay(check_domain(domain))
            elif key in (ord("i"), ord("I")):
                ip = _prompt(stdscr, "IP to check (Enter to cancel): ")
                if ip:
                    try:
                        ipaddress.ip_address(ip)
                        overlay = _ip_overlay(check_ip(ip))
                    except ValueError:
                        overlay = [(f"Not a valid IP address: {ip}", 2)]
            elif key in (ord("t"), ord("T")):
                host = _prompt(stdscr, "Host to trace (Enter to cancel): ")
                if host:
                    overlay = _mtr_overlay(mtr_report(host))

            stdscr.erase()
            h, w = stdscr.getmaxyx()

            if overlay is not None:
                _safe_addstr(stdscr, 0, 0, " netwatch — details  (any key to return) ".ljust(w), curses.A_BOLD | curses.A_REVERSE)
                for idx, (text, pair) in enumerate(overlay):
                    row = idx + 2
                    if row >= h - 1:
                        break
                    attr = (curses.color_pair(pair) if pair else 0) | (curses.A_BOLD if idx == 0 else 0)
                    _safe_addstr(stdscr, row, 1, text, attr)
                stdscr.refresh()
                continue

            data = None
            if LATEST_PATH.exists():
                try:
                    data = json.loads(LATEST_PATH.read_text())
                except Exception:
                    data = None

            _safe_addstr(stdscr, 0, 0, " netwatch ".ljust(w), curses.A_BOLD | curses.A_REVERSE)

            if data is None:
                _safe_addstr(stdscr, 2, 1, "No data yet — is the netwatch service running?", curses.color_pair(3))
                _safe_addstr(stdscr, 3, 1, "Check with: systemctl --user status netwatch")
            else:
                ts = datetime.fromisoformat(data["timestamp"])
                age = (datetime.now() - ts).total_seconds()
                stale = age > 75
                _safe_addstr(
                    stdscr, 1, 0,
                    f" last update {ts.strftime('%H:%M:%S')} ({age:.0f}s ago)",
                    curses.color_pair(3) if stale else curses.A_DIM,
                )
                if stale:
                    _safe_addstr(stdscr, 1, w - 28, "service may be stopped", curses.color_pair(3))

                checks = data["checks"]
                name_w = max((len(c["name"]) for c in checks), default=8) + 2
                row = 3
                fails = 0
                expected_down = 0

                network_checks = [c for c in checks if c.get("group") == "network"]
                target_checks = [c for c in checks if c.get("group") != "network"]

                def _draw_section(title, rows):
                    nonlocal row, fails, expected_down
                    if not rows or row >= h - 2:
                        return
                    _safe_addstr(stdscr, row, 0, title, curses.A_BOLD | curses.A_UNDERLINE)
                    row += 1
                    for c in rows:
                        if row >= h - 2:
                            break
                        if c["skipped"]:
                            mark, pair = " ? ", 3
                        elif c["ok"]:
                            mark, pair = " OK ", 1
                        elif c.get("expected"):
                            mark, pair = " RL ", 3
                            expected_down += 1
                        else:
                            mark, pair = " X  ", 2
                            fails += 1
                        latency = f"  {c['latency_ms']:.0f}ms" if c.get("latency_ms") is not None else ""
                        _safe_addstr(stdscr, row, 0, mark, curses.color_pair(pair) | curses.A_BOLD)
                        _safe_addstr(stdscr, row, 5, f"{c['name']:<{name_w}} {c['detail']}{latency}")
                        row += 1
                    row += 1

                _draw_section("Network", network_checks)
                _draw_section("Targets", target_checks)

                if fails:
                    summary = f"{fails} check(s) failed."
                elif expected_down:
                    summary = "All systems normal (VPN down for Rocket League)."
                else:
                    summary = "All systems normal."
                _safe_addstr(
                    stdscr, row, 0, summary,
                    curses.color_pair(2) if fails else curses.color_pair(3) if expected_down else curses.color_pair(1),
                )

            if pending_up is not None:
                verb = "start" if pending_up else "stop"
                _safe_addstr(
                    stdscr, h - 2, 0,
                    f" {verb} wg-quick@{vpn_interface}? y/n ".ljust(w - 1),
                    curses.color_pair(3) | curses.A_REVERSE,
                )
            elif status_msg and now < status_until:
                _safe_addstr(stdscr, h - 2, 0, f" {status_msg} ".ljust(w - 1), curses.A_BOLD)

            vpn_keys = "u: vpn up  d: vpn down  " if vpn_action is not None else ""
            _safe_addstr(
                stdscr, h - 1, 0,
                f" q: quit  {vpn_keys}c: check domain  i: check ip  t: hops (mtr) ".ljust(w - 1),
                curses.A_REVERSE,
            )
            stdscr.refresh()

    curses.wrapper(_draw)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="one-shot check, JSON output")
    parser.add_argument("--watch", action="store_true", help="loop forever, notify on transitions")
    parser.add_argument("--interval", type=float, default=30, help="seconds between checks in --watch (default 30)")
    parser.add_argument("--tui", action="store_true", help="live curses view of the running --watch service (reads .latest.json, runs no checks itself)")
    parser.add_argument("--tui-refresh", type=float, default=2.0, help="seconds between TUI redraws (default 2)")
    parser.add_argument(
        "--check-domain", metavar="DOMAIN",
        help="one-off essential checks (DNS, ping, HTTP/HTTPS, TLS cert expiry) for a domain, outside targets.toml",
    )
    parser.add_argument(
        "--check-ip", metavar="IP",
        help="one-off essential checks (reverse DNS, ping, common port connectivity) for an IP",
    )
    parser.add_argument(
        "--mtr", metavar="HOST",
        help="hop-by-hop path check (mtr --report) against a domain or IP, to see which hop is dropping packets or adding latency",
    )
    parser.add_argument("--mtr-cycles", type=int, default=10, help="ping cycles per hop for --mtr (default 10)")
    args = parser.parse_args()

    if args.check_domain:
        result = check_domain(args.check_domain)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_domain_report(result)
        sys.exit(0 if result["dns"]["ok"] and result["ping"]["ok"] else 1)

    if args.check_ip:
        try:
            ipaddress.ip_address(args.check_ip)
        except ValueError:
            sys.exit(f"Not a valid IP address: {args.check_ip}")
        result = check_ip(args.check_ip)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_ip_report(result)
        sys.exit(0 if result["ping"]["ok"] else 1)

    if args.mtr:
        result = mtr_report(args.mtr, cycles=args.mtr_cycles)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_mtr_report(result)
        sys.exit(0 if result["ok"] else 1)

    cfg = load_config()

    if args.tui:
        vpn_interface = cfg.get("network", {}).get("vpn_interface", "wg0")
        run_tui(args.tui_refresh, vpn_interface)
        return

    if args.watch:
        run_watch(cfg, args.interval)
        return

    results = run_checks(cfg)
    if args.json:
        print(json.dumps(results_to_dict(results), indent=2))
    else:
        print_report(results)

    if any(not r.ok and not r.skipped for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
