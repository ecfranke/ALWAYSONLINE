#!/usr/bin/env python3
"""
ddns-cf — Cloudflare DDNS + network watchdog for Debian / Ubuntu VPS.

Features
  1. Cloudflare DDNS: keeps A (IPv4) and AAAA (IPv6) records in sync with the public IP.
  2. All credentials / settings are read from a .env file.
  3. PPPoE uplink preference (PPP_ENABLE, pppd / pon):
       - while ppp0 is up, the system IPv4 default route is forced onto ppp0
         (other default routes are kept as higher-metric backups)
       - when ppp0 drops: redial with poff/pon; if that fails, fall back to DHCP on the
         physical NIC and keep redialing every PPP_RETRY_INTERVAL seconds (default 60);
         as soon as ppp0 is back, traffic switches back to it and DDNS is re-synced
       - only ppp0 may exist: the pppd behind any other pppN (e.g. ppp1) is terminated
  4. Watchdog: detects network loss and recovers automatically, escalating:
       L0  PPP redial        (poff + pon, only when PPP is enabled)
       L1  DHCP renew        (networkctl renew / nmcli reapply / dhclient / dhcpcd)
       L2  restart network   (netplan apply / systemd-networkd / NetworkManager / networking)
       L3  reboot            (optional, off by default)
  5. Designed to run as a systemd service (see ddns-cf.service / install.sh).

Pure Python 3 standard library (3.8+). No pip packages needed.

Usage
  ddns_cf.py run        # daemon: watchdog + periodic DDNS (default)
  ddns_cf.py ddns       # one-shot DDNS update, then exit
  ddns_cf.py check      # print config, PPP / route status, network stack, connectivity, public IPs
  ddns_cf.py dial       # (re)dial PPP once and point the default route at it (needs root)
  ddns_cf.py recover    # run the recovery sequence once (for testing, needs root)
Options
  --env PATH            # .env location (default: .env next to this script, then /opt/ddns-cf/.env)
"""

import argparse
import json
import logging
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Tuple

VERSION = "1.1.0"
log = logging.getLogger("ddns-cf")
_stop = False  # set by SIGTERM / SIGINT

# ─────────────────────────────── .env handling ────────────────────────────────

DEFAULTS = {
    "CF_API_TOKEN": "",
    "CF_ZONE_ID": "",            # optional; looked up from the record name if empty
    "CF_RECORDS": "",            # comma separated FQDNs, e.g. home.example.com,vps.example.com
    "CF_ENABLE_IPV4": "true",
    "CF_ENABLE_IPV6": "true",
    "CF_CREATE_MISSING": "true", # create the record if it does not exist
    "CF_PROXIED": "false",       # only used when creating a record
    "CF_TTL": "60",              # only used when creating a record (1 = auto)
    "CF_API_BASE": "https://api.cloudflare.com/client/v4",
    "IPV4_SOURCES": "https://api.ipify.org,https://ipv4.icanhazip.com,https://1.1.1.1/cdn-cgi/trace",
    "IPV6_SOURCES": "https://api6.ipify.org,https://ipv6.icanhazip.com,https://[2606:4700:4700::1111]/cdn-cgi/trace",
    "DDNS_INTERVAL": "300",      # seconds between DDNS checks
    "DDNS_FORCE_SYNC": "3600",   # re-verify records with Cloudflare at least this often, even if IP unchanged
    "CHECK_INTERVAL": "30",      # seconds between connectivity checks
    "CHECK_TARGETS": "1.1.1.1,8.8.8.8,9.9.9.9",
    "CHECK_METHOD": "auto",      # auto | ping | tcp
    "CHECK_TCP_PORT": "443",
    "FAIL_THRESHOLD": "3",       # consecutive failed checks before recovery starts
    "NET_IFACE": "",             # physical NIC for DHCP fallback / recovery; auto-detected if empty
    "PPP_ENABLE": "auto",        # auto = on if /etc/ppp/peers/$PPP_PROVIDER exists | true | false
    "PPP_IFACE": "ppp0",         # the only ppp interface allowed; others (ppp1...) get terminated
    "PPP_PROVIDER": "dsl-provider",  # peer name for pon/poff (pppoeconf default)
    "PPP_DIAL_TIMEOUT": "30",    # seconds to wait for PPP_IFACE to get an IPv4 after pon
    "PPP_RETRY_INTERVAL": "60",  # while PPP is down, redial this often (DHCP is used in between)
    "PPP_ROUTE_METRIC": "0",     # metric of the default route via PPP_IFACE
    "RECOVERY_WAIT": "20",       # seconds to wait after each recovery step before re-checking
    "RECOVERY_COOLDOWN": "300",  # seconds between full recovery rounds
    "REBOOT_ON_FAILURE": "false",
    "REBOOT_AFTER_ROUNDS": "3",  # failed recovery rounds before reboot (if enabled)
    "BOOT_GRACE": "60",          # don't start recovery within N seconds of service start
    "HTTP_TIMEOUT": "15",
    "LOG_LEVEL": "INFO",
}


def load_env(path: str) -> Dict[str, str]:
    cfg = dict(DEFAULTS)
    if not os.path.isfile(path):
        raise SystemExit("config not found: %s  (copy .env.example to .env and edit it)" % path)
    with open(path, "r", encoding="utf-8") as f:
        for n, raw in enumerate(f, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].lstrip()
            if "=" not in line:
                log.warning("%s:%d ignored (no '=')", path, n)
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip()
            if v[:1] in ("'", '"') and v.find(v[0], 1) > 0:   # KEY="value"  # comment
                v = v[1:v.find(v[0], 1)]
            elif " #" in v:
                v = v.split(" #", 1)[0].rstrip()
            cfg[k] = v
    # real environment variables override the file (handy for testing)
    for k in list(cfg):
        if k in os.environ:
            cfg[k] = os.environ[k]
    return cfg


def b(cfg, k) -> bool:
    return str(cfg.get(k, "")).strip().lower() in ("1", "true", "yes", "on")


def i(cfg, k) -> int:
    try:
        return int(str(cfg[k]).strip())
    except (KeyError, ValueError):
        return int(DEFAULTS[k])


def lst(cfg, k) -> List[str]:
    return [x.strip() for x in str(cfg.get(k, "")).split(",") if x.strip()]


# ─────────────────────────────── HTTP helpers ─────────────────────────────────

class _ForceFamily:
    """Temporarily force socket.getaddrinfo to one address family (IPv4 or IPv6)."""

    def __init__(self, family):
        self.family = family
        self._orig = socket.getaddrinfo

    def __enter__(self):
        orig, fam = self._orig, self.family

        def patched(host, port, family=0, *a, **kw):
            return orig(host, port, fam, *a, **kw)

        socket.getaddrinfo = patched
        return self

    def __exit__(self, *exc):
        socket.getaddrinfo = self._orig


def http(method: str, url: str, timeout: int, headers=None, body=None) -> Tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "ddns-cf/%s" % VERSION)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def _valid_ip(ip: str, family) -> bool:
    try:
        socket.inet_pton(family, ip)
        return True
    except (OSError, ValueError):
        return False


def public_ip(cfg, v6: bool) -> Optional[str]:
    family = socket.AF_INET6 if v6 else socket.AF_INET
    sources = lst(cfg, "IPV6_SOURCES" if v6 else "IPV4_SOURCES")
    for url in sources:
        try:
            with _ForceFamily(family):
                code, text = http("GET", url, i(cfg, "HTTP_TIMEOUT"))
            if code != 200:
                continue
            ip = text.strip()
            if "ip=" in text:  # cloudflare /cdn-cgi/trace format
                for line in text.splitlines():
                    if line.startswith("ip="):
                        ip = line[3:].strip()
            if _valid_ip(ip, family):
                return ip
        except Exception as e:  # noqa: BLE001
            log.debug("IP source %s failed: %s", url, e)
    return None


# ─────────────────────────────── Cloudflare ───────────────────────────────────

class CFError(Exception):
    pass


class Cloudflare:
    def __init__(self, cfg):
        self.cfg = cfg
        self.base = cfg["CF_API_BASE"].rstrip("/")
        self.timeout = i(cfg, "HTTP_TIMEOUT")
        self.headers = {"Authorization": "Bearer %s" % cfg["CF_API_TOKEN"]}
        self._zone_cache: Dict[str, str] = {}

    def _call(self, method, path, body=None):
        code, text = http(method, self.base + path, self.timeout, self.headers, body)
        try:
            js = json.loads(text)
        except ValueError:
            raise CFError("HTTP %s, non-JSON response" % code)
        if not js.get("success"):
            errs = "; ".join("%s: %s" % (e.get("code"), e.get("message")) for e in js.get("errors", []))
            raise CFError("HTTP %s %s" % (code, errs or text[:200]))
        return js["result"]

    def verify_token(self):
        return self._call("GET", "/user/tokens/verify")

    def zone_id(self, fqdn: str) -> str:
        if self.cfg.get("CF_ZONE_ID"):
            return self.cfg["CF_ZONE_ID"]
        labels = fqdn.rstrip(".").split(".")
        for n in range(len(labels) - 1):
            cand = ".".join(labels[n:])
            if cand in self._zone_cache:
                return self._zone_cache[cand]
            res = self._call("GET", "/zones?name=%s" % cand)
            if res:
                self._zone_cache[cand] = res[0]["id"]
                return res[0]["id"]
        raise CFError("no Cloudflare zone found for %s (set CF_ZONE_ID or give the token Zone:Read)" % fqdn)

    def sync(self, fqdn: str, rtype: str, ip: str) -> str:
        zid = self.zone_id(fqdn)
        recs = self._call("GET", "/zones/%s/dns_records?type=%s&name=%s" % (zid, rtype, fqdn))
        if not recs:
            if not b(self.cfg, "CF_CREATE_MISSING"):
                return "missing (CF_CREATE_MISSING=false)"
            self._call("POST", "/zones/%s/dns_records" % zid, {
                "type": rtype, "name": fqdn, "content": ip,
                "ttl": i(self.cfg, "CF_TTL"), "proxied": b(self.cfg, "CF_PROXIED"),
            })
            return "created -> %s" % ip
        rec = recs[0]
        if len(recs) > 1:
            log.warning("%s %s has %d records; only the first is managed", rtype, fqdn, len(recs))
        if rec.get("content") == ip:
            return "unchanged (%s)" % ip
        self._call("PATCH", "/zones/%s/dns_records/%s" % (zid, rec["id"]), {"content": ip})
        return "updated %s -> %s" % (rec.get("content"), ip)


class DDNS:
    def __init__(self, cfg):
        self.cfg = cfg
        self.cf = Cloudflare(cfg)
        self.last_ips: Dict[str, Optional[str]] = {"A": None, "AAAA": None}
        self.last_full_sync = 0.0

    def run(self, force=False) -> bool:
        records = lst(self.cfg, "CF_RECORDS")
        wanted = []
        if b(self.cfg, "CF_ENABLE_IPV4"):
            wanted.append(("A", public_ip(self.cfg, False)))
        if b(self.cfg, "CF_ENABLE_IPV6"):
            wanted.append(("AAAA", public_ip(self.cfg, True)))

        stale = time.time() - self.last_full_sync > i(self.cfg, "DDNS_FORCE_SYNC")
        ok = True
        for rtype, ip in wanted:
            if not ip:
                log.info("DDNS %s: no public %s address detected, skipped", rtype,
                         "IPv6" if rtype == "AAAA" else "IPv4")
                continue
            if not force and not stale and ip == self.last_ips[rtype]:
                log.debug("DDNS %s: IP unchanged (%s)", rtype, ip)
                continue
            type_ok = True
            for fqdn in records:
                try:
                    log.info("DDNS %s %s: %s", rtype, fqdn, self.cf.sync(fqdn, rtype, ip))
                except Exception as e:  # noqa: BLE001
                    ok = type_ok = False
                    log.error("DDNS %s %s failed: %s", rtype, fqdn, e)
            if type_ok:
                self.last_ips[rtype] = ip
        if ok and (force or stale):
            self.last_full_sync = time.time()
        return ok


# ─────────────────────────────── system helpers ───────────────────────────────

# interfaces that are never the physical / DHCP uplink
VIRTUAL_PREFIXES = ("lo", "ppp", "docker", "veth", "br-", "virbr", "tun", "tap", "wg", "tailscale", "zt")


def sh(cmd: List[str], timeout=60) -> Tuple[int, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout, universal_newlines=True)
        return p.returncode, p.stdout.strip()
    except FileNotFoundError:
        return 127, "not found"
    except subprocess.TimeoutExpired:
        return 124, "timeout"


def nap(sec: float) -> None:
    """sleep() that returns early on SIGTERM / SIGINT."""
    end = time.time() + sec
    while not _stop:
        left = end - time.time()
        if left <= 0:
            return
        time.sleep(min(1.0, left))


def wait_for(pred, sec: float) -> bool:
    """Poll pred() once per second for up to `sec` seconds."""
    end = time.time() + sec
    while True:
        if pred():
            return True
        if _stop or time.time() >= end:
            return False
        time.sleep(1)


def unit_active(name: str) -> bool:
    return sh(["systemctl", "is-active", "--quiet", name], 10)[0] == 0


def unit_exists(name: str) -> bool:
    code, out = sh(["systemctl", "list-unit-files", name, "--no-legend"], 10)
    return code == 0 and name in out


def _kv(parts: List[str], key: str) -> Optional[str]:
    """value following `key` in a tokenised `ip` output line."""
    try:
        return parts[parts.index(key) + 1]
    except (ValueError, IndexError):
        return None


# ─────────────────────────────── interfaces / routes ──────────────────────────

def iface_exists(name: Optional[str]) -> bool:
    return bool(name) and os.path.exists("/sys/class/net/%s" % name)


def iface_ipv4(name: str) -> Optional[str]:
    code, out = sh(["ip", "-4", "-o", "addr", "show", "dev", name], 5)
    if code == 0:
        for line in out.splitlines():
            ip = _kv(line.split(), "inet")
            if ip:
                return ip.split("/")[0]
    return None


def ppp_ifaces() -> List[str]:
    try:
        return sorted(n for n in os.listdir("/sys/class/net") if n.startswith("ppp"))
    except OSError:
        return []


def route_dev(probe: str) -> Optional[str]:
    """Interface the kernel would use right now to reach `probe` (no packet is sent)."""
    code, out = sh(["ip", "-4", "route", "get", probe], 5)
    return _kv(out.split(), "dev") if code == 0 else None


def default_routes() -> List[List[str]]:
    code, out = sh(["ip", "-4", "route", "show", "default"], 5)
    return [line.split() for line in out.splitlines() if line.strip()] if code == 0 else []


def ppp_peer_nic(provider: str) -> Optional[str]:
    """Ethernet NIC used by a PPPoE peer file (`nic-eth0`, `plugin rp-pppoe.so eth0`, or a bare `eth0`)."""
    try:
        with open(os.path.join("/etc/ppp/peers", provider)) as f:
            for line in f:
                t = line.split("#", 1)[0].split()
                if not t:
                    continue
                for tok in t:
                    if tok.startswith("nic-"):
                        return tok[4:]
                if t[0] == "plugin" and len(t) >= 3 and "pppoe" in t[1]:
                    return t[2]
                if len(t) == 1 and iface_exists(t[0]) and not t[0].startswith(VIRTUAL_PREFIXES):
                    return t[0]
    except OSError:
        pass
    return None


def dhcp_iface(cfg) -> Optional[str]:
    """Physical interface used for DHCP fallback / recovery (never a ppp interface)."""
    if cfg.get("NET_IFACE"):
        return cfg["NET_IFACE"]
    for fam in ("-4", "-6"):
        code, out = sh(["ip", fam, "route", "show", "default"], 5)
        for line in (out.splitlines() if code == 0 else []):
            dev = _kv(line.split(), "dev")
            if dev and not dev.startswith(VIRTUAL_PREFIXES):
                return dev
    nic = ppp_peer_nic(cfg.get("PPP_PROVIDER") or "dsl-provider")
    if nic:
        return nic
    # nothing routed (typical while offline): first non-virtual interface
    code, out = sh(["ip", "-o", "link", "show"], 5)
    for line in out.splitlines():
        name = line.split(":")[1].strip().split("@")[0] if ":" in line else ""
        if name and not name.startswith(VIRTUAL_PREFIXES):
            return name
    return None


def iface_is_dhcp_ifupdown(iface: str) -> bool:
    files = ["/etc/network/interfaces"]
    d = "/etc/network/interfaces.d"
    if os.path.isdir(d):
        files += [os.path.join(d, f) for f in sorted(os.listdir(d))]
    for fp in files:
        try:
            with open(fp) as f:
                for line in f:
                    p = line.split()
                    if len(p) >= 4 and p[0] == "iface" and p[1] == iface and p[3] == "dhcp":
                        return True
        except OSError:
            pass
    return False


def detect_stack() -> Dict[str, bool]:
    return {
        "netplan": shutil.which("netplan") is not None and os.path.isdir("/etc/netplan")
                   and any(f.endswith(".yaml") for f in os.listdir("/etc/netplan")),
        "networkd": unit_active("systemd-networkd"),
        "networkmanager": unit_active("NetworkManager"),
        "ifupdown": os.path.isfile("/etc/network/interfaces") and unit_exists("networking.service"),
        "dhclient": shutil.which("dhclient") is not None,
        "dhcpcd": shutil.which("dhcpcd") is not None,
    }


# ─────────────────────────────── pppd processes ───────────────────────────────

def _alive(pid: int) -> bool:
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def pppd_pids(provider: str = "") -> List[int]:
    """PIDs of running pppd processes (optionally only those started with `call <provider>`)."""
    pids = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % d, "rb") as f:
                argv = f.read().split(b"\0")
        except OSError:
            continue
        if argv and os.path.basename(argv[0]) == b"pppd" and (not provider or provider.encode() in argv):
            pids.append(int(d))
    return pids


def iface_pppd_pid(iface: str) -> Optional[int]:
    """pppd writes /run/<iface>.pid once the interface exists."""
    for d in ("/run", "/var/run"):
        try:
            with open(os.path.join(d, iface + ".pid")) as f:
                pid = int(f.readline().strip())
        except (OSError, ValueError):
            continue
        if _alive(pid):
            return pid
    return None


def kill_pid(pid: int, grace=5) -> None:
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    if wait_for(lambda: not _alive(pid), grace):
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


# ─────────────────────────────── Network watchdog ─────────────────────────────

class Watchdog:
    def __init__(self, cfg):
        self.cfg = cfg
        self.fails = 0
        self.failed_rounds = 0
        self.last_recovery = 0.0
        self.started = time.time()
        m = cfg.get("CHECK_METHOD", "auto").lower()
        self.method = ("ping" if shutil.which("ping") else "tcp") if m == "auto" else m
        # address used for `ip route get` (never actually contacted)
        self.probe = next((t for t in lst(cfg, "CHECK_TARGETS") if ":" not in t), "1.1.1.1")

        # PPP
        self.ppp_if = cfg.get("PPP_IFACE") or "ppp0"
        self.provider = cfg.get("PPP_PROVIDER") or "dsl-provider"
        mode = str(cfg.get("PPP_ENABLE", "auto")).strip().lower()
        self.ppp = os.path.isfile(os.path.join("/etc/ppp/peers", self.provider)) if mode == "auto" \
            else b(cfg, "PPP_ENABLE")
        self.uplink: Optional[str] = None     # "ppp" | "dhcp" (None until first decision / PPP disabled)
        self.last_dial = 0.0
        self.ppp_ip: Optional[str] = None     # last seen IPv4 on PPP_IFACE (new IP -> force DDNS)
        self._children: List[subprocess.Popen] = []

    # ---- connectivity ----
    def _probe(self, target: str) -> bool:
        if self.method == "ping":
            fam = "-6" if ":" in target else "-4"
            return sh(["ping", fam, "-c", "1", "-W", "3", target], 8)[0] == 0
        try:
            fam = socket.AF_INET6 if ":" in target else socket.AF_INET
            with socket.socket(fam, socket.SOCK_STREAM) as s:
                s.settimeout(4)
                s.connect((target, i(self.cfg, "CHECK_TCP_PORT")))
            return True
        except OSError:
            return False

    def online(self) -> bool:
        return any(self._probe(t) for t in lst(self.cfg, "CHECK_TARGETS"))

    # ---- PPP ----
    def ppp_up(self) -> bool:
        return iface_exists(self.ppp_if) and iface_ipv4(self.ppp_if) is not None

    def kill_extra_ppp(self) -> None:
        """Only PPP_IFACE may exist: terminate the pppd behind any other pppN (e.g. a stray ppp1)."""
        extras = [n for n in ppp_ifaces() if n != self.ppp_if]
        if not extras:
            return
        keep = iface_pppd_pid(self.ppp_if)
        for name in extras:
            pid = iface_pppd_pid(name)
            victims = [pid] if pid and pid != keep else [p for p in pppd_pids() if p != keep]
            for p in victims:
                log.warning("PPP: extra interface %s found, terminating pppd %d (keeping only %s)",
                            name, p, self.ppp_if)
                kill_pid(p)

    def _spawn(self, cmd: List[str]) -> None:
        # pppd normally daemonises, but with `nodetach`/`updetach` it would block or be killed by
        # a timeout, so run it detached and never kill it.
        try:
            self._children.append(subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                start_new_session=True))
        except OSError as e:
            log.error("PPP: cannot run %s: %s", cmd[0], e)

    def _reap(self) -> None:
        self._children = [p for p in self._children if p.poll() is None]

    def ppp_dial(self, force=False) -> bool:
        """Bring PPP_IFACE up with poff/pon and wait PPP_DIAL_TIMEOUT for an IPv4 address.
        force=True hangs up and redials even if the link looks up."""
        first = self.last_dial == 0.0
        self.last_dial = time.time()
        if not shutil.which("pon"):
            log.error("PPP: 'pon' not found (apt install ppp)")
            return False
        timeout = i(self.cfg, "PPP_DIAL_TIMEOUT")
        self.kill_extra_ppp()
        if not force:
            if self.ppp_up():
                return True
            # at boot ifupdown may already be dialing: give that pppd a chance first
            if first and pppd_pids(self.provider):
                log.info("PPP: pppd for %s already running, waiting up to %ss", self.provider, timeout)
                if wait_for(self.ppp_up, timeout):
                    self.kill_extra_ppp()
                    return True
        if pppd_pids(self.provider) or iface_exists(self.ppp_if):
            log.warning("PPP: poff %s", self.provider)
            sh(["poff", self.provider], 15)
            wait_for(lambda: not pppd_pids(self.provider) and not iface_exists(self.ppp_if), 10)
        unit = self.ppp_if[3:] if self.ppp_if.startswith("ppp") and self.ppp_if[3:].isdigit() else None
        cmd = ["pon", self.provider] + (["unit", unit] if unit else [])   # ask pppd for ppp0, not ppp1
        log.warning("PPP: dialing (%s)", " ".join(cmd))
        self._spawn(cmd)
        ok = wait_for(self.ppp_up, timeout)
        self.kill_extra_ppp()
        if ok:
            log.warning("PPP: %s is up, IPv4 %s", self.ppp_if, iface_ipv4(self.ppp_if))
        else:
            log.warning("PPP: %s did not come up within %ss", self.ppp_if, timeout)
        return ok

    # ---- routes ----
    def ensure_ppp_route(self) -> None:
        """Make PPP_IFACE the IPv4 default route; other default routes are kept as backups."""
        if route_dev(self.probe) == self.ppp_if:
            return
        metric = i(self.cfg, "PPP_ROUTE_METRIC")
        for r in default_routes():
            if _kv(r, "dev") != self.ppp_if and int(_kv(r, "metric") or 0) <= metric:
                self._demote(r, metric)
        code, out = sh(["ip", "-4", "route", "replace", "default", "dev", self.ppp_if,
                        "metric", str(metric)], 5)
        if code == 0:
            log.warning("route: IPv4 default -> %s (metric %d)", self.ppp_if, metric)
        else:
            log.error("route: failed to set default via %s: %s", self.ppp_if, out)

    @staticmethod
    def _demote(r: List[str], metric: int) -> None:
        """Re-add a competing default route with a higher metric so it stays as a backup."""
        base = ["default"]
        for k in ("via", "dev", "proto", "src"):
            v = _kv(r, k)
            if v:
                base += [k, v]
        if "onlink" in r:
            base.append("onlink")
        old = int(_kv(r, "metric") or 0)
        for new in range(metric + 100, metric + 110):
            if sh(["ip", "-4", "route", "add"] + base + ["metric", str(new)], 5)[0] == 0:
                sh(["ip", "-4", "route", "del"] + base + ["metric", str(old)], 5)
                log.info("route: %s default kept as backup (metric %d -> %d)", _kv(r, "dev"), old, new)
                return
        log.warning("route: could not keep '%s' as backup; it will be replaced", " ".join(r))

    def fallback_dhcp(self) -> None:
        dev = route_dev(self.probe)
        if dev and not dev.startswith("ppp"):
            log.warning("uplink: PPP unavailable, traffic now via %s (DHCP fallback)", dev)
            return
        iface = dhcp_iface(self.cfg)
        log.warning("uplink: PPP unavailable and no usable default route, DHCP on %s", iface)
        self.step_dhcp(detect_stack(), iface)

    def select_uplink(self) -> bool:
        """Prefer PPP_IFACE. While it is down, redial every PPP_RETRY_INTERVAL seconds and use
        DHCP in between. Returns True when the active uplink changed (caller re-syncs DDNS)."""
        if not self.ppp:
            return False
        self._reap()
        self.kill_extra_ppp()
        prev = self.uplink
        if self.ppp_up():
            self.uplink = "ppp"
        else:
            if prev == "ppp":
                log.warning("PPP: %s went down", self.ppp_if)
            if prev != "dhcp" or time.time() - self.last_dial >= i(self.cfg, "PPP_RETRY_INTERVAL"):
                self.uplink = "ppp" if self.ppp_dial() else "dhcp"
                if self.uplink == "dhcp" and prev != "dhcp":
                    self.fallback_dhcp()
        ip = None
        if self.uplink == "ppp":
            self.ensure_ppp_route()
            ip = iface_ipv4(self.ppp_if)
        ip_changed = bool(ip and self.ppp_ip and ip != self.ppp_ip)
        if ip:
            self.ppp_ip = ip
        if prev != self.uplink:
            log.warning("uplink: %s -> %s", prev or "start", self.uplink)
            return prev is not None
        if ip_changed:
            log.warning("PPP: %s address changed, re-syncing DDNS", self.ppp_if)
        return ip_changed

    def sleep_hint(self, default: int) -> float:
        """Seconds until the next tick: shorter while waiting for the next PPP redial."""
        if self.ppp and self.uplink == "dhcp":
            due = self.last_dial + i(self.cfg, "PPP_RETRY_INTERVAL") - time.time()
            return max(1.0, min(default, due))
        return default

    # ---- recovery steps ----
    def step_ppp(self) -> bool:
        log.warning("L0: PPP redial %s", self.provider)
        ok = self.ppp_dial(force=True)
        self.uplink = "ppp" if ok else "dhcp"
        if ok:
            self.ensure_ppp_route()
        return ok

    def step_dhcp(self, st, iface) -> bool:
        if not iface:
            log.warning("L1: no interface detected, skip DHCP renew")
            return False
        if st["networkd"]:
            log.warning("L1: networkctl renew %s", iface)
            sh(["networkctl", "renew", iface], 30)
            return True
        if st["networkmanager"] and shutil.which("nmcli"):
            log.warning("L1: nmcli device reapply %s", iface)
            code, _ = sh(["nmcli", "device", "reapply", iface], 30)
            if code != 0:
                sh(["nmcli", "device", "connect", iface], 30)
            return True
        if st["dhclient"] and (not st["ifupdown"] or iface_is_dhcp_ifupdown(iface)):
            log.warning("L1: dhclient -r %s && dhclient %s", iface, iface)
            sh(["dhclient", "-r", iface], 30)
            sh(["dhclient", "-1", iface], 60)
            return True
        if st["dhcpcd"]:
            log.warning("L1: dhcpcd -n %s", iface)
            sh(["dhcpcd", "-n", iface], 30)
            return True
        log.info("L1: interface %s is not DHCP-managed (static?), skip", iface)
        return False

    def step_restart(self, st, iface) -> bool:
        did = False
        if st["netplan"]:
            log.warning("L2: netplan apply")
            sh(["netplan", "apply"], 90)
            did = True
        elif st["networkd"]:
            log.warning("L2: systemctl restart systemd-networkd")
            sh(["systemctl", "restart", "systemd-networkd"], 90)
            did = True
        if st["networkmanager"]:
            log.warning("L2: systemctl restart NetworkManager")
            sh(["systemctl", "restart", "NetworkManager"], 90)
            did = True
        if st["ifupdown"]:
            log.warning("L2: systemctl restart networking")
            code, out = sh(["systemctl", "restart", "networking"], 120)
            if code != 0 and iface:
                log.warning("L2: restart networking failed (%s); ifdown/ifup %s", out[-200:], iface)
                sh(["ifdown", "--force", iface], 60)
                sh(["ifup", iface], 90)
            did = True
        if not did and iface:
            log.warning("L2: no known network manager; ip link down/up %s", iface)
            sh(["ip", "link", "set", iface, "down"], 10)
            time.sleep(2)
            sh(["ip", "link", "set", iface, "up"], 10)
            did = True
        return did

    def recover(self) -> bool:
        st = detect_stack()
        iface = dhcp_iface(self.cfg)
        log.warning("network DOWN — starting recovery (uplink=%s, dhcp iface=%s, stack=%s)",
                    self.uplink or "-", iface, ",".join(k for k, v in st.items() if v) or "unknown")
        wait = i(self.cfg, "RECOVERY_WAIT")
        steps = [("PPP redial", self.step_ppp)] if self.ppp else []
        steps += [("DHCP renew", lambda: self.step_dhcp(st, iface)),
                  ("network restart", lambda: self.step_restart(st, iface))]
        for name, step in steps:
            if _stop:
                return False
            if not step():
                continue
            if step != self.step_ppp:
                nap(wait)
                if self.ppp and self.ppp_up():   # e.g. ifupdown re-dialed during the restart
                    self.uplink = "ppp"
                    self.ensure_ppp_route()
            if self.online():
                log.warning("network RESTORED after %s (uplink %s)", name, self.uplink or iface)
                return True
            if step == self.step_ppp:
                # PPP has an address but no internet: hang up so the DHCP route takes over
                log.warning("PPP: %s is up but offline, hanging up and falling back to DHCP", self.ppp_if)
                sh(["poff", self.provider], 15)
                self.uplink = "dhcp"
        self.failed_rounds += 1
        log.error("recovery round failed (%d consecutive)", self.failed_rounds)
        if b(self.cfg, "REBOOT_ON_FAILURE") and self.failed_rounds >= i(self.cfg, "REBOOT_AFTER_ROUNDS"):
            log.critical("L3: rebooting after %d failed recovery rounds", self.failed_rounds)
            sh(["systemctl", "reboot"], 30)
        return False

    def tick(self) -> bool:
        """One watchdog cycle. Returns True when the uplink changed or the network was just
        restored (the caller then forces a DDNS sync)."""
        changed = self.select_uplink()
        if self.online():
            if self.fails:
                log.info("network OK again after %d failed checks", self.fails)
            self.fails = 0
            self.failed_rounds = 0
            return changed
        self.fails += 1
        log.warning("connectivity check failed (%d/%d)", self.fails, i(self.cfg, "FAIL_THRESHOLD"))
        if self.fails < i(self.cfg, "FAIL_THRESHOLD"):
            return changed
        now = time.time()
        if now - self.started < i(self.cfg, "BOOT_GRACE"):
            log.info("within boot grace period, not recovering yet")
            return changed
        if now - self.last_recovery < i(self.cfg, "RECOVERY_COOLDOWN"):
            return changed
        self.last_recovery = now
        if self.recover():
            self.fails = 0
            self.failed_rounds = 0
            return True
        return changed


# ─────────────────────────────── main ─────────────────────────────────────────

def _on_signal(signum, _frame):
    global _stop
    log.info("signal %d received, stopping", signum)
    _stop = True


def validate(cfg, need_cf=True):
    errs = []
    if need_cf:
        if not cfg.get("CF_API_TOKEN") or cfg["CF_API_TOKEN"].startswith("your_"):
            errs.append("CF_API_TOKEN is not set")
        if not lst(cfg, "CF_RECORDS") or any("example.com" in r for r in lst(cfg, "CF_RECORDS")):
            errs.append("CF_RECORDS is not set")
    if errs:
        raise SystemExit("config error: " + "; ".join(errs))


def cmd_run(cfg):
    validate(cfg)
    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)
    ddns, wd = DDNS(cfg), Watchdog(cfg)
    log.info("ddns-cf %s started: records=%s, check every %ss (%s), DDNS every %ss, PPP %s",
             VERSION, ",".join(lst(cfg, "CF_RECORDS")), cfg["CHECK_INTERVAL"], wd.method, cfg["DDNS_INTERVAL"],
             "%s via %s, redial every %ss" % (wd.ppp_if, wd.provider, cfg["PPP_RETRY_INTERVAL"])
             if wd.ppp else "disabled")
    if wd.ppp and os.geteuid() != 0:
        log.warning("not running as root: PPP dialing and route changes will fail")
    next_ddns = 0.0
    while not _stop:
        force = wd.tick()
        now = time.time()
        if force or (now >= next_ddns and wd.fails == 0):
            try:
                ddns.run(force=force or next_ddns == 0.0)
            except Exception as e:  # noqa: BLE001
                log.error("DDNS error: %s", e)
            next_ddns = now + i(cfg, "DDNS_INTERVAL")
        nap(wd.sleep_hint(i(cfg, "CHECK_INTERVAL")))
    log.info("stopped")


def cmd_ddns(cfg):
    validate(cfg)
    sys.exit(0 if DDNS(cfg).run(force=True) else 1)


def cmd_check(cfg):
    print("ddns-cf", VERSION)
    print("records     :", ", ".join(lst(cfg, "CF_RECORDS")) or "(none)")
    print("token       :", ("set (%d chars)" % len(cfg["CF_API_TOKEN"])) if cfg.get("CF_API_TOKEN") else "NOT SET")
    if cfg.get("CF_API_TOKEN"):
        try:
            r = Cloudflare(cfg).verify_token()
            print("token check :", r.get("status"))
        except Exception as e:  # noqa: BLE001
            print("token check : FAILED -", e)
    st = detect_stack()
    wd = Watchdog(cfg)
    if wd.ppp:
        up = wd.ppp_up()
        print("ppp         : enabled (provider=%s, iface=%s, redial every %ss)"
              % (wd.provider, wd.ppp_if, cfg["PPP_RETRY_INTERVAL"]))
        print("ppp status  :", ("UP, IPv4 %s" % iface_ipv4(wd.ppp_if)) if up else "DOWN",
              "| pppd pids:", pppd_pids(wd.provider) or "none", "| pon:", shutil.which("pon") or "NOT FOUND")
        extras = [n for n in ppp_ifaces() if n != wd.ppp_if]
        if extras:
            print("ppp extras  :", ", ".join(extras), "(will be terminated)")
    else:
        print("ppp         : disabled (PPP_ENABLE=%s, /etc/ppp/peers/%s %s)"
              % (cfg.get("PPP_ENABLE"), wd.provider,
                 "exists" if os.path.isfile("/etc/ppp/peers/" + wd.provider) else "missing"))
    print("route dev   :", route_dev(wd.probe) or "NO ROUTE")
    print("dhcp iface  :", dhcp_iface(cfg), "(configured)" if cfg.get("NET_IFACE") else "(auto)")
    print("net stack   :", ", ".join(k for k, v in st.items() if v) or "unknown")
    print("check method:", wd.method)
    print("online      :", wd.online())
    print("public IPv4 :", public_ip(cfg, False) if b(cfg, "CF_ENABLE_IPV4") else "(disabled)")
    print("public IPv6 :", public_ip(cfg, True) if b(cfg, "CF_ENABLE_IPV6") else "(disabled)")


def cmd_dial(cfg):
    if os.geteuid() != 0:
        raise SystemExit("dial needs root")
    wd = Watchdog(cfg)
    if not wd.ppp:
        raise SystemExit("PPP is disabled (PPP_ENABLE / PPP_PROVIDER)")
    ok = wd.ppp_dial(force=True)
    if ok:
        wd.ensure_ppp_route()
    sys.exit(0 if ok else 1)


def cmd_recover(cfg):
    if os.geteuid() != 0:
        raise SystemExit("recover needs root")
    wd = Watchdog(cfg)
    sys.exit(0 if wd.recover() else 1)


COMMANDS = {"run": cmd_run, "ddns": cmd_ddns, "check": cmd_check, "dial": cmd_dial, "recover": cmd_recover}


def main():
    ap = argparse.ArgumentParser(description="Cloudflare DDNS + PPPoE-aware network watchdog")
    ap.add_argument("command", nargs="?", default="run", choices=list(COMMANDS))
    ap.add_argument("--env", help="path to .env")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()

    here = os.path.dirname(os.path.realpath(__file__))
    env_path = a.env or next((p for p in (os.path.join(here, ".env"), "/opt/ddns-cf/.env") if os.path.isfile(p)),
                             os.path.join(here, ".env"))
    logging.basicConfig(format="%(levelname)s %(message)s" if os.environ.get("INVOCATION_ID")
                        else "%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    cfg = load_env(env_path)
    log.setLevel("DEBUG" if a.verbose else cfg.get("LOG_LEVEL", "INFO").upper())
    COMMANDS[a.command](cfg)


if __name__ == "__main__":
    main()
