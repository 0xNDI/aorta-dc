"""Minimal UDP DNS responder backed by dnspython.

Only the records needed for AD DC discovery of the attacker realm are served:

* ``A <dc_fqdn> -> attacker IP``  (the coerced listener address)
* ``A <domain apex> -> attacker IP``  (compatibility)
* ``SRV`` answers for ``_kerberos._tcp/_udp`` and ``_ldap._tcp`` queries under
  the attacker realm (with or without ``<site>._sites.dc._msdcs`` middles)

Unknown names get NXDOMAIN; unsupported types at existing in-zone names get
an empty NOERROR (NODATA). The responder never forwards anything.

The golden reference was Samba's output in the recorded capture:
QR|AA|RD|RA responses, short TTLs, an SOA record in the authority section.
Cryptographic values aside, responses are reproduced semantically rather
than byte-for-byte.
"""

from __future__ import annotations

import logging

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .keys import ResponderConfig

log = logging.getLogger("dns")

TTL = 900
SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_MINIMUM = 900, 600, 86400, 600


def _soa(cfg: ResponderConfig) -> dns.rrset.Rdata:
    from dns.rdtypes.ANY.SOA import SOA

    return SOA(
        dns.rdataclass.IN,
        dns.rdatatype.SOA,
        dns.name.from_text(cfg.dc_fqdn),
        dns.name.from_text("hostmaster." + cfg.domain),
        1,
        SOA_REFRESH,
        SOA_RETRY,
        SOA_EXPIRE,
        SOA_MINIMUM,
    )


def _srv_target_port(qname: dns.name.Name, zone: dns.name.Name) -> int | None:
    """Return the service port for a supported AD DC-locator name."""
    try:
        labels = [label.lower() for label in qname.relativize(zone).labels]
    except dns.name.NeedAbsoluteNameOrOrigin:
        return None
    if len(labels) < 2:
        return None

    service, proto, *middle = labels
    valid_middle = (
        not middle
        or middle == [b"dc", b"_msdcs"]
        or (len(middle) == 2 and middle[1] == b"_sites")
        or (len(middle) == 4 and middle[1:] == [b"_sites", b"dc", b"_msdcs"])
    )
    if not valid_middle:
        return None
    if service == b"_kerberos" and proto in (b"_tcp", b"_udp"):
        return 88
    if service == b"_ldap" and proto == b"_tcp":
        return 389
    return None


def build_response(query: dns.message.Message, cfg: ResponderConfig) -> dns.message.Message:
    """Build an authoritative answer for one parsed query."""
    resp = dns.message.make_response(query, recursion_available=True)
    resp.flags |= dns.flags.AA  # authoritative for the attacker realm

    if query.opcode() != dns.opcode.QUERY:
        resp.set_rcode(dns.rcode.NOTIMP)
        return resp

    zone = dns.name.from_text(cfg.domain)
    qname = query.question[0].name
    qtype = query.question[0].rdtype

    dc_name = dns.name.from_text(cfg.dc_fqdn)
    in_zone = qname == zone or qname.is_subdomain(zone)
    srv_port = _srv_target_port(qname, zone) if in_zone else None
    known_name = qname in (zone, dc_name) or srv_port is not None
    if not known_name:
        resp.set_rcode(dns.rcode.NXDOMAIN)
        resp.authority.append(dns.rrset.from_rdata(zone, TTL, _soa(cfg)))
        return resp

    if qtype == dns.rdatatype.A and qname in (zone, dc_name):
        from dns.rdtypes.IN.A import A

        resp.answer.append(dns.rrset.from_rdata(qname, TTL, A(dns.rdataclass.IN, dns.rdatatype.A, cfg.ip)))
        return resp

    if qtype == dns.rdatatype.SRV and srv_port is not None:
        from dns.rdtypes.IN.SRV import SRV

        resp.answer.append(
            dns.rrset.from_rdata(
                qname,
                TTL,
                SRV(
                    dns.rdataclass.IN,
                    dns.rdatatype.SRV,
                    0,
                    100,
                    srv_port,
                    dc_name,
                ),
            )
        )
        return resp

    # Known name, unsupported type (including AAAA on this IPv4-only server).
    resp.authority.append(dns.rrset.from_rdata(zone, TTL, _soa(cfg)))
    return resp


def handle_datagram(data: bytes, addr, cfg: ResponderConfig) -> bytes | None:
    """Entry point from the UDP listener; returns bytes to send or None."""
    if len(data) > 4096:
        log.warning("oversized DNS datagram from %s (%d bytes) dropped", addr, len(data))
        return None
    try:
        query = dns.message.from_wire(data)
    except Exception as exc:
        log.warning("malformed DNS query from %s: %s", addr, exc)
        return None
    if len(query.question) != 1:
        log.warning("DNS query from %s with %d questions ignored", addr, len(query.question))
        return None
    answer = build_response(query, cfg)
    log.info(
        "DNS %s %s from %s -> %s",
        dns.rdatatype.to_text(query.question[0].rdtype),
        query.question[0].name.to_text(),
        addr[0],
        dns.rcode.to_text(answer.rcode()),
    )
    return answer.to_wire(max_size=4096)
