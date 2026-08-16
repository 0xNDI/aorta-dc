"""Configuration and ephemeral key material for the aorta-dc responder.

Everything the responder needs to impersonate the attacker-side DC is derived
here from CLI options:

* the incoming cross-realm trust AES256 key
  (``string_to_key(AES256, trust_password, "<VICTIM>krbtgt<ATTACKER>")``) is the
  shared secret with which the victim KDC encrypts its referral TGT
  (``krbtgt/<ATTACKER_REALM>@<VICTIM_REALM>``); no Samba/LDB/keytab involved.
* the service AES256 key for ``cifs/<dc>`` defaults to a static lab constant
  (deterministic across runs); ``--random-service-key`` regenerates it fresh
  at startup and ``--service-aes-key`` pins an explicit value.
* a domain GUID used in the CLDAP Netlogon response is generated fresh
  per run.

Nothing is persisted and no AD database of any kind exists. The domain GUID
is ephemeral; the service key is ephemeral only when explicitly randomized.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from dataclasses import dataclass, field

from impacket.krb5 import crypto

DEFAULT_SITE = "Default-First-Site-Name"

# Static default for the cifs/<dc> service key so runs are reproducible in the
# lab (matching the other bytestorm.local defaults); --random-service-key or
# --service-aes-key replace it.
DEFAULT_SERVICE_KEY = hashlib.sha256(b"ahos6@bytestorm").digest()


def derive_trust_key(trust_password: bytes, victim_realm: str, attacker_realm: str) -> crypto.Key:
    """Derive the AES256 key for krbtgt/<ATTACKER>@<VICTIM> (incoming trust).

    Verified against Samba's exported cross-realm keytab: the salt is
    ``<VICTIM_REALM>krbtgt<ATTACKER_REALM>`` (both upper-case, no separators).
    """
    salt = f"{victim_realm.upper()}krbtgt{attacker_realm.upper()}".encode()
    return crypto.string_to_key(crypto.Enctype.AES256, trust_password, salt)


@dataclass
class ResponderConfig:
    """All runtime identity/key material for the responder."""

    ip: str
    realm: str  # Kerberos realm, upper-case
    domain: str  # DNS domain name, lower-case
    dc_fqdn: str  # lower-case DC FQDN
    dc_name: str  # DC short (NetBIOS host) name, upper-case
    netbios_domain: str  # upper-case NetBIOS domain
    sid: str
    victim_realm: str  # upper-case
    trust_password: bytes
    service_key: bytes  # 32-byte AES256 key for cifs/<dc>
    domain_guid: bytes  # 16 raw bytes for the Netlogon response
    site: str = DEFAULT_SITE
    service_principal: tuple[str, str] = ()  # ("cifs", "dc01.bytestorm.local")
    # runtime observations (mutated by the handlers, not identity material):
    victim_dc_fqdn: str | None = None  # learned from the CLDAP ping DnsHostName
    clock_skew: int | None = None  # victim clock - local clock, seconds
    trust_key: crypto.Key = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.realm = self.realm.upper()
        self.victim_realm = self.victim_realm.upper()
        self.domain = self.domain.lower()
        self.dc_fqdn = self.dc_fqdn.lower()
        self.netbios_domain = self.netbios_domain.upper()
        self.dc_name = self.dc_name.upper()
        if len(self.service_key) != 32:
            raise ValueError("service AES256 key must be exactly 32 bytes")
        if len(self.domain_guid) != 16:
            raise ValueError("domain GUID must be exactly 16 bytes")
        if not self.service_principal:
            self.service_principal = ("cifs", self.dc_fqdn)
        self.trust_key = derive_trust_key(self.trust_password, self.victim_realm, self.realm)


def fresh_service_key() -> bytes:
    """Random 32-byte AES256 key (only used with --random-service-key)."""
    return secrets.token_bytes(32)


def fresh_domain_guid() -> bytes:
    """Return a GUID in the little-endian byte layout used on the Netlogon wire."""
    return uuid.uuid4().bytes_le
