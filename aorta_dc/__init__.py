"""aorta-dc: attacker-side responder for the AORTA delegated-TGT capture.

Replaces the Dockerized Samba attacker DC: one process serves DNS (udp/53),
CLDAP (udp/389) and a TGS-only KDC (tcp/88) for the victim's DC-locator and
referral chase, plus a built-in SMB listener (tcp/445) that
captures the delegated ticket and stops automatically.
"""

__version__ = "0.1.0"
