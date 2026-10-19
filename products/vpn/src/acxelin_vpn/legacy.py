"""The PQC Suite's names, still read through Acxelin VPN 1.x with a warning, so an upgrade keeps working. Removed in 2.0."""
import logging
import os
from pathlib import Path

log = logging.getLogger(__name__)
INVITE_SUFFIXES = (".acxinvite", ".pqcinvite")


def warn(old, new):
    log.warning("%s is the PQC Suite's name, read until Acxelin VPN 2.0; use %s", old, new)


def env(name):
    """ACXELIN_<name>, or the suite's PQCSUITE_<name> with a warning."""
    if value := os.environ.get(f"ACXELIN_{name}"):
        return value
    if value := os.environ.get(f"PQCSUITE_{name}"):
        warn(f"PQCSUITE_{name}", f"ACXELIN_{name}")
    return value


def home():
    """The person's VPN folder, ~/.acxelin-vpn; the suite's ~/.pqcsuite/vpn while it is the only one there."""
    new, old = Path.home() / ".acxelin-vpn", Path.home() / ".pqcsuite" / "vpn"
    if not new.exists() and old.is_dir():
        warn(str(old), str(new))
        return old
    return new
