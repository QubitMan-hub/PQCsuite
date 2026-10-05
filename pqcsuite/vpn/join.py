"""Joining a WireGuard gateway from an administrator's invitation: one file instead of four hand-copied values. Shared by
`vpn join` and the `vpn app` window, so both refuse the same things before anything on the machine changes."""
import datetime as dt
import json
import os
import re
import shutil
from pathlib import Path

from .. import tls
from ..storage import write
from . import platforms

FIELDS = ("pqcsuite_invite", "name", "enroll", "ca_fingerprint", "gateway", "server_name", "expires")


def parse(text, where="this file"):
    try:
        inv = json.loads(text)
    except ValueError:
        inv = None
    if not isinstance(inv, dict) or inv.get("pqcsuite_invite") != 1 or not all(isinstance(inv.get(k), str) for k in ("name", "enroll", "ca_fingerprint", "gateway")) \
            or not inv["enroll"].startswith("https://") or not re.fullmatch(r"[0-9a-f]{64}", inv["ca_fingerprint"]):
        raise ValueError(f"{where} is not a PQC Suite invitation; ask your administrator for the .pqcinvite file from `pqcsuite vpn invite`")
    tls.hostport(inv["gateway"])
    return inv


def read(path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as e:
        raise ValueError(f"{path} could not be read ({e.__class__.__name__}); check the file name, or ask your administrator for a new invitation") from None
    return parse(text, str(path))


def administrator():
    if os.name == "nt":
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return os.geteuid() == 0


def preflight(command):
    """What must hold before a tunnel can be configured; `command` is what to run again once it does."""
    if not administrator():
        raise ValueError(f"connecting changes this machine's network, which needs administrator rights. Open an administrator terminal "
                         f"(Windows: Run as administrator; Linux/macOS: sudo) and run: {command}")
    if not shutil.which(platforms.find("wg")):
        raise ValueError(f"WireGuard is not installed: {platforms.INSTALL.get(platforms.system(), 'install wireguard-tools')}, then run this again")


def device_for(invitation, device=None):
    return Path(device or Path(invitation).with_suffix(""))


def must_enroll(inv, device):
    """True when this machine still needs a certificate; refuses a used or expired invitation."""
    if (Path(device) / "cert.pem").exists():
        return False
    if "token" not in inv:
        raise ValueError(f"this invitation was already used and {device} holds no certificate; ask your administrator for a new invitation")
    if dt.datetime.fromisoformat(inv["expires"]) < dt.datetime.now(dt.timezone.utc):
        raise ValueError(f"this invitation expired at {inv['expires']}; ask your administrator for a new one")
    return True


def enroll(inv, device, invitation, passphrase):
    """Pin the CA by the invitation's fingerprint, enroll with its one-time token, then remove the used token from the file."""
    from ..pki import est
    device = Path(device)
    device.mkdir(parents=True, exist_ok=True)
    est.fetch_ca(inv["enroll"], inv["ca_fingerprint"], device / "ca.crt")
    cert = est.enroll(inv["enroll"], inv["token"], inv["name"], (), device, device / "ca.crt", passphrase=passphrase)
    write(Path(invitation), json.dumps({k: inv[k] for k in FIELDS if k in inv}, indent=1).encode(), secret=True)
    return cert
