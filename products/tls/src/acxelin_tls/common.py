"""What Acxelin TLS's commands share: the CA passphrase and the TLS client options."""
import os
from pathlib import Path

from acxelin_core.cli import ask
from acxelin_core.pki import CAError, encrypted

from . import policies

CA_PASS_ENV = "ACXELIN_TLS_CA_PASSPHRASE"


def ca_passphrase(root, new=False):
    """From ACXELIN_TLS_CA_PASSPHRASE or a prompt, and only when the CA key is (or will be) encrypted."""
    if not new and not encrypted(Path(root) / "ca.key"):
        return None
    given = os.environ.get(CA_PASS_ENV)
    if given:
        return given.encode()
    if not new:
        return ask("CA passphrase: ", f"set {CA_PASS_ENV}")
    instead = f"set {CA_PASS_ENV}, or pass --no-encrypt to leave the CA key unencrypted"
    p1, p2 = ask("New CA passphrase: ", instead), ask("Repeat: ", instead)
    if p1 != p2:
        raise CAError("the passphrases do not match")
    return p1


def policy(p):
    p.add_argument("--policy", choices=list(policies.POLICIES), default="strict",
                   help="strict: post-quantum only (default); transition: also classical clients; cnsa2: ML-KEM-1024, ML-DSA-87 and AES-256 only")


def tls_client_args(p):
    p.add_argument("target", help="host:port")
    p.add_argument("--server-name", help="name the certificate must match (default: host)")
    policy(p)
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--json", action="store_true")
