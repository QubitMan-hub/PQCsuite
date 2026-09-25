"""PQC TLS 1.3: policies, contexts and a client helper on top of the OpenSSL bridge."""
import socket
from dataclasses import dataclass

from .openssl import Connection, Context, OpenSSLUnavailable, TLSError, lib

PQC_GROUPS = "X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768"
CIPHERSUITES = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"


@dataclass(frozen=True)
class Policy:
    """What a peer may negotiate. `strict` is post-quantum only; `transition` prefers PQC but still talks to classical peers."""
    name: str
    groups: str
    sigalgs: str | None


POLICIES = {
    "strict": Policy("strict", PQC_GROUPS, "mldsa87:mldsa65:mldsa44"),
    "transition": Policy("transition", PQC_GROUPS + ":X25519:secp256r1:secp384r1", None),
}


def policy(name):
    if name not in POLICIES:
        raise TLSError(f"unknown policy {name}; choose from {', '.join(POLICIES)}")
    return POLICIES[name]


def server_context(cert, key, ca=None, require_client_cert=False, policy_name="strict", key_passphrase=None):
    p = policy(policy_name)
    if require_client_cert and not ca:
        raise TLSError("requiring client certificates needs the CA that issued them")
    return Context(True, p.groups, p.sigalgs, CIPHERSUITES, cert, key, key_passphrase, ca, True, require_client_cert)


def client_context(ca=None, cert=None, key=None, policy_name="strict", key_passphrase=None, verify=True):
    p = policy(policy_name)
    if verify and not ca:
        raise TLSError("verifying the server needs a CA certificate (or pass verify=False for a probe)")
    return Context(False, p.groups, p.sigalgs, CIPHERSUITES, cert, key, key_passphrase, ca, verify)


def connect(host, port, ctx, server_name=None, timeout=10.0):
    """Open a verified TLS 1.3 connection; the certificate must match `server_name` (defaults to `host`)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap(sock, server_name or host, timeout)


__all__ = ["Connection", "Context", "OpenSSLUnavailable", "POLICIES", "Policy", "TLSError", "client_context", "connect", "lib",
           "server_context"]
