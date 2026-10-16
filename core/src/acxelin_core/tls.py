"""TLS 1.3 contexts and a client helper on top of the OpenSSL bridge. What a peer may negotiate is a `Policy` the caller passes in."""
import socket
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509

from .openssl import Connection, Context, OpenSSLUnavailable, TLSError, lib  # noqa: F401
from .pki import algorithm_of


@dataclass(frozen=True)
class Policy:
    """What a peer may negotiate: key-exchange groups, signature algorithms (None allows any) and cipher suites.
    `cert_algorithm`, when set, is the only certificate key algorithm that can work under the policy; a certificate with another
    one is refused at start-up, with a message that says why, instead of failing every handshake."""
    name: str
    groups: str
    sigalgs: str | None
    ciphersuites: str
    cert_algorithm: str | None = None


def _check_certificate(p, cert):
    if not p.cert_algorithm or not cert:
        return
    try:
        leaf = x509.load_pem_x509_certificates(Path(cert).read_bytes())[0]
    except (OSError, ValueError):
        return
    found = algorithm_of(leaf.public_key())
    if found != p.cert_algorithm:
        raise TLSError(f"the {p.name} policy needs a {p.cert_algorithm} certificate, but {cert} holds {found or 'a non-ML-DSA key'}; "
                       f"issue one with --algorithm {p.cert_algorithm}")


def server_context(policy, cert, key, ca=None, require_client_cert=False, key_passphrase=None, request_client_cert=False,
                   any_purpose=False, fallback=None):
    """`request_client_cert` asks for a client certificate and verifies it if one is sent, but lets clients without one in.
    `any_purpose` accepts a client certificate whose extended key usage is not clientAuth (the chain is still verified).
    `fallback` (cert, key) is a classical certificate for browsers and other clients that cannot verify ML-DSA yet; it needs
    a policy that allows classical signatures."""
    if (require_client_cert or request_client_cert) and not ca:
        raise TLSError("checking client certificates needs the CA that issued them")
    if fallback and policy.sigalgs:
        raise TLSError(f"a fallback certificate needs a policy that allows classical signatures; {policy.name} only allows {policy.sigalgs}")
    _check_certificate(policy, cert)
    return Context(True, policy.groups, policy.sigalgs, policy.ciphersuites, cert, key, key_passphrase, ca, True, require_client_cert,
                   request_client_cert, any_purpose, fallback)


def client_context(policy, ca=None, cert=None, key=None, key_passphrase=None, verify=True):
    if verify and not ca:
        raise TLSError("verifying the server needs a CA certificate (or pass verify=False for a probe)")
    _check_certificate(policy, cert)
    return Context(False, policy.groups, policy.sigalgs, policy.ciphersuites, cert, key, key_passphrase, ca, verify)


def connect(host, port, ctx, server_name=None, timeout=10.0):
    """Open a verified TLS 1.3 connection; the certificate must match `server_name` (defaults to `host`)."""
    sock = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap(sock, server_name or host, timeout)
