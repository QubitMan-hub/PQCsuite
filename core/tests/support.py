"""Shared by core's tests: the skip reason without OpenSSL 3.5, a poll helper, and a post-quantum-only policy of the tests' own."""
import time

from acxelin_core import openssl, tls

REASON = openssl.available()  # why the tests that need OpenSSL 3.5 are skipped, when they are
PQ = tls.Policy("test-strict", "X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768", "mldsa87:mldsa65:mldsa44",
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")


def wait(check, seconds=5.0):
    """Poll `check` until it is true or `seconds` pass; its last answer."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.05)
    return check()


def server_context(cert, key, ca=None, require_client_cert=False, **kw):
    return tls.server_context(PQ, cert, key, ca, require_client_cert, **kw)


def client_context(ca=None, cert=None, key=None, **kw):
    return tls.client_context(PQ, ca, cert, key, **kw)


def echo(conn, addr):
    while data := conn.recv(timeout=5):
        conn.sendall(data)

CIPHERSUITES = PQ.ciphersuites
