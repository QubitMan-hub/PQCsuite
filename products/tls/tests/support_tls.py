"""Shared by Acxelin TLS's tests: the skip reason without OpenSSL 3.5, a poll helper, and the old-style context helpers."""
import time

from acxelin_core import openssl, tls

from acxelin_tls import policies

REASON = openssl.available()  # why the tests that need OpenSSL 3.5 are skipped, when they are


def wait(check, seconds=5.0):
    """Poll `check` until it is true or `seconds` pass; its last answer."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.05)
    return check()


def server_context(cert, key, ca=None, require_client_cert=False, policy_name="strict", key_passphrase=None, **kw):
    return tls.server_context(policies.policy(policy_name), cert, key, ca, require_client_cert, key_passphrase, **kw)


def client_context(ca=None, cert=None, key=None, policy_name="strict", key_passphrase=None, verify=True):
    return tls.client_context(policies.policy(policy_name), ca, cert, key, key_passphrase, verify)
