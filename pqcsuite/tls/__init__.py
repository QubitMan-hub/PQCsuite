"""Moved to acxelin-core (acxelin_core.tls) and Acxelin TLS (policies, edge, bundles). These names work until Stage 6."""
import sys

from acxelin_core import tls as _core
from acxelin_core.http import hostport  # noqa: F401
from acxelin_core.openssl import Connection, Context, OpenSSLUnavailable, TLSError, lib  # noqa: F401
from acxelin_core.tls import Policy, connect  # noqa: F401
from acxelin_tls import bundles, edge, policies
from acxelin_tls.policies import CIPHERSUITES, PQC_GROUPS, POLICIES, policy  # noqa: F401


def server_context(cert, key, ca=None, require_client_cert=False, policy_name="strict", key_passphrase=None, request_client_cert=False,
                   any_purpose=False, fallback=None):
    return _core.server_context(policies.policy(policy_name), cert, key, ca, require_client_cert, key_passphrase, request_client_cert, any_purpose, fallback)


def client_context(ca=None, cert=None, key=None, policy_name="strict", key_passphrase=None, verify=True):
    return _core.client_context(policies.policy(policy_name), ca, cert, key, key_passphrase, verify)


from acxelin_core import https as http, server  # noqa: E402

sys.modules[__name__ + ".edge"], sys.modules[__name__ + ".bundles"] = edge, bundles
sys.modules[__name__ + ".server"], sys.modules[__name__ + ".http"] = server, http
