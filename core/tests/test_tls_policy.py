"""The TLS mechanism follows whatever policy the caller passes; core defines no policy of its own."""
import threading

import pytest
from acxelin_core import openssl, tls
from acxelin_core.pki import CA

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")
SUITES = "TLS_AES_256_GCM_SHA384"


def policy(name, groups, sigalgs="mldsa87:mldsa65:mldsa44", cert_algorithm=None):
    return tls.Policy(name, groups, sigalgs, SUITES, cert_algorithm)


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")
    CA.init(d / "ca", "Core Test CA", passphrase=b"x")
    ca = CA(d / "ca", b"x")
    paths = {}
    for algorithm in ("ML-DSA-65", "ML-DSA-87"):
        out, _ = ca.issue("localhost", "server", names=["localhost"], algorithm=algorithm, out=d / algorithm, passphrase=b"x")
        paths[algorithm] = out
    paths["ca"] = d / "ca" / "ca.crt"
    return paths


def handshake(pki, server_policy, client_policy, algorithm="ML-DSA-65"):
    out = pki[algorithm]
    server = tls.server_context(server_policy, out / "cert.pem", out / "key.pem", key_passphrase=b"x")
    client = tls.client_context(client_policy, pki["ca"])
    import socket
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    box = {}

    def serve():
        try:
            conn = server.wrap(listener.accept()[0], None, 5)
            box["server"] = conn.group
            conn.close()
        except Exception as e:  # noqa: BLE001
            box["error"] = e
    t = threading.Thread(target=serve)
    t.start()
    try:
        with tls.connect("127.0.0.1", listener.getsockname()[1], client, "localhost", timeout=5) as conn:
            return conn.group
    finally:
        t.join(10)
        listener.close()


def test_core_defines_no_named_policy():
    assert not hasattr(tls, "POLICIES") and not hasattr(tls, "PQC_GROUPS") and not hasattr(tls, "policy")


def test_a_policy_has_no_defaults():
    with pytest.raises(TypeError):
        tls.Policy("x", "X25519MLKEM768", None)


def test_the_negotiated_group_follows_the_callers_policies(pki):
    both = policy("both", "X25519MLKEM768:SecP384r1MLKEM1024")
    assert handshake(pki, both, policy("c1", "SecP384r1MLKEM1024")) == "SecP384r1MLKEM1024"
    assert handshake(pki, both, policy("c2", "X25519MLKEM768")) == "X25519MLKEM768"


def test_no_shared_group_means_no_connection(pki):
    with pytest.raises(tls.TLSError):
        handshake(pki, policy("s", "X25519MLKEM768"), policy("c", "SecP384r1MLKEM1024"))


def test_a_certificate_requirement_comes_from_the_policy_not_a_name(pki):
    strict87 = policy("only87", "SecP384r1MLKEM1024", "mldsa87", "ML-DSA-87")
    out = pki["ML-DSA-65"]
    with pytest.raises(tls.TLSError, match="only87.*ML-DSA-87.*ML-DSA-65"):
        tls.server_context(strict87, out / "cert.pem", out / "key.pem", key_passphrase=b"x")
    assert handshake(pki, strict87, strict87, "ML-DSA-87") == "SecP384r1MLKEM1024"
