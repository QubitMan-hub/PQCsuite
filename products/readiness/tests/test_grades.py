"""The grader against real servers: post-quantum only (A), post-quantum with classical fallback (B), classical TLS 1.3 (C),
TLS 1.2 only (C) and nothing listening (F). The post-quantum servers run on the core's TLS mechanism, the classical ones on Python's ssl."""
import datetime as dt
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from acxelin_core import openssl
from acxelin_core.pki import CA
from acxelin_core.server import Server
from acxelin_core.tls import Policy, server_context
from acxelin_readiness import endpoints

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")

PQ = "X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768"
SUITES = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256"


def ec_certificate(d):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "app.internal")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1)).sign(key, hashes.SHA256()))
    (d / "ec.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "ec.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return d / "ec.pem", d / "ec.key"


def pq_server(request, policy, cert, key):
    srv = Server(("127.0.0.1", 0), lambda: server_context(policy, cert, key), lambda conn, addr: conn.close(), name=policy.name)
    srv.start()
    request.addfinalizer(lambda: srv.stop(grace=1))
    return srv.port


def classical_server(request, cert, key, version):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ctx.maximum_version = version
    ctx.set_ecdh_curve("prime256v1")
    ctx.load_cert_chain(cert, key)
    sock = socket.create_server(("127.0.0.1", 0))
    request.addfinalizer(sock.close)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                ctx.wrap_socket(conn, server_side=True).close()
            except (OSError, ssl.SSLError):
                conn.close()
    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def closed_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_grades_follow_what_each_server_accepts(tmp_path, request):
    CA.init(tmp_path / "ca", "Grades Test CA")
    out, _ = CA(tmp_path / "ca").issue("app.internal", "server", ["127.0.0.1"], out=tmp_path / "app")
    cert, key = out / "chain.pem", out / "key.pem"
    ec_cert, ec_key = ec_certificate(tmp_path)
    ports = {
        "strict": pq_server(request, Policy("strict", PQ, "mldsa87:mldsa65:mldsa44", SUITES), cert, key),
        "transition": pq_server(request, Policy("transition", PQ + ":X25519:secp256r1", None, SUITES), cert, key),
        "classical": classical_server(request, ec_cert, ec_key, ssl.TLSVersion.TLSv1_3),
        "legacy": classical_server(request, ec_cert, ec_key, ssl.TLSVersion.TLSv1_2),
        "closed": closed_port(),
    }
    results = {r["target"]: r for r in endpoints.scan([f"127.0.0.1:{p}" for p in ports.values()], timeout=5)}
    got = {name: results[f"127.0.0.1:{p}"] for name, p in ports.items()}
    assert {name: r["grade"] for name, r in got.items()} == {"strict": "A", "transition": "B", "classical": "C", "legacy": "C", "closed": "F"}
    assert got["strict"]["negotiated"] == "X25519MLKEM768" and got["strict"]["certificate"]["quantum_safe"]
    assert "X25519" in got["transition"]["accepts"] and "X25519MLKEM768" in got["transition"]["accepts"]
    assert got["classical"]["accepts"] == ["secp256r1"]
    assert got["legacy"]["negotiated"] == "TLSv1.2" and got["legacy"]["certificate"]["key"] == "ECDSA-secp256r1"
    assert got["closed"]["error"] == "connection refused (nothing is listening on that port)"
