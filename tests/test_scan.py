import datetime as dt
import os
import socket
import tempfile
import time
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pqcsuite import scan, tls
from pqcsuite.ca import CA
from pqcsuite.tls.openssl import Context
from pqcsuite.tls.server import Server

try:
    tls.lib()
    REASON = None
except tls.OpenSSLUnavailable as e:
    REASON = str(e)


def rsa_cert(d):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "legacy")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=20)).sign(key, hashes.SHA256()))
    (d / "rsa.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "rsa.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return d / "rsa.pem", d / "rsa.key"


@unittest.skipIf(REASON, REASON)
class ScanTest(unittest.TestCase):
    def test_grades_and_report(self):
        d = Path(tempfile.mkdtemp())
        out, _ = CA.init(d / "pki", "Root").issue("localhost", "server", out=d / "srv")
        rcert, rkey = rsa_cert(d)
        servers = {
            "A": lambda: tls.server_context(out / "chain.pem", out / "key.pem", policy_name="strict"),
            "B": lambda: tls.server_context(out / "chain.pem", out / "key.pem", policy_name="transition"),
            "C": lambda: Context(True, "X25519:secp256r1", None, tls.CIPHERSUITES, rcert, rkey),
        }
        ports = {}
        for grade, make in servers.items():
            s = Server(("127.0.0.1", 0), make, lambda c, a: None)
            s.start()
            self.addCleanup(s.stop, 1)
            ports[grade] = s.port
        results = scan.scan([f"127.0.0.1:{p}" for p in ports.values()] + ["127.0.0.1:1"], timeout=3)
        by = {r["target"]: r for r in results}
        for grade, port in ports.items():
            self.assertEqual(by[f"127.0.0.1:{port}"]["grade"], grade)
        self.assertEqual(by["127.0.0.1:1"]["grade"], "F")
        self.assertEqual(by[f"127.0.0.1:{ports['A']}"]["certificate"]["key"], "ML-DSA-65")
        self.assertEqual(by[f"127.0.0.1:{ports['C']}"]["certificate"]["key"], "RSA-2048")
        self.assertEqual(by[f"127.0.0.1:{ports['B']}"]["negotiated"], "X25519MLKEM768")
        s = scan.summary(results)
        self.assertEqual((s["pq_key_exchange"], s["pq_certificates"], s["expiring_30d"]), (2, 2, 1))
        self.assertFalse(any(r["cnsa2"] for r in results))
        page = scan.report_html(results)
        self.assertIn("2/4", page)
        self.assertNotIn("<script", page)


@unittest.skipIf(REASON, REASON)
class CNSA2Test(unittest.TestCase):
    def test_cnsa2_policy_and_verdict(self):
        d = Path(tempfile.mkdtemp())
        ca = CA.init(d / "pki", "Root", algorithm="ML-DSA-87")
        out87, _ = ca.issue("localhost", "server", algorithm="ML-DSA-87", out=d / "s87")
        out65, _ = ca.issue("localhost", "server", algorithm="ML-DSA-65", out=d / "s65")
        s = Server(("127.0.0.1", 0), lambda: tls.server_context(out87 / "chain.pem", out87 / "key.pem", policy_name="cnsa2"), lambda c, a: None)
        s.start()
        self.addCleanup(s.stop, 1)
        r = scan.probe(f"127.0.0.1:{s.port}", "localhost", 3)
        self.assertEqual(set(r["accepts"]), {"SecP384r1MLKEM1024", "MLKEM1024"})
        self.assertTrue(r["cnsa2"])
        with tls.connect("127.0.0.1", s.port, tls.client_context(d / "pki" / "ca.crt", policy_name="cnsa2"), "localhost", 3) as c:
            self.assertEqual((c.group, c.cipher, c.info()["peer_key"]), ("SecP384r1MLKEM1024", "TLS_AES_256_GCM_SHA384", "ML-DSA-87"))
        with self.assertRaises(tls.TLSError):
            tls.connect("127.0.0.1", s.port, tls.client_context(d / "pki" / "ca.crt", policy_name="strict"), "localhost", 3).close()
            raise tls.TLSError("strict clients offer no CNSA 2.0 group first")
        with self.assertRaises(tls.TLSError):
            s65 = Server(("127.0.0.1", 0), lambda: tls.server_context(out65 / "chain.pem", out65 / "key.pem", policy_name="cnsa2"), lambda c, a: None)
            s65.start()
            self.addCleanup(s65.stop, 1)
            tls.connect("127.0.0.1", s65.port, tls.client_context(d / "pki" / "ca.crt", policy_name="cnsa2"), "localhost", 3).close()


if __name__ == "__main__":
    unittest.main()


def fake_ssh(kex, hostkeys="ssh-ed25519"):
    import os
    import socket
    import struct
    import threading
    srv = socket.create_server(("127.0.0.1", 0))

    def serve():
        c, _ = srv.accept()
        with c:
            c.sendall(b"SSH-2.0-FakeSSH_1.0\r\n")
            nl = lambda s: struct.pack(">I", len(s)) + s.encode()
            payload = bytes([20]) + os.urandom(16) + nl(kex) + nl(hostkeys) + b"".join(nl("") for _ in range(8)) + b"\0" + b"\0" * 4
            pad = 8 - (len(payload) + 5) % 8 + 4
            c.sendall(struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\0" * pad)
            c.recv(100)
        srv.close()
    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


class SSHTest(unittest.TestCase):
    def test_ssh_grades(self):
        cases = {"A": "mlkem768x25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com",
                 "B": "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256",
                 "C": "curve25519-sha256,diffie-hellman-group14-sha256"}
        for grade, kex in cases.items():
            r = scan.probe(f"ssh://127.0.0.1:{fake_ssh(kex)}", timeout=3)
            self.assertEqual(r["grade"], grade, kex)
            self.assertNotIn("ext-info-s", r["accepts"])
        self.assertEqual(scan.probe("ssh://127.0.0.1:1", timeout=2)["grade"], "F")

    @unittest.skipUnless(Path("/usr/sbin/sshd").exists() and hasattr(os, "geteuid") and os.geteuid() == 0, "needs root and OpenSSH")
    def test_real_openssh(self):
        import subprocess
        d = Path(tempfile.mkdtemp())
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "key")], check=True)
        Path("/run/sshd").mkdir(exist_ok=True)
        with socket.create_server(("127.0.0.1", 0)) as s:
            port = s.getsockname()[1]
        (d / "conf").write_text(f"Port {port}\nListenAddress 127.0.0.1\nHostKey {d / 'key'}\nPidFile {d / 'pid'}\n")
        proc = subprocess.Popen(["/usr/sbin/sshd", "-D", "-f", str(d / "conf")])
        self.addCleanup(proc.terminate)
        for _ in range(50):
            r = scan.probe(f"ssh://127.0.0.1:{port}", timeout=2)
            if r["grade"] != "F":
                break
            time.sleep(0.1)
        self.assertIn(r["grade"], "AB")
        self.assertEqual(r["host_keys"], ["ssh-ed25519"])
