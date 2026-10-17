"""End-to-end scenarios with real applications behind the products, driven through the `pqcsuite` command line and checked
with independent clients (the OpenSSL 3.5 command line, curl, psql, redis-cli, mosquitto). Each scenario is skipped when its
application is not installed."""
import hashlib
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from pqcsuite.pki import CA
from tests.helpers import REASON


def openssl_cli():
    """An `openssl` command line of version 3.5 or newer, used only as an independent client in these tests."""
    for c in [os.environ.get("PQCSUITE_OPENSSL_CLI"), "/opt/openssl35/bin/openssl", shutil.which("openssl")]:
        if c and Path(c).exists():
            v = subprocess.run([c, "version"], capture_output=True, text=True).stdout.split()
            if len(v) > 1 and tuple(int(x) for x in v[1].split(".")[:2] if x.isdigit()) >= (3, 5):
                return c
    return None


OPENSSL = openssl_cli()
PG_BIN = max((p.parent for p in Path("/usr/lib/postgresql").glob("*/bin/initdb")), key=lambda p: int(p.parent.name), default=None)


def free_port():
    with socket.create_server(("127.0.0.1", 0)) as s:
        return s.getsockname()[1]


def wait_port(port, seconds=20):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"nothing listens on {port}")


def need(*tools):
    missing = [t for t in tools if not (shutil.which(t) or Path(t).exists())]
    return unittest.skipIf(missing, f"needs {', '.join(missing)}")


def ec_certificate(d, name="app.internal"):
    """A self-signed ECDSA certificate, as a classical server or a browser-facing fallback would have."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), False).sign(key, hashes.SHA256()))
    (d / "ec.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "ec.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


@unittest.skipIf(REASON, REASON)
class Scenario(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.d, True)
        self.procs = []
        self.addCleanup(self.stop_all)
        self.ca = CA.init(self.d / "pki", "Scenario Root")
        self.ca.crl()

    def stop_all(self):
        for p in reversed(self.procs):
            p.terminate()
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            if p.stdout:
                p.stdout.close()

    def spawn(self, *cmd, log=None, **kw):
        out = open(log or os.devnull, "w")
        p = subprocess.Popen([str(c) for c in cmd], stdout=out, stderr=subprocess.STDOUT, **kw)
        out.close()
        self.procs.append(p)
        return p

    def postgres(self):
        data, port = self.d / "pg", free_port()
        data.mkdir()
        shutil.chown(data, "postgres")
        os.chmod(self.d, 0o755)
        subprocess.run(["runuser", "-u", "postgres", "--", PG_BIN / "initdb", "-D", data, "-A", "trust", "--encoding=UTF8"],
                       check=True, capture_output=True)
        self.spawn("runuser", "-u", "postgres", "--", PG_BIN / "postgres", "-D", data, "-p", port, "-k", data,
                   "-c", "listen_addresses=127.0.0.1")
        wait_port(port)
        deadline = time.monotonic() + 30  # the port opens before the server accepts connections
        while subprocess.run([PG_BIN / "pg_isready", "-h", "127.0.0.1", "-p", str(port)], capture_output=True).returncode:
            if time.monotonic() > deadline:
                raise TimeoutError(f"PostgreSQL on {port} never accepted connections")
            time.sleep(0.2)
        return port

    def pqc(self, *args, log):
        return self.spawn(sys.executable, "-m", "pqcsuite", *args, log=self.d / log)

    def edge(self, config, name):
        (self.d / f"{name}.toml").write_text(config)
        self.pqc("tls", "edge", "--config", self.d / f"{name}.toml", log=f"{name}.log")

    def route(self, name, mode, listen, target, **extra):
        lines = [f'[[edge]]\nname = "{name}"\nmode = "{mode}"\nlisten = "127.0.0.1:{listen}"\ntarget = "127.0.0.1:{target}"']
        for k, v in extra.items():
            lines.append(f"{k} = {str(v).lower() if isinstance(v, bool) else repr(str(v))}")
        return "\n".join(lines) + "\n"

    def tunnel(self, upstream, mtls=True):
        """An originate edge on the client side and a terminate edge in front of the service: what a branch office runs."""
        srv, _ = self.ca.issue("service.internal", "server", ["127.0.0.1"], out=self.d / "srv")
        cli, _ = self.ca.issue("branch", "client", out=self.d / "branch")
        front, local = free_port(), free_port()
        self.edge(self.route("front", "terminate", front, upstream, cert=srv / "chain.pem", key=srv / "key.pem",
                             ca=self.d / "pki" / "ca.crt", require_client_cert=mtls, crl=self.d / "pki" / "crl.pem"), "front")
        wait_port(front)
        self.edge(self.route("local", "originate", local, front, server_name="service.internal", ca=self.d / "pki" / "ca.crt",
                             cert=cli / "chain.pem", key=cli / "key.pem"), "local")
        wait_port(local)
        return local

    def s_client(self, port, *extra, name="app.internal", cafile=None, send=b"GET / HTTP/1.0\r\nHost: app.internal\r\n\r\n"):
        r = subprocess.run([OPENSSL, "s_client", "-connect", f"127.0.0.1:{port}", "-servername", name, "-verify_hostname", name,
                            "-CAfile", str(cafile or self.d / "pki" / "ca.crt"), "-verify_return_error", "-ign_eof", *extra],
                           input=send, capture_output=True, timeout=30)
        return r.returncode, r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")

    def edge_log(self, name):
        return (self.d / f"{name}.log").read_text(errors="replace")








class VaultTest(Scenario):
    """Backups of a real data folder: large files, nested folders, the command line, and tampering."""

    @unittest.skipUnless(PG_BIN and shutil.which("psql") and shutil.which("runuser") and
                         hasattr(os, "geteuid") and os.geteuid() == 0, "needs PostgreSQL and root")
    def test_postgres_dump_can_be_restored_after_vault_recovery(self):
        from pqcsuite import vault
        port = self.postgres()
        args = ["-h", "127.0.0.1", "-p", str(port), "-U", "postgres"]
        def sql(query):
            return subprocess.run(["psql", *args, "-v", "ON_ERROR_STOP=1", "-tAc", query], capture_output=True,
                                  text=True, encoding="utf-8", timeout=30, check=True).stdout.strip()
        sql("CREATE TABLE customer_data (id integer PRIMARY KEY, value text); "
            "INSERT INTO customer_data VALUES (1, 'customer α'), (2, 'recovery 漢字')")
        expected = sql("SELECT id, value FROM customer_data ORDER BY id")
        dump = self.d / "database.dump"
        subprocess.run([PG_BIN / "pg_dump", *args, "-Fc", "-f", dump, "postgres"], capture_output=True, check=True, timeout=30)
        ops, recovery = vault.Identity.generate(), vault.Identity.generate()
        archive = self.d / "database.pqv"
        vault.encrypt(dump, archive, [ops.public, recovery.public])
        vault.verify(archive, recovery)
        dump.unlink()
        sql("DROP TABLE customer_data")
        restored, _ = vault.decrypt(archive, self.d / "restore", recovery)
        subprocess.run([PG_BIN / "pg_restore", *args, "--clean", "--if-exists", "--exit-on-error", "-d", "postgres", restored],
                       capture_output=True, check=True, timeout=30)
        self.assertEqual(sql("SELECT id, value FROM customer_data ORDER BY id"), expected)

    def test_backup_restore_and_tamper(self):
        src = self.d / "data"
        (src / "a" / "b").mkdir(parents=True)
        big = os.urandom(1 << 20) * 40 + os.urandom(12345)
        (src / "a" / "b" / "big.bin").write_bytes(big)
        (src / "notes.txt").write_text("quarterly figures\n")
        (src / "empty.txt").write_text("")
        run = lambda *a: subprocess.run([sys.executable, "-m", "pqcsuite", *map(str, a)], capture_output=True, text=True, timeout=300)
        for who in ("ops", "dr"):
            self.assertEqual(run("vault", "keygen", self.d / who, "--no-passphrase").returncode, 0)
        signer, _ = self.ca.issue("backup-bot", "client", out=self.d / "bot")
        for _ in range(3):
            r = run("vault", "backup", src, "--to", self.d / "backups", "-r", self.d / "ops.pub", "-r", self.d / "dr.pub",
                    "--sign-cert", signer / "cert.pem", "--sign-key", signer / "key.pem", "--keep", 2)
            self.assertEqual(r.returncode, 0, r.stderr)
            time.sleep(1.1)
        archives = sorted((self.d / "backups").glob("*.pqv"))
        self.assertEqual(len(archives), 2)
        r = run("vault", "decrypt", archives[-1], "--key", self.d / "dr.key", "-o", self.d / "restore", "--ca", self.d / "pki" / "ca.crt",
                "--crl", self.d / "pki" / "crl.pem", "--signer", "backup-bot", "--require-signature")
        self.assertEqual(r.returncode, 0, r.stderr)
        restored = next((self.d / "restore").iterdir())
        self.assertEqual(hashlib.sha256((restored / "a" / "b" / "big.bin").read_bytes()).digest(), hashlib.sha256(big).digest())
        self.assertEqual((restored / "empty.txt").read_text(), "")
        raw = bytearray(archives[-1].read_bytes())
        raw[len(raw) // 3] ^= 0x40
        archives[-1].write_bytes(bytes(raw))
        r = run("vault", "decrypt", archives[-1], "--key", self.d / "ops.key", "-o", self.d / "bad")
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(any((self.d / "bad").rglob("big.bin")) if (self.d / "bad").exists() else False)


class ReadinessTest(Scenario):
    """The scanner grades real servers: our strict and transition edges, and a classical OpenSSL server."""

    @unittest.skipUnless(OPENSSL, "needs an OpenSSL 3.5+ command line")
    def test_grades(self):
        from pqcsuite.readiness import scan
        ec_certificate(self.d)
        out, _ = self.ca.issue("app.internal", "server", ["127.0.0.1"], out=self.d / "app")
        backend = free_port()
        srv = socket.create_server(("127.0.0.1", backend))
        self.addCleanup(srv.close)
        strict, transition, classical = free_port(), free_port(), free_port()
        self.edge(self.route("s", "terminate", strict, backend, cert=out / "chain.pem", key=out / "key.pem") +
                  self.route("t", "terminate", transition, backend, cert=out / "chain.pem", key=out / "key.pem", policy="transition"), "edges")
        self.spawn(OPENSSL, "s_server", "-accept", f"127.0.0.1:{classical}", "-cert", out / "chain.pem", "-key", out / "key.pem",
                   "-groups", "X25519:P-256", "-www", "-tls1_3")
        for p in (strict, transition, classical):
            wait_port(p)
        legacy, closed = free_port(), free_port()
        self.spawn(OPENSSL, "s_server", "-accept", f"127.0.0.1:{legacy}", "-cert", self.d / "ec.pem", "-key", self.d / "ec.key",
                   "-www", "-tls1_2")
        wait_port(legacy)
        results = {r["target"]: r for r in scan.scan([f"127.0.0.1:{p}" for p in (strict, transition, classical, legacy, closed)], timeout=5)}
        grades = [results[f"127.0.0.1:{p}"]["grade"] for p in (strict, transition, classical, legacy, closed)]
        self.assertEqual(grades, ["A", "B", "C", "C", "F"])
        self.assertEqual(results[f"127.0.0.1:{legacy}"]["negotiated"], "TLSv1.2")
        self.assertEqual(results[f"127.0.0.1:{legacy}"]["certificate"]["key"], "ECDSA-secp256r1")


if __name__ == "__main__":
    unittest.main()
