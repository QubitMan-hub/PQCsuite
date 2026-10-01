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

from pqcsuite import tls
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


class WebTest(Scenario):
    """A web app (nginx) behind the TLS edge, reached by third-party clients."""

    def nginx(self):
        port = free_port()
        (self.d / "www").mkdir()
        (self.d / "www" / "index.html").write_text("hello from nginx\n")
        (self.d / "nginx.conf").write_text(
            f"daemon off; master_process off; pid {self.d}/nginx.pid; error_log {self.d}/nginx-error.log;\n"
            f"events {{}}\nhttp {{ access_log off; client_body_temp_path {self.d}; proxy_temp_path {self.d};\n"
            f"  server {{ listen 127.0.0.1:{port}; root {self.d}/www; }} }}\n")
        self.spawn("nginx", "-p", self.d, "-c", self.d / "nginx.conf")
        wait_port(port)
        return port

    def web_edge(self, policy="strict", mtls=False, **extra):
        out, _ = self.ca.issue("app.internal", "server", ["127.0.0.1"], out=self.d / "app")
        port = free_port()
        self.metrics = free_port()
        cfg = f'[metrics]\nlisten = "127.0.0.1:{self.metrics}"\n' + self.route(
            "web", "terminate", port, self.nginx(), policy=policy, cert=out / "chain.pem", key=out / "key.pem",
            ca=self.d / "pki" / "ca.crt", require_client_cert=mtls, crl=self.d / "pki" / "crl.pem", **extra)
        self.edge(cfg, "web")
        wait_port(port)
        return port

    @need("nginx")
    @unittest.skipUnless(OPENSSL, "needs an OpenSSL 3.5+ command line")
    def test_openssl_client_gets_the_page_over_ml_kem_and_ml_dsa(self):
        port = self.web_edge()
        code, out = self.s_client(port)
        self.assertEqual(code, 0, out)
        self.assertIn("hello from nginx", out)
        self.assertIn("X25519MLKEM768", out)
        self.assertIn("Verify return code: 0 (ok)", out)
        self.assertRegex(out, r"(?i)peer signature type: (mldsa65|ML-DSA-65)")
        code, out = self.s_client(port, "-groups", "X25519")
        self.assertNotEqual(code, 0, "strict must refuse a classical key exchange")
        import urllib.request
        metrics = urllib.request.urlopen(f"http://127.0.0.1:{self.metrics}/metrics", timeout=5).read().decode()
        self.assertIn('group="X25519MLKEM768"', metrics)

    @need("nginx", "curl")
    def test_classical_clients_under_transition_with_a_fallback_certificate(self):
        ec_certificate(self.d)
        port = self.web_edge("transition", fallback_cert=self.d / "ec.pem", fallback_key=self.d / "ec.key")
        (self.d / "both.pem").write_bytes((self.d / "ec.pem").read_bytes() + (self.d / "pki" / "ca.crt").read_bytes())
        r = subprocess.run(["curl", "-sS", "--noproxy", "*", "--max-time", "10", "--cacert", self.d / "both.pem", "--resolve", f"app.internal:{port}:127.0.0.1",
                            f"https://app.internal:{port}/"], capture_output=True, text=True)
        self.assertEqual(r.stdout, "hello from nginx\n", r.stderr + self.edge_log("web"))
        if OPENSSL:
            code, out = self.s_client(port, "-sigalgs", "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256", "-groups", "X25519:P-256",
                                      cafile=self.d / "ec.pem")
            self.assertEqual(code, 0, out)
            self.assertIn("hello from nginx", out)
            self.assertRegex(out, r"(?i)peer signature type: ecdsa")
            code, out = self.s_client(port)
            self.assertEqual(code, 0, out)
            self.assertIn("X25519MLKEM768", out)
            self.assertRegex(out, r"(?i)peer signature type: (mldsa65|ML-DSA-65)")

    @need("nginx")
    @unittest.skipUnless(OPENSSL, "needs an OpenSSL 3.5+ command line")
    def test_mutual_tls_and_revocation_with_openssl_as_the_client(self):
        port = self.web_edge(mtls=True)
        alice, rec = self.ca.issue("alice", "client", out=self.d / "alice")
        code, out = self.s_client(port, "-cert", alice / "cert.pem", "-key", alice / "key.pem")
        self.assertIn("hello from nginx", out)
        code, out = self.s_client(port)
        self.assertNotIn("hello from nginx", out)
        self.ca.revoke(rec.serial, "keyCompromise")
        time.sleep(0.2)
        code, out = self.s_client(port, "-cert", alice / "cert.pem", "-key", alice / "key.pem")
        self.assertNotIn("hello from nginx", out)
        self.assertIn("revoked", self.edge_log("web"))

    @need("nginx")
    def test_many_concurrent_clients(self):
        from concurrent.futures import ThreadPoolExecutor
        from pqcsuite.tls.http import request
        port = self.web_edge()
        ctx = tls.client_context(self.d / "pki" / "ca.crt")

        def get(_):
            with tls.connect("127.0.0.1", port, ctx, "app.internal", 20) as c:
                return request(c, "GET", "/", "app.internal")[2]
        start = time.monotonic()
        with ThreadPoolExecutor(32) as pool:
            bodies = list(pool.map(get, range(300)))
        self.assertEqual(set(bodies), {b"hello from nginx\n"})
        self.assertLess(time.monotonic() - start, 120)


class TunnelTest(Scenario):
    """Legacy clients that cannot speak post-quantum TLS reach a service through two edges."""

    @need("redis-server", "redis-cli")
    def test_redis(self):
        port = free_port()
        self.spawn("redis-server", "--port", port, "--bind", "127.0.0.1", "--save", "", "--appendonly", "no")
        wait_port(port)
        local = self.tunnel(port)
        cli = lambda *a: subprocess.run(["redis-cli", "-p", str(local), *a], capture_output=True, text=True, timeout=15).stdout.strip()
        self.assertEqual(cli("SET", "pqc", "ML-KEM"), "OK")
        self.assertEqual(cli("GET", "pqc"), "ML-KEM")

    @need("mosquitto", "mosquitto_pub", "mosquitto_sub")
    def test_mqtt(self):
        port = free_port()
        (self.d / "mosquitto.conf").write_text(f"listener {port} 127.0.0.1\nallow_anonymous true\n")
        self.spawn("mosquitto", "-c", self.d / "mosquitto.conf")
        wait_port(port)
        local = self.tunnel(port)
        sub = subprocess.Popen(["mosquitto_sub", "-p", str(local), "-t", "plant/temp", "-C", "1", "-W", "20"], stdout=subprocess.PIPE, text=True)
        time.sleep(1)
        subprocess.run(["mosquitto_pub", "-p", str(local), "-t", "plant/temp", "-m", "21.5"], check=True, timeout=15)
        self.assertEqual(sub.communicate(timeout=25)[0].strip(), "21.5")

    @unittest.skipUnless(PG_BIN and shutil.which("psql"), "needs PostgreSQL")
    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0 and shutil.which("runuser"), "needs root to run postgres as its own user")
    def test_postgres(self):
        port = self.postgres()
        local = self.tunnel(port)
        r = subprocess.run(["psql", "-h", "127.0.0.1", "-p", str(local), "-U", "postgres", "-tAc", "select 6 * 7"],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "42", r.stderr)


class EnrollTest(Scenario):
    """A machine enrolls over EST with a one-time token, then uses its certificate for mutual TLS."""

    def test_est_enroll_then_mutual_tls(self):
        est_dir, _ = self.ca.issue("ca.internal", "server", ["127.0.0.1"], out=self.d / "est")
        port = free_port()
        self.pqc("ca", "serve", "--dir", self.d / "pki", "--listen", f"127.0.0.1:{port}", "--cert", est_dir / "chain.pem",
                 "--key", est_dir / "key.pem", log="est.log")
        wait_port(port)
        run = lambda *a: subprocess.run([sys.executable, "-m", "pqcsuite", *map(str, a)], capture_output=True, text=True, timeout=60)
        token = run("ca", "token", "--dir", self.d / "pki", "client", "laptop-7").stdout.strip().splitlines()[-1]
        from pqcsuite.pki.est import fingerprint
        fp = fingerprint(self.ca.cert)
        r = subprocess.run([sys.executable, "-m", "pqcsuite", "ca", "enroll", f"https://127.0.0.1:{port}", "--cn", "laptop-7", "--ca-fingerprint", fp,
                            "--server-name", "ca.internal", "--out", str(self.d / "laptop")], capture_output=True, text=True, timeout=60,
                           env={**os.environ, "PQCSUITE_ENROLL_TOKEN": token})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = run("ca", "enroll", f"https://127.0.0.1:{port}", "--token", token, "--cn", "laptop-7", "--ca-fingerprint", fp,
                "--server-name", "ca.internal", "--out", self.d / "again")
        self.assertNotEqual(r.returncode, 0, "a token works once")
        before = (self.d / "laptop" / "cert.pem").read_bytes()
        r = run("ca", "enroll", f"https://127.0.0.1:{port}", "--renew", self.d / "laptop", "--server-name", "ca.internal")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotEqual((self.d / "laptop" / "cert.pem").read_bytes(), before)
        ctx = tls.client_context(self.d / "laptop" / "ca.crt", self.d / "laptop" / "chain.pem", self.d / "laptop" / "key.pem")
        with tls.connect("127.0.0.1", port, ctx, "ca.internal", 10) as c:
            self.assertIsNotNone(c.peer_certificate())


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
