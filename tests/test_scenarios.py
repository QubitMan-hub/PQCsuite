"""End-to-end Vault scenarios with real data behind them, driven through the `pqcsuite` command line and checked with
an independent client (psql). The TLS and Readiness scenarios moved to their products. Each scenario is skipped when its
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


if __name__ == "__main__":
    unittest.main()
