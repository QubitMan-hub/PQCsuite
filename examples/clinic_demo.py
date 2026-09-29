"""Northside Clinic: the whole product story in one run, for live demos.

A clinic has a patient portal, an old records server, doctors' laptops and nightly backups. The demo grades it, finds the
weak cryptography in its code, puts the portal behind post-quantum TLS with mutual TLS for staff, cuts off a stolen
laptop, backs up patient records with Vault, catches a tampered backup and writes the auditor's evidence report.

    python examples/clinic_demo.py            # pauses before each step; press Enter to go on
    python examples/clinic_demo.py --auto     # runs straight through and checks every result (CI does this)

Needs pqcsuite installed and OpenSSL 3.5+. Wolf Pack is used when the `wolfpack` command is installed.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

PORTAL = """
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
RECORDS = {"P-1042": {"patient": "P-1042", "name": "A. Rao", "allergies": ["penicillin"], "next_visit": "2026-10-02"}}
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        rec = RECORDS.get(self.path.rsplit("/", 1)[-1])
        body = json.dumps(rec or {"error": "not found"}).encode()
        self.send_response(200 if rec else 404)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
"""

LEGACY = """
import socket, ssl, sys, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[2], sys.argv[3])
ctx.maximum_version = ssl.TLSVersion.TLSv1_2
srv = socket.create_server(("127.0.0.1", int(sys.argv[1])))
def serve(c):
    try:
        t = ctx.wrap_socket(c, server_side=True)
        t.recv(1024)
        t.sendall(b"HTTP/1.0 200 OK\\r\\n\\r\\nrecords")
        t.close()
    except Exception:
        c.close()
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"""

APP = {
    "records/Export.java": """\
        package org.northside.records;
        import java.security.MessageDigest;
        import javax.crypto.Cipher;
        public class Export {
            byte[] fingerprint(byte[] row) throws Exception { return MessageDigest.getInstance("MD5").digest(row); }
            Cipher cipher() throws Exception { return Cipher.getInstance("AES/ECB/PKCS5Padding"); }
        }
        """,
    "portal/tokens.py": """\
        # Session tokens. We used MD5 here until 2024; it is SHA-256 now.
        import hashlib, hmac
        def sign(secret, payload):
            return hmac.new(secret, payload, hashlib.sha256).hexdigest()
        """,
    "deploy/nginx.conf": """\
        server {
          listen 443 ssl;
          ssl_protocols TLSv1.1 TLSv1.2;
          ssl_certificate /etc/ssl/portal.crt;
          ssl_certificate_key /etc/ssl/portal.key;
        }
        """,
}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise SystemExit(f"demo: nothing started on port {port}")


class Demo:
    def __init__(self, work, auto):
        self.work, self.auto, self.procs, self.n = work, auto, [], 0

    def step(self, title, story):
        self.n += 1
        print(f"\n{'=' * 78}\n{self.n}. {title}\n{'=' * 78}")
        print(textwrap.fill(story, 78))
        if not self.auto:
            self.pause("\n  [Enter] to run it ")

    def run(self, *args, expect=0, contains=(), tool="pqcsuite"):
        cmd = [sys.executable, "-m", tool, *map(str, args)] if tool == "pqcsuite" else [tool, *map(str, args)]
        shown = " ".join(f"$'{a}'".replace("\r", "\\r").replace("\n", "\\n") if "\n" in str(a) else f'"{a}"' if " " in str(a) else str(a)
                         for a in args)
        print(f"\n$ {tool} {shown}")
        return self.attempt(lambda: subprocess.run(cmd, cwd=self.work, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                                   stdin=subprocess.DEVNULL), expect, contains)

    def attempt(self, go, expect, contains):
        """Run a command until it does what the step expects. With --auto a miss stops the demo; live, the presenter can run it
        again or go on, so one surprise does not end the meeting."""
        while True:
            r = go()
            out = (r.stdout + r.stderr).rstrip()
            print(textwrap.indent(out, "  ") if out else "  (no output)")
            if (expect is None or r.returncode == expect) and all(c in out for c in contains):
                return out
            why = f"exit {r.returncode}, expected {expect}; wanted {list(contains)}"
            if self.auto:
                raise SystemExit(f"\ndemo: step {self.n} did not go as planned ({why})")
            print(f"\n  This did not go as planned ({why}).")
            try:
                choice = input("  [Enter] run it again, s + Enter to go on, q + Enter to stop: ").strip().lower()
            except EOFError:
                choice = "q"
            if choice == "q":
                raise SystemExit(f"\ndemo: stopped at step {self.n}")
            if choice == "s":
                return out

    def pause(self, prompt):
        try:
            input(prompt)
        except EOFError:
            self.auto = True

    def serial(self, name):
        """The serial of the valid certificate called `name`, looked up without printing the whole list."""
        r = subprocess.run([sys.executable, "-m", "pqcsuite", "ca", "list", "--json"], cwd=self.work, capture_output=True, text=True)
        return next(c["serial"] for c in json.loads(r.stdout) if c["common_name"] == name)

    def start(self, name, cmd, port):
        log = open(self.work / f"{name}.log", "w", encoding="utf-8")
        self.procs.append(subprocess.Popen(cmd, cwd=self.work, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL))
        wait_port(port)

    def stop(self):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(5)
            except subprocess.TimeoutExpired:
                p.kill()


def preflight(d):
    """The demos need OpenSSL 3.5+; say how to get it rather than failing on the first step."""
    try:
        d.run("doctor", contains=["X25519MLKEM768"])
    except SystemExit:
        script = Path(sys.argv[0]).name
        raise SystemExit(f"\ndemo: this machine's OpenSSL cannot do post-quantum TLS yet (it needs 3.5 or newer). Run the demo on "
                         f"Debian 13 or Ubuntu 25.04+, or in the Docker image, from the pqcsuite folder:\n"
                         f"  docker build -t pqcsuite .\n"
                         f'  docker run --rm -it -v "$PWD/examples:/examples" --entrypoint python pqcsuite /examples/{script}') from None


def legacy_certificate(work):
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "records.northside.test")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    (work / "legacy.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (work / "legacy.key").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return key


def main():
    sys.stdout.reconfigure(line_buffering=True)
    os.environ.setdefault("PQCSUITE_CA_PASSPHRASE", "demo-only-passphrase")  # CA keys are encrypted; scripts pass the passphrase
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--auto", action="store_true", help="run without pauses and check every result")
    ap.add_argument("--dir", help="work folder (default: a new temporary folder)")
    a = ap.parse_args()
    work = Path(a.dir or tempfile.mkdtemp(prefix="northside-")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    d = Demo(work, a.auto)
    portal, legacy, staff = free_port(), free_port(), free_port()
    py = sys.executable
    print(f"Northside Clinic demo, working in {work}")
    try:
        preflight(d)
        (work / "portal.py").write_text(PORTAL, encoding="utf-8")
        (work / "legacy.py").write_text(LEGACY, encoding="utf-8")
        legacy_certificate(work)
        d.start("portal", [py, "portal.py", str(portal)], portal)
        d.start("legacy", [py, "legacy.py", str(legacy), "legacy.crt", "legacy.key"], legacy)
        (work / "hosts.txt").write_text(f"127.0.0.1:{legacy}    # old patient records server\n", encoding="utf-8")

        d.step("Readiness scan: where does the clinic stand today?",
               "The clinic sends us its list of servers. We need nothing else: no access, no software on their side.")
        d.run("readiness", "scan", "hosts.txt", "--html", "readiness-before.html", expect=2, contains=["C  ", "TLSv1.2", "RSA-2048"])
        print("\n  Say: grade C. Anyone recording this traffic today can read the patient records once quantum computers arrive.")

        app = work / "clinic-app"
        for rel, text in APP.items():
            (app / rel).parent.mkdir(parents=True, exist_ok=True)
            (app / rel).write_text(textwrap.dedent(text), encoding="utf-8")
        (app / "deploy" / "portal.key").write_bytes((work / "legacy.key").read_bytes())
        d.step("Wolf Pack: where is the weak cryptography in their code?",
               "Wolf Pack reads the clinic's code, configuration and keys, and ranks what to fix first. It runs on the "
               "clinic's machine; the code never leaves it.")
        if shutil.which("wolfpack"):
            d.run("scan", "clinic-app", "-o", "wolfpack-out", "--fail-on", "critical", expect=2, tool="wolfpack",
                  contains=["MD5", "AES-ECB", "TLS 1.1", "Private key stored in repository"])
            print("\n  Say: the comment about MD5 in tokens.py is not flagged. Wolf Pack flags what the code does, not what it mentions.")
        else:
            print("\n  (wolfpack is not installed here, so this step is skipped: pip install ./wolf-pack to show it)")

        d.step("A private certificate authority for the clinic",
               "The clinic gets its own quantum-safe passport office. It issues ML-DSA certificates to the portal and to "
               "each doctor's laptop, and can cancel any of them.")
        d.run("ca", "init", "--name", "Northside Clinic Root", contains=["ML-DSA-87"])
        d.run("ca", "issue", "server", "portal.northside.test", "--san", "127.0.0.1", "--out", "certs/portal")
        d.run("ca", "issue", "client", "dr-mehta-laptop", "--out", "certs/dr-mehta")
        d.run("ca", "crl")

        d.step("Put the portal behind post-quantum TLS, staff only",
               "One command puts an edge in front of the portal. The portal itself is not changed. Only laptops with a "
               "certificate from the clinic's CA get in.")
        edge = [py, "-m", "pqcsuite", "tls", "edge", "--listen", f"127.0.0.1:{staff}", "--target", f"127.0.0.1:{portal}",
                "--cert", "certs/portal/chain.pem", "--key", "certs/portal/key.pem", "--ca", "pki/ca.crt", "--crl", "pki/crl.pem",
                "--require-client-cert"]
        print(f"\n$ pqcsuite {' '.join(edge[3:])}")
        d.start("edge", edge, staff)
        print("  (running in the background; its log is edge.log)")
        get = ["--server-name", "portal.northside.test", "--ca", "pki/ca.crt", "--send", "GET /patients/P-1042 HTTP/1.0\r\n\r\n"]
        laptop = ["--cert", "certs/dr-mehta/chain.pem", "--key", "certs/dr-mehta/key.pem"]
        d.run("tls", "connect", f"127.0.0.1:{staff}", *get, *laptop, contains=["X25519MLKEM768", "ML-DSA-65", "penicillin"])
        print("\n  Say: X25519MLKEM768 is the quantum-safe key exchange, ML-DSA-65 the quantum-safe certificate. The record arrived as before.")
        d.run("tls", "connect", f"127.0.0.1:{staff}", *get, expect=1, contains=["refused our client certificate"])
        print("\n  Say: a machine without a clinic certificate does not get in.")

        (work / "hosts.txt").write_text(f"127.0.0.1:{legacy}    # old patient records server\n127.0.0.1:{staff}    # portal, now behind the edge\n",
                                        encoding="utf-8")
        d.step("Scan again", "Same scan as step 1, now including the protected portal.")
        d.run("readiness", "scan", "hosts.txt", "--html", "readiness-after.html", expect=2, contains=["A  ", "X25519MLKEM768"])
        print("\n  Say: the portal is an A. The old records server is next on the list.")

        d.step("Dr Mehta's laptop is stolen",
               "The clinic cancels the laptop's certificate. Within seconds the portal refuses it; nobody touches the edge.")
        d.run("ca", "list", contains=["dr-mehta-laptop"])
        d.run("ca", "revoke", d.serial("dr-mehta-laptop"), "--reason", "keyCompromise", contains=["revoked"])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and "was revoked" not in (work / "edge.log").read_text(encoding="utf-8", errors="replace"):
            subprocess.run([py, "-m", "pqcsuite", "tls", "connect", f"127.0.0.1:{staff}", *get, *laptop], cwd=work, capture_output=True)
            time.sleep(0.5)
        d.run("tls", "connect", f"127.0.0.1:{staff}", *get, *laptop, expect=1)
        print("  edge.log: " + next(l for l in (work / "edge.log").read_text(encoding="utf-8").splitlines() if "was revoked" in l).split(" ", 3)[-1])

        records = work / "patient-records"
        records.mkdir(exist_ok=True)
        for pid in ("P-1042", "P-1043", "P-1044"):
            (records / f"{pid}.json").write_text(json.dumps({"patient": pid, "notes": "confidential"}), encoding="utf-8")
        d.step("Nightly backup with Vault",
               "Patient records are kept for decades. Vault encrypts the backup with ML-KEM and signs it with the backup "
               "job's certificate, so the clinic knows who made it. Two keys can open it: the one operations uses, and a "
               "recovery key kept offline, so losing one never loses the records.")
        d.run("vault", "keygen", "clinic-ops", "--no-passphrase")
        d.run("vault", "keygen", "clinic-recovery", "--no-passphrase")
        d.run("ca", "issue", "client", "backup-bot", "--out", "certs/backup-bot")
        out = d.run("vault", "backup", "patient-records", "--to", "backups", "-r", "clinic-ops.pub", "-r", "clinic-recovery.pub", "--sign-cert", "certs/backup-bot/cert.pem",
                    "--sign-key", "certs/backup-bot/key.pem", "--keep", "30")
        archive = out.split("backup ", 1)[1].split()[0]
        d.run("vault", "inspect", archive, contains=["ML-KEM-768", "CN=backup-bot"])
        d.run("vault", "decrypt", archive, "--key", "clinic-ops.key", "-o", "restore", "--ca", "pki/ca.crt", "--signer", "backup-bot",
              contains=["signed by CN=backup-bot"])

        d.step("Ransomware quietly edits the backup",
               "One bit of the backup is changed, as ransomware or a bad copy would. Vault refuses to restore it and "
               "writes nothing.")
        raw = bytearray((work / archive).read_bytes())
        raw[len(raw) // 2] ^= 1
        (work / "tampered.pqv").write_bytes(bytes(raw))
        d.run("vault", "decrypt", "tampered.pqv", "--key", "clinic-ops.key", "-o", "restore-tampered", expect=1, contains=["modified"])
        if (work / "restore-tampered").exists():
            raise SystemExit("demo: the tampered backup left files behind")

        d.step("The auditor's evidence report",
               "One report lists every certificate, server and backup with its NIST IR 8547 and CNSA 2.0 status.")
        d.run("readiness", "report", "--ca", "pki", "--targets", "hosts.txt", "--backups", "backups", "--html", "evidence.html",
              expect=2, contains=["assets"])
        print(f"\nDone. Open these in a browser:\n  {work / 'readiness-before.html'}\n  {work / 'readiness-after.html'}\n  {work / 'evidence.html'}")
        if (work / "wolfpack-out" / "report.html").exists():
            print(f"  {work / 'wolfpack-out' / 'report.html'}")
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        d.stop()


if __name__ == "__main__":
    main()
