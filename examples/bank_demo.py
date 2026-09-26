"""Demo Bank: the product story for banks, in one run.

A bank (fictional) has an internet banking server, a payment API used by licensed partners, a card switch that branches
reach over an old line protocol, legacy code, and statement archives kept for years. The demo grades it, finds the weak
cryptography in its code, puts the payment API behind post-quantum mutual TLS, tunnels the card switch protocol unchanged,
cuts off a compromised branch, archives statements with Vault, shares an archive with an auditor, catches tampering, writes
the evidence report and opens the console.

    python examples/bank_demo.py            # pauses before each step; ends with the console open
    python examples/bank_demo.py --auto     # runs straight through and checks every result (CI does this)
"""
import argparse
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from clinic_demo import LEGACY, Demo, free_port, legacy_certificate  # noqa: E402

API = """
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"txn": "TXN20260926-000481", "amount": "25000.00", "currency": "INR", "status": "SUCCESS"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
"""

SWITCH = """
import socket, sys, threading
srv = socket.create_server(("127.0.0.1", int(sys.argv[1])))
def serve(c):
    with c:
        for line in c.makefile("rb"):
            mti, pan, amount = line.decode().strip().split("|")
            c.sendall(f"0210|{pan}|{amount}|00|APPROVED|AUTH 481516\\n".encode())
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
"""

LEGACY_CODE = {
    "cards/PinBlock.java": """\
        package bank.cards;
        import javax.crypto.Cipher;
        public class PinBlock {
            Cipher pinCipher() throws Exception { return Cipher.getInstance("DESede/ECB/NoPadding"); }
        }
        """,
    "payments/Signer.java": """\
        package bank.payments;
        import java.security.*;
        public class Signer {
            KeyPair keys() throws Exception { KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); g.initialize(1024); return g.generateKeyPair(); }
            Signature signer() throws Exception { return Signature.getInstance("SHA1withRSA"); }
        }
        """,
    "netbanking/session.py": """\
        # Session ids used to be MD5 of the user id; they are random now.
        import secrets
        def new_session():
            return secrets.token_urlsafe(32)
        """,
    "deploy/haproxy.cfg": """\
        global
          ssl-default-bind-options ssl-min-ver TLSv1.0
        frontend netbanking
          bind :443 ssl crt /etc/haproxy/netbanking.pem
        """,
}


def switch_request(port, line, timeout=5):
    """One card authorisation over the plain line protocol, as a branch system sends it."""
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        s.sendall(line.encode() + b"\n")
        return s.makefile("rb").readline().decode().strip()


def main():
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--auto", action="store_true", help="run without pauses and check every result")
    ap.add_argument("--dir", help="work folder (default: a new temporary folder)")
    a = ap.parse_args()
    work = Path(a.dir or tempfile.mkdtemp(prefix="demobank-")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    d = Demo(work, a.auto)
    py = sys.executable
    netbanking, api, api_edge, metrics, switch, switch_edge, branch_port, console = (free_port() for _ in range(8))
    print(f"Demo Bank, working in {work}")
    try:
        d.run("doctor", contains=["X25519MLKEM768"])
        for name, code in (("api.py", API), ("switch.py", SWITCH), ("legacy.py", LEGACY)):
            (work / name).write_text(code, encoding="utf-8")
        legacy_certificate(work)
        d.start("netbanking", [py, "legacy.py", str(netbanking), "legacy.crt", "legacy.key"], netbanking)
        d.start("api", [py, "api.py", str(api)], api)
        d.start("switch", [py, "switch.py", str(switch)], switch)
        (work / "hosts.txt").write_text(f"127.0.0.1:{netbanking}    # internet banking\n", encoding="utf-8")

        d.step("Readiness scan: where does the bank stand today?",
               "We only need the list of public addresses. No access, no agent, nothing installed at the bank. "
               "(With a real bank, scan only addresses it has approved in writing.)")
        d.run("readiness", "scan", "hosts.txt", "--html", "readiness-before.html", expect=2, contains=["C  ", "TLSv1.2", "RSA-2048"])
        print("\n  Say: grade C. Traffic recorded today, logins and statements included, can be decrypted once quantum computers arrive.")

        app = work / "legacy-code"
        for rel, text in LEGACY_CODE.items():
            (app / rel).parent.mkdir(parents=True, exist_ok=True)
            (app / rel).write_text(textwrap.dedent(text), encoding="utf-8")
        d.step("Wolf Pack: the weak cryptography inside legacy banking code",
               "Card PIN encryption with 3DES, payment signatures with RSA-1024 and SHA-1, and a load balancer that still "
               "allows TLS 1.0. Wolf Pack finds them, ranks them and says what replaces each. It runs inside the bank.")
        if shutil.which("wolfpack"):
            d.run("scan", "legacy-code", "-o", "wolfpack-out", "--fail-on", "critical", expect=2, tool="wolfpack",
                  contains=["3DES", "RSA-1024", "SHA-1", "TLS 1.0"])
            print("\n  Say: session.py mentions MD5 in a comment and is not flagged. Wolf Pack reports what code does, not what it mentions.")
        else:
            print("\n  (wolfpack is not installed here, so this step is skipped: pip install the WolfPack-CBOM package to show it)")

        d.step("The bank's own quantum-safe certificate authority",
               "An ML-DSA root for the bank, a certificate for the payment API, one for a licensed fintech partner, one for "
               "branch 0417 and one for the archive job. Its root key can live in the bank's HSM.")
        d.run("ca", "init", "--name", "Demo Bank Root", contains=["ML-DSA-87"])
        d.run("ca", "issue", "server", "api.demobank.test", "--san", "127.0.0.1", "--out", "certs/api")
        d.run("ca", "issue", "server", "switch.demobank.test", "--san", "127.0.0.1", "--out", "certs/switch")
        d.run("ca", "issue", "client", "fintech-partner-a", "--out", "certs/partner")
        d.run("ca", "issue", "client", "branch-0417", "--out", "certs/branch-0417")
        d.run("ca", "crl")

        d.step("Payment API behind post-quantum TLS, licensed partners only",
               "One command puts an edge in front of the payment API; the API is not changed. Only partners holding a "
               "certificate from the bank get in.")
        mtls = ["--ca", "pki/ca.crt", "--crl", "pki/crl.pem", "--require-client-cert"]
        edge = [py, "-m", "pqcsuite", "tls", "edge", "--listen", f"127.0.0.1:{api_edge}", "--target", f"127.0.0.1:{api}",
                "--cert", "certs/api/chain.pem", "--key", "certs/api/key.pem", *mtls, "--metrics", f"127.0.0.1:{metrics}"]
        print(f"\n$ pqcsuite {' '.join(edge[3:])}")
        d.start("api-edge", edge, api_edge)
        get = ["--server-name", "api.demobank.test", "--ca", "pki/ca.crt", "--send", "GET /v1/payments/TXN20260926-000481 HTTP/1.0\r\n\r\n"]
        partner = ["--cert", "certs/partner/chain.pem", "--key", "certs/partner/key.pem"]
        d.run("tls", "connect", f"127.0.0.1:{api_edge}", *get, *partner, contains=["X25519MLKEM768", "ML-DSA-65", '"status": "SUCCESS"'])
        print("\n  Say: the payment status arrived over a quantum-safe connection, and the API itself was not touched.")
        d.run("tls", "connect", f"127.0.0.1:{api_edge}", *get, expect=1, contains=["refused our client certificate"])
        print("\n  Say: anyone without a bank-issued certificate is refused before reaching the API.")

        d.step("A card switch on an old line protocol, tunnelled unchanged",
               "Branch systems speak a plain line protocol to the card switch, like many ATM and POS links. Two edges carry "
               "it over post-quantum TLS: one at the branch, one at the data centre. Neither the branch software nor the "
               "switch changes.")
        dc = [py, "-m", "pqcsuite", "tls", "edge", "--listen", f"127.0.0.1:{switch_edge}", "--target", f"127.0.0.1:{switch}",
              "--cert", "certs/switch/chain.pem", "--key", "certs/switch/key.pem", *mtls]
        br = [py, "-m", "pqcsuite", "tls", "edge", "--mode", "originate", "--listen", f"127.0.0.1:{branch_port}",
              "--target", f"127.0.0.1:{switch_edge}", "--server-name", "switch.demobank.test", "--ca", "pki/ca.crt",
              "--cert", "certs/branch-0417/chain.pem", "--key", "certs/branch-0417/key.pem"]
        for label, cmd, port in (("data centre", dc, switch_edge), ("branch 0417", br, branch_port)):
            print(f"\n$ pqcsuite {' '.join(cmd[3:])}    # {label}")
            d.start(f"edge-{label.split()[0]}", cmd, port)
        msg = "0200|4111XXXXXXXX1111|000002500000"
        print(f"\n  branch system sends: {msg}")
        answer = switch_request(branch_port, msg)
        print(f"  card switch answers: {answer}")
        if "APPROVED" not in answer:
            raise SystemExit("demo: the card switch did not answer through the tunnel")
        try:
            plain = switch_request(switch_edge, msg, timeout=3)
        except OSError:
            plain = ""
        print(f"  the same message sent unencrypted straight to the data centre edge: {'refused' if not plain else plain}")
        if plain:
            raise SystemExit("demo: the data centre edge accepted a plain connection")
        print("\n  Say: the switch only accepts the protocol inside post-quantum TLS, from a branch holding a bank certificate.")

        (work / "hosts.txt").write_text(f"127.0.0.1:{netbanking}    # internet banking\n127.0.0.1:{api_edge}    # payment API, behind the edge\n",
                                        encoding="utf-8")
        d.step("Scan again", "Same scan as step 1, now including the protected payment API.")
        d.run("readiness", "scan", "hosts.txt", "--html", "readiness-after.html", expect=2, contains=["A  ", "X25519MLKEM768"])
        print("\n  Say: the payment API is an A. Internet banking is next, with the transition policy so every browser keeps working.")

        d.step("Branch 0417 is compromised",
               "The bank revokes the branch's certificate. Within seconds the data centre refuses the branch; nobody touches "
               "the switch or the edges.")
        d.run("ca", "list", contains=["branch-0417"])
        d.run("ca", "revoke", d.serial("branch-0417"), "--reason", "keyCompromise", contains=["revoked"])
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and "was revoked" not in (work / "edge-data.log").read_text(encoding="utf-8", errors="replace"):
            try:
                switch_request(branch_port, msg, timeout=2)
            except OSError:
                pass
            time.sleep(0.5)
        try:
            answer = switch_request(branch_port, msg, timeout=3)
        except OSError:
            answer = ""
        print(f"\n  branch system sends: {msg}\n  card switch answers: {answer or '(connection closed)'}")
        if answer:
            raise SystemExit("demo: the revoked branch still reached the card switch")
        print("  data centre edge log: " + next(l for l in (work / "edge-data.log").read_text(encoding="utf-8").splitlines() if "was revoked" in l).split(" ", 3)[-1])

        statements = work / "statements-2026-09"
        statements.mkdir(exist_ok=True)
        for acct in ("30001234567", "30001234568", "30001234569"):
            (statements / f"{acct}.csv").write_text("date,description,amount\n2026-09-01,Salary,85000.00\n2026-09-03,UPI to grocer,-1240.50\n",
                                                    encoding="utf-8")
        d.step("Statement archive with Vault",
               "Statements are kept for years. Vault encrypts the archive with ML-KEM for two key holders (operations, and an "
               "offline recovery key) and signs it with the archive job's certificate.")
        d.run("vault", "keygen", "bank-ops", "--no-passphrase")
        d.run("vault", "keygen", "recovery-offline", "--no-passphrase")
        d.run("ca", "issue", "client", "archive-job", "--out", "certs/archive-job")
        out = d.run("vault", "backup", "statements-2026-09", "--to", "archive", "-r", "bank-ops.pub", "-r", "recovery-offline.pub",
                    "--sign-cert", "certs/archive-job/cert.pem", "--sign-key", "certs/archive-job/key.pem", "--keep", "84")
        archive = out.split("backup ", 1)[1].split()[0]
        d.run("vault", "inspect", archive, contains=["ML-KEM-768", "CN=archive-job"])

        d.step("An auditor needs this month's statements",
               "The auditor gets access to this one archive, without re-encrypting it and without sharing the bank's key.")
        d.run("vault", "keygen", "auditor", "--no-passphrase")
        d.run("vault", "share", archive, "--key", "bank-ops.key", "-r", "auditor.pub", contains=["3 recipient"])
        d.run("vault", "decrypt", archive, "--key", "auditor.key", "-o", "auditor-copy", "--ca", "pki/ca.crt", "--signer", "archive-job",
              contains=["signed by CN=archive-job"])

        d.step("Someone alters an archived statement",
               "One bit of the archive is changed, as an insider, ransomware or a bad copy would. Vault refuses it and writes nothing.")
        raw = bytearray((work / archive).read_bytes())
        raw[len(raw) // 2] ^= 1
        (work / "altered.pqv").write_bytes(bytes(raw))
        d.run("vault", "decrypt", "altered.pqv", "--key", "bank-ops.key", "-o", "restore-altered", expect=1, contains=["modified"])
        if (work / "restore-altered").exists():
            raise SystemExit("demo: the altered archive left files behind")

        d.step("The evidence report for auditors and the regulator",
               "One report lists every certificate, server and archive with its NIST IR 8547 and CNSA 2.0 status and deadline.")
        d.run("readiness", "report", "--ca", "pki", "--targets", "hosts.txt", "--backups", "archive", "--html", "evidence.html",
              expect=2, contains=["assets"])

        print(f"\nOpen these in a browser:\n  {work / 'readiness-before.html'}\n  {work / 'readiness-after.html'}\n  {work / 'evidence.html'}")
        if (work / "wolfpack-out" / "report.html").exists():
            print(f"  {work / 'wolfpack-out' / 'report.html'}")
        if not a.auto:
            token = "demobank"
            cmd = [py, "-m", "pqcsuite", "console", "--ca", "pki", "--edge", f"http://127.0.0.1:{metrics}", "--backups", "archive",
                   "--listen", f"127.0.0.1:{console}"]
            d.procs.append(subprocess.Popen(cmd, cwd=work, env={**__import__("os").environ, "PQCSUITE_CONSOLE_TOKEN": token},
                                            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))
            print(f"\nThe console is at http://127.0.0.1:{console}/  (access token: {token})")
            d.pause("  [Enter] to stop everything ")
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        d.stop()


if __name__ == "__main__":
    main()
