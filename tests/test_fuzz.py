"""Malformed input, seeded so failures reproduce: every entry point that reads something from outside must answer with its own
error (never a crash, a hang or a half-written file). Longer runs of the same generators found the console cases below."""
import base64
import json
import os
import random
import shutil
import tempfile
import time
import tomllib
import unittest
import unittest.mock
from pathlib import Path

from pqcsuite import vault
from pqcsuite.console import App, Settings
from pqcsuite.pki import CA, CAError
from pqcsuite.pki.acme import Problem, Service
from pqcsuite.tls.edge import load_config as edge_config
from pqcsuite.tls.http import HTTPError, _read_message
from pqcsuite.vpn import load_config as vpn_config
from pqcsuite.vpn.wireguard import load_gateway


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def junk(rnd, depth=0):
    k = rnd.randrange(9 if depth < 3 else 5)
    if k == 0:
        return None
    if k == 1:
        return rnd.choice([True, False])
    if k == 2:
        return rnd.choice([0, -1, 1, 10 ** 30, rnd.randrange(-2 ** 40, 2 ** 40)])
    if k == 3:
        return rnd.choice(["", "x" * rnd.randrange(300), "../../etc/passwd", "\x00", "server", "a,b,,c", "ünï"])
    if k == 4:
        return b64(os.urandom(rnd.randrange(80)))
    if k == 5:
        return [junk(rnd, depth + 1) for _ in range(rnd.randrange(4))]
    if k == 6:
        return {rnd.choice(["alg", "jwk", "kid", "nonce", "url", "kty", "crv", "x", "identifiers", "csr", "type", "value"]): junk(rnd, depth + 1)
                for _ in range(rnd.randrange(5))}
    if k == 7:
        return b64(json.dumps(junk(rnd, depth + 1)).encode())
    return rnd.random()


class FuzzTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        self.rnd = random.Random(20260928)

    def test_corrupted_archives_fail_cleanly_and_leave_nothing(self):
        me = vault.Identity.generate()
        src = self.d / "data"
        src.write_bytes(os.urandom(200_000))
        vault.encrypt(src, self.d / "good.pqv", [me.public])
        good, rnd = (self.d / "good.pqv").read_bytes(), self.rnd
        mutations = [lambda b: os.urandom(rnd.randrange(2000)), lambda b: b[:rnd.randrange(len(b))],
                     lambda b: (lambda i: b[:i] + os.urandom(rnd.randrange(64)) + b[i + rnd.randrange(1, 64):])(rnd.randrange(len(b))),
                     lambda b: (lambda i: b[:i] + bytes([b[i] ^ (1 + rnd.randrange(255))]) + b[i + 1:])(rnd.randrange(min(len(b), 4096))),
                     lambda b: (lambda i, j: b[:i] + b[j:j + 5000] + b[i:])(rnd.randrange(len(b)), rnd.randrange(len(b))),
                     lambda b: b + os.urandom(rnd.randrange(1, 5000))]
        for n in range(150):
            data = rnd.choice(mutations)(good)
            if data == good:
                continue
            p, out = self.d / "x.pqv", self.d / "out"
            p.write_bytes(data)
            shutil.rmtree(out, ignore_errors=True)
            start = time.monotonic()
            with self.subTest(n=n):
                for fn in (lambda: vault.inspect(p), lambda: vault.decrypt(p, out, me)):
                    try:
                        fn()
                    except vault.VaultError:
                        pass
                self.assertFalse(out.exists() and any(out.rglob("*")), "a refused archive left something behind")
                self.assertLess(time.monotonic() - start, 5)

    def test_acme_answers_every_request_with_an_acme_problem(self):
        ca = CA.init(self.d / "pki", "Root")
        svc, rnd = Service(ca, "http://127.0.0.1:14000", allow=["*.test"], validate_async=False), self.rnd
        paths = ["/directory", "/new-nonce", "/new-account", "/new-order", "/acct/1", "/order/x", "/authz/x", "/chall/x", "/finalize/x",
                 "/cert/x", "/revoke-cert", "/key-change", "/../../etc/passwd", "/" + "a" * 3000]
        for n in range(1500):
            body = rnd.choice([os.urandom(rnd.randrange(400)), json.dumps(junk(rnd)).encode(),
                               json.dumps({"protected": b64(json.dumps({"alg": rnd.choice(["ES256", "none", "HS256", 5]), "nonce": svc.nonce(),
                                                                        "url": "http://127.0.0.1:14000" + rnd.choice(paths),
                                                                        rnd.choice(["jwk", "kid"]): junk(rnd)}).encode()),
                                           "payload": b64(json.dumps(junk(rnd)).encode()), "signature": b64(os.urandom(64))}).encode()])
            try:
                svc.handle(rnd.choice(["GET", "POST", "HEAD"]), rnd.choice(paths), body)
            except Problem:
                pass

    def test_console_never_answers_malformed_input_with_an_internal_error(self):
        CA.init(self.d / "pki", "Root").crl()
        app, rnd = App(Settings(ca=str(self.d / "pki"), audit_log=str(self.d / "a.jsonl")), token="t"), self.rnd
        routes = ["/api/certificates/issue", "/api/certificates/revoke", "/api/scan", "/api/overview", "/api/nope"]
        with unittest.mock.patch("pqcsuite.console.App.run_scan"):
            for n in range(800):
                body = {rnd.choice(["kind", "common_name", "names", "days", "serial", "reason", "targets"]): junk(rnd) for _ in range(rnd.randrange(5))}
                status, out = app.handle("POST" if "overview" not in (r := rnd.choice(routes)) else "GET", r, body)
                self.assertLess(status, 500, (r, body, out))

    def test_found_by_fuzzing_bad_values_are_refused_clearly(self):
        ca = CA.init(self.d / "pki", "Root")
        ca.issue("only.test", "server")
        app = App(Settings(ca=str(self.d / "pki"), audit_log=str(self.d / "a.jsonl")), token="t")
        for body in ({"serial": ""}, {"serial": {}}, {"serial": 1}, {"serial": "ab"}, {"serial": ca.records()[0].serial, "reason": []}):
            with self.subTest(body=body):
                self.assertEqual(app.handle("POST", "/api/certificates/revoke", body)[0], 400)
        self.assertEqual(ca.records()[0].status, "valid", "an empty serial must not revoke the only certificate")
        self.assertEqual(app.handle("POST", "/api/certificates/issue", {"kind": "server", "common_name": "c.test", "days": 10 ** 30})[0], 200,
                         "a huge validity is capped at the CA's own, not an error")
        for body in ({"kind": [], "common_name": "a.test"}, {"kind": "server", "common_name": "a.test", "days": True}, {"kind": "server", "common_name": None},
                     {"kind": "server", "common_name": "a.test", "days": -5}):
            with self.subTest(body=body):
                self.assertEqual(app.handle("POST", "/api/certificates/issue", body)[0], 400)
        for targets in ({}, "{}", "a b:443", "<script>"):
            with self.subTest(targets=targets):
                self.assertEqual(app.handle("POST", "/api/scan", {"targets": targets})[0], 400)
        self.assertEqual(app.handle("POST", "/api/certificates/issue", {"kind": "server", "common_name": "b.test", "days": "30"})[0], 200)

    def test_the_http_reader_rejects_malformed_messages(self):
        rnd = self.rnd

        class Conn:
            def __init__(self, data):
                self.data = data

            def recv(self, n, timeout=None):
                chunk, self.data = self.data[:rnd.randrange(1, n + 1)], self.data[n:]
                return chunk
        samples = [b"POST / HTTP/1.1\r\nContent-Length: " + v + b"\r\n\r\nabc" for v in (b"-1", b"99999999", b"x", b"\xff", b"")]
        for n in range(600):
            data = rnd.choice(samples + [os.urandom(rnd.randrange(300)), b"GET / HTTP/1.1\r\n" + os.urandom(50) + b"\r\n\r\n"])
            try:
                _read_message(Conn(data), 1)
            except HTTPError:
                pass

    def test_config_files_with_wrong_values_give_an_error_not_a_crash(self):
        rnd = self.rnd
        vals = ['"x"', '1', '-1', '0', '1.5', 'true', '[]', '["a"]', '[1, 2]', '{}', '"0.0.0.0:0"', '"10.0.0.0/33"', '"host:99999"', '""',
                '"strict"', '"terminate"', '"originate"', '"10.99.0.0/24"', '["0.0.0.0/0"]', '{b = ["10.1.0.0/24"]}']
        keys = {"edge": ["name", "mode", "listen", "target", "policy", "cert", "key", "ca", "require_client_cert", "crl", "crl_url", "crl_every",
                         "fallback_cert", "fallback_key", "max_connections", "bogus"],
                "site": ["name", "address", "cert", "key", "ca", "crl", "crl_url", "keyring_listen"],
                "peer": ["name", "address", "local_subnets", "remote_subnets", "initiate", "keyring", "profile", "rotate_minutes"],
                "wireguard": ["name", "endpoint", "keyring_listen", "pool", "cert", "key", "ca", "crl_url", "users", "routes", "sites", "rotate_minutes"],
                "console": ["listen", "ca", "scan_targets", "scan_every_hours", "check_updates"]}

        def section(name, many):
            fields = rnd.sample(keys[name], rnd.randrange(len(keys[name]) + 1))
            return (f"[[{name}]]" if many else f"[{name}]") + "\n" + "".join(f"{k} = {rnd.choice(vals)}\n" for k in fields)
        makers = [(edge_config, lambda: "".join(section("edge", True) for _ in range(rnd.randrange(3)))),
                  (vpn_config, lambda: section("site", False) + "".join(section("peer", True) for _ in range(rnd.randrange(3)))),
                  (load_gateway, lambda: section("wireguard", False)), (Settings.load, lambda: section("console", False))]
        p = self.d / "c.toml"
        for n in range(800):
            load, make = rnd.choice(makers)
            text = make()
            try:
                tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                continue
            p.write_text(text, encoding="utf-8")
            try:
                load(p)
            except (ValueError, CAError, OSError):
                pass



if __name__ == "__main__":
    unittest.main()
