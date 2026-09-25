import unittest
from pathlib import Path

from wolfpack import pack, cbom
from wolfpack.elders import lookup, parse_transformation, curve
from wolfpack.scouts.suites import cipher_string, ssh_token, sig_scheme

CORPUS = Path(__file__).resolve().parent.parent / "bench" / "corpus"


class Elders(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(lookup("DESede"), "3DES")
        self.assertEqual(lookup("mlkem768x25519-sha256"), "X25519MLKEM768")
        self.assertEqual(parse_transformation("AES/ECB/PKCS5Padding"), ("AES", {"mode": "ECB", "padding": "pkcs5"}))
        self.assertEqual(curve("NID_X9_62_prime256v1"), "P-256")


class Suites(unittest.TestCase):
    def test_negations_are_ignored(self):
        algos = {a for a, _ in cipher_string("ECDHE-RSA-AES128-GCM-SHA256:HIGH:!aNULL:!MD5:!RC4")}
        self.assertEqual(algos, {"ECDH", "RSA", "AES", "SHA-256"})

    def test_ssh(self):
        self.assertEqual(ssh_token("diffie-hellman-group1-sha1")[0], ("DH", {"key_size": 1024}))
        self.assertEqual(ssh_token("-3des-cbc"), [])

    def test_sig(self):
        self.assertEqual([a for a, _ in sig_scheme("SHA1withRSA")], ["RSA", "SHA-1"])


class Pack(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = pack.run(CORPUS, "corpus")

    def accepted(self, f):
        return {s.algo for s in self.r.sightings if s.file == f and s.verdict == "accepted"}

    def test_traps_rejected(self):
        self.assertEqual(self.accepted("py/notes.py"), set())
        self.assertEqual(self.accepted("config/java.security"), set())
        self.assertNotIn("DES", self.accepted("java/TokenSigner.java"))

    def test_second_look(self):
        self.assertIn("SHA-1", self.accepted("java/Hasher.java"))
        self.assertNotIn("AES", self.accepted("java/Hasher.java"))

    def test_tiers(self):
        t = {a.variant: a.tier for a in self.r.assets}
        self.assertEqual(t["AES-ECB"], "critical")
        self.assertEqual(t["ML-KEM-768"], "ok")
        self.assertEqual(t["TLS 1.3"], "ok")

    def test_cbom_shape(self):
        b = cbom.build("corpus", self.r.assets, self.r.artifacts, self.r.libraries)
        self.assertEqual(b["specVersion"], "1.6")
        kinds = {c["cryptoProperties"]["assetType"] for c in b["components"] if c["type"] == "cryptographic-asset"}
        self.assertTrue({"algorithm", "protocol", "certificate", "related-crypto-material"} <= kinds)


if __name__ == "__main__":
    unittest.main()


class Pack2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = pack.run(CORPUS, "corpus")

    def verdicts(self, f):
        return {(s.algo, s.verdict) for s in self.r.sightings if s.file == f}

    def test_suppression(self):
        self.assertIn(("MD5", "suppressed"), self.verdicts("py/suppressed.py"))

    def test_registry_but_not_denylist(self):
        v = self.verdicts("py/policy.py")
        self.assertIn(("AES", "accepted"), v)
        self.assertIn(("MD5", "quarantined"), v)

    def test_binary_constants(self):
        self.assertTrue({("AES", "accepted"), ("MD5", "accepted")} <= self.verdicts("bin/legacy_tool"))

    def test_deployed_trail(self):
        a = next(x for x in self.r.assets if x.variant == "RSA-2048")
        self.assertEqual(a.exposure, "deployed key or certificate")

    def test_library_provides(self):
        b = cbom.build("corpus", self.r.assets, self.r.artifacts, self.r.libraries)
        prov = {d["ref"]: d.get("provides", []) for d in b["dependencies"]}
        self.assertIn("crypto/ML-KEM-768", prov["lib/pypi/liboqs-python"])


class Probe(unittest.TestCase):
    def test_hello_retry_parsing(self):
        import socket, struct, threading
        from wolfpack.scouts import probe
        body = b"\x03\x03" + probe.HRR + b"\x00" + b"\x13\x01" + b"\x00"
        exts = struct.pack(">HHH", 0x002B, 2, 0x0304) + struct.pack(">HHH", 0x0033, 2, 0x11EC)
        body += struct.pack(">H", len(exts)) + exts
        hs = b"\x02" + struct.pack(">I", len(body))[1:] + body
        record = b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(32)
        port = srv.getsockname()[1]

        def serve():
            for _ in range(len(probe.GROUPS) + 1):
                c, _ = srv.accept()
                c.recv(4096)
                c.sendall(record)
                c.close()
        threading.Thread(target=serve, daemon=True).start()
        r = probe.tls_groups("127.0.0.1", port, 3)
        srv.close()
        self.assertEqual(r["preferred"], "X25519MLKEM768")
        self.assertEqual(r["pq"], ["X25519MLKEM768"])
