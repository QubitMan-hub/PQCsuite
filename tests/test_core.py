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
        self.assertEqual(lookup("SHA-512/256"), "SHA-512")
        self.assertEqual(lookup("HMACSHA1"), "HMAC")


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

    def test_runtime_name_prefix_is_not_an_algorithm(self):
        self.assertEqual(self.accepted("java/Digests.java"), {"SHA-256"})

    def test_split_literal_shares_fate_but_neighbours_do_not(self):
        self.assertEqual(self.accepted("py/token_kind.py"), {"RSA", "SHA-256"})

    def test_jwt_default_only_when_algorithm_is_absent(self):
        self.assertEqual(self.accepted("py/jwt_calls.py"), {"ECDSA", "SHA-256"})

    def test_hmac_and_kdf_report_their_hash(self):
        self.assertEqual(self.accepted("java/Macs.java"), {"HMAC", "SHA-256", "PBKDF2", "SHA-1"})

    def test_libsodium_calls_but_not_its_size_constants(self):
        self.assertEqual(self.accepted("c/sodium.c"), {"BLAKE2", "Ed25519", "scrypt", "Salsa20"})
        self.assertEqual(self.accepted("c/sodium_api.h"), set())

    def test_names_that_are_not_algorithms(self):
        self.assertEqual(self.accepted("js/hmac_bits.js"), {"HMAC"})
        self.assertEqual(self.accepted("go/flags.go"), set())
        self.assertEqual(self.accepted("cs/Blob.cs"), set())

    def test_implementations_by_their_constants(self):
        self.assertEqual(self.accepted("c/keccak.c"), {"SHA-3"})
        self.assertEqual(self.accepted("c/md5_impl.c"), {"MD5"})
        self.assertEqual(self.accepted("go/sm4.go"), {"SM4"})

    def test_one_constant_table_for_source_and_binaries(self):
        import tempfile
        from wolfpack.scouts import binary, implementations
        p = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "k1.c").write_text(f"static const char P[] = \"{p}\";\n", encoding="utf-8")
            (Path(d) / "k1.so").write_bytes(b"\x7fELF" + bytes.fromhex(p)[::-1])
            src = implementations.scan(d)[0]
            bins = binary.scan(d)[0]
        self.assertEqual({(s.algo, s.params["curve"]) for s in src + bins}, {("ECC", "secp256k1")})
        self.assertEqual(len(bins), 1)

    def test_sodium_bindings_sjcl_and_extensionless_config(self):
        self.assertEqual(self.accepted("cs/SodiumInterop.cs"), set())
        self.assertEqual(self.accepted("cs/SodiumUse.cs"), {"Ed25519", "BLAKE2"})
        self.assertEqual(self.accepted("js/sjcl_use.js"), {"PBKDF2", "AES"})
        self.assertIn("TLS 1.2", self.accepted("config/tls"))
        self.assertEqual(self.accepted("config/NOTES"), set())
        self.assertEqual(self.accepted("js/perf.js"), set())

    def test_keys_by_variable_or_numbers_and_library_digests(self):
        self.assertEqual(self.accepted("java/Codec.java"), {"SHA-256", "MD5"})
        self.assertEqual(self.accepted("go/keygen.go"), {"RSA", "ECDSA"})
        self.assertEqual(self.accepted("cs/Kdf.cs"), {"HMAC", "SHA-512", "ECDH"})
        self.assertEqual(self.accepted("py/tpm_keys.py"), {"RSA", "ECC"})

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


class Roles(unittest.TestCase):
    def accepted(self, off, f):
        r = pack.run(CORPUS, "corpus", roles=pack.Roles.without(*off))
        return {s.algo for s in r.sightings if s.file == f and s.verdict == "accepted"}

    def test_unknown_role(self):
        with self.assertRaises(ValueError):
            pack.Roles.without("sheep")

    def test_second_look_covers_its_parts(self):
        self.assertEqual(pack.Roles.without("second-look").off, ["flow", "registries", "siblings"])

    def test_propagation_recovers_key_size(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "k.py").write_text("from cryptography.hazmat.primitives.asymmetric import rsa\n\nKEY_BITS = 1024\n\n\n"
                                          "def make():\n    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_BITS)\n", encoding="utf-8")
            full = {a.variant: a.tier for a in pack.run(d, "k").assets}
            blind = {a.variant: a.tier for a in pack.run(d, "k", roles=pack.Roles.without("propagation")).assets}
        self.assertEqual(full.get("RSA-1024"), "critical")
        self.assertNotIn("RSA-1024", blind)

    def test_format_sniffing_is_not_a_registry(self):
        self.assertEqual(self.accepted([], "py/keysniff.py"), {"ECC"})
        self.assertEqual(self.accepted(["recognition"], "py/keysniff.py"), {"ECC", "RSA", "ECDSA", "Ed25519"})
        self.assertIn("AES", self.accepted([], "py/policy.py"))

    def test_cross_file_constant_resolves_by_owner(self):
        self.assertEqual(self.accepted([], "java/Keys.java"), {"AES"})
        self.assertEqual(self.accepted(["cross-file"], "java/Keys.java"), set())

    def test_final_int_constant_gives_key_size_but_a_local_does_not(self):
        sizes = lambda off: {s.params.get("key_size") for s in pack.run(CORPUS, "c", roles=pack.Roles.without(*off)).sightings
                             if s.file == "java/KeySizes.java" and s.verdict == "accepted"}
        self.assertEqual(sizes([]), {1024, None})
        self.assertEqual(sizes(["propagation"]), {None})

    def test_implementation_scout_is_live(self):
        self.assertEqual(self.accepted(["implementations"], "c/keccak.c"), set())

    def test_each_role_is_live(self):
        self.assertNotIn("SHA-256", self.accepted(["corroboration"], "py/token_kind.py"))
        self.assertNotIn("SHA-256", self.accepted(["siblings"], "py/token_kind.py"))
        self.assertNotIn("AES", self.accepted(["registries"], "py/policy.py"))
        self.assertEqual(self.accepted(["source"], "java/TokenSigner.java"), set())
        self.assertIn("MD5", self.accepted(["den"], "py/notes.py"))


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


class Scope(unittest.TestCase):
    def test_test_and_benchmark_directories(self):
        from wolfpack.scouts import is_test
        for p in ("UnitTestsNet46/jwk/JwkTest.cs", "src/Jose.Tests/A.cs", "benches/x25519.rs", "browserTest/perf.js", "tests/a.py"):
            self.assertTrue(is_test(p), p)
        for p in ("src/contests/a.py", "src/attestation/a.py", "latest/a.go", "src/jwt/a.py"):
            self.assertFalse(is_test(p), p)


class Regressions(unittest.TestCase):
    def test_ssh_probe_survives_early_close(self):
        import socket, threading
        from wolfpack.scouts import tls
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)

        def serve():
            c, _ = srv.accept()
            c.sendall(b"SSH-2.0-test\r\n")
            c.recv(100)
            c.shutdown(socket.SHUT_RDWR)
            c.close()
        threading.Thread(target=serve, daemon=True).start()
        out = []
        t = threading.Thread(target=lambda: out.append(tls.probe_ssh(f"127.0.0.1:{srv.getsockname()[1]}", 3)), daemon=True)
        t.start()
        t.join(5)
        srv.close()
        self.assertFalse(t.is_alive())
        self.assertIn("error", out[0][3])

    def test_ipv6_target_without_port(self):
        from wolfpack.scouts.tls import _split
        self.assertEqual(_split("[::1]", 443), ("::1", 443))
        self.assertEqual(_split("[::1]:8443", 443), ("::1", 8443))

    def test_nuget_without_inline_version(self):
        import tempfile
        from wolfpack.scouts import deps
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.csproj").write_text('<PackageReference Include="BouncyCastle.Cryptography" />\n'
                                                '<PackageReference Include="NSec.Cryptography" Version="24.4.0" />', encoding="utf-8")
            libs = {(l.name, l.version) for l in deps.scan(d)}
        self.assertEqual(libs, {("bouncycastle.cryptography", ""), ("nsec.cryptography", "24.4.0")})

    def test_corrupt_jar_entry_is_skipped(self):
        import io, tempfile, zipfile
        from wolfpack.scouts import binary
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("Bad.class", b"javax/crypto" * 50)
            z.writestr("Good.class", b"javax/crypto\x00\x03MD5\x00")
        data = bytearray(buf.getvalue())
        i = data.find(b"Bad.class") + len("Bad.class")
        data[i + 2:i + 12] = b"\xff" * 10
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "app.jar").write_bytes(bytes(data))
            sights, _, _ = binary.scan(d)
        self.assertEqual({(s.algo, s.file) for s in sights}, {("MD5", "app.jar!Good.class")})

    def test_config_key_size_does_not_blank_curve(self):
        import tempfile
        from wolfpack.scouts import config
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "keys.yaml").write_text("key_algorithm: ECDSA\nkey_size: 2048\n", encoding="utf-8")
            s = config.scan(d)[0]
        self.assertEqual([(x.algo, x.params) for x in s], [("ECDSA", {})])


if __name__ == "__main__":
    unittest.main()
