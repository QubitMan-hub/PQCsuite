"""Python values followed through the syntax tree, look-alike names and unreachable code; each with its ablation and traps."""
import textwrap

from wolfpack import pack


def write(root, files):
    for name, text in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")


def accepted(result):
    return {(s.file, s.algo, s.params.get("key_size")) for s in result.sightings if s.verdict == "accepted"}


PROJECT = {
    "pkg/__init__.py": "",
    "pkg/settings.py": """
        KEY_BITS = 1024
        DIGEST = "md5"
        CONFIG = {"hash": "sha1"}
    """,
    "pkg/primitives.py": """
        import hashlib
        from cryptography.hazmat.primitives.asymmetric import rsa

        def make_key(bits):
            return rsa.generate_private_key(public_exponent=65537, key_size=bits)

        def fingerprint(data, algo):
            return hashlib.new(algo, data).hexdigest()
    """,
    "pkg/reexport.py": "from hashlib import sha1 as quick_digest\n",
    "pkg/service.py": """
        import hashlib
        from .settings import KEY_BITS, DIGEST, CONFIG
        from .primitives import make_key, fingerprint
        from .reexport import quick_digest

        class Signer:
            ALGO = "sha224"
            def __init__(self, bits=KEY_BITS):
                self.key = make_key(bits)
            def tag(self, data):
                return hashlib.new(self.ALGO, data)
            def checksum(self, data, name=DIGEST):
                return hashlib.new(name, data)

        def main():
            fingerprint(b"x", CONFIG["hash"])
            quick_digest(b"y")
    """,
}


def test_values_cross_files_classes_dicts_defaults_and_callers(tmp_path):
    write(tmp_path, PROJECT)
    found = accepted(pack.run(tmp_path, "p"))
    assert ("pkg/primitives.py", "RSA", 1024) in found
    assert ("pkg/primitives.py", "SHA-1", None) in found
    assert {("pkg/service.py", "MD5", None), ("pkg/service.py", "SHA-224", None), ("pkg/service.py", "SHA-1", None)} <= found
    assert ("pkg/settings.py", "MD5", None) in found


def test_each_value_switch_changes_the_result(tmp_path):
    write(tmp_path, PROJECT)
    full = accepted(pack.run(tmp_path, "p"))
    assert ("pkg/primitives.py", "RSA", 1024) not in accepted(pack.run(tmp_path, "p", roles=pack.Roles.without("parameters")))
    no_cross = accepted(pack.run(tmp_path, "p", roles=pack.Roles.without("cross-file")))
    assert ("pkg/service.py", "SHA-1", None) not in no_cross and ("pkg/service.py", "MD5", None) not in no_cross
    assert no_cross < full


def test_rebound_names_and_runtime_attributes_are_not_constants(tmp_path):
    write(tmp_path, {"settings.py": 'DIGEST = "md5"\n', "app.py": """
        import hashlib
        from settings import DIGEST
        class Box:
            ALGO = "sha1"
            def configure(self, choice):
                self.ALGO = choice
            def run(self, data):
                return hashlib.new(self.ALGO, data)
        def handle(request):
            DIGEST = request.args["d"]
            return hashlib.new(DIGEST, request.body)
    """})
    calls = {(s.file, s.algo) for s in pack.run(tmp_path, "p").sightings if s.evidence == "call"}
    assert calls == set()


def test_unresolvable_values_are_never_guessed(tmp_path):
    write(tmp_path, {"dyn.py": """
        import hashlib, os
        def digest(data, name):
            return hashlib.new(name, data)
        def handler(request):
            return digest(request.body, request.headers.get("X-Digest", os.environ.get("DIGEST")))
        def loop(name):
            return loop(name) or hashlib.new(name)
    """})
    assert {a for _, a, _ in accepted(pack.run(tmp_path, "p"))} == set()


def test_lookalike_names_are_rejected_only_when_the_definition_does_no_cryptography(tmp_path):
    write(tmp_path, {"names.py": """
        import hashlib
        def md5(text):
            return "md5:" + text
        class rsa:
            region = "eu"
        def sha512_hex(data):
            return hashlib.sha512(data).hexdigest()
        def blowfish_round(x, k):
            return ((x << 3) ^ k) & 0xffffffff
        md5("a"), sha512_hex(b"a"), blowfish_round(1, 2)
    """})
    full = {a for _, a, _ in accepted(pack.run(tmp_path, "p"))}
    assert "MD5" not in full and "RSA" not in full
    assert {"SHA-512", "Blowfish"} <= full
    assert {"MD5", "RSA"} <= {a for _, a, _ in accepted(pack.run(tmp_path, "p", roles=pack.Roles.without("lookalikes")))}


def test_unreachable_code_is_held_not_dropped(tmp_path):
    write(tmp_path, {"dead.py": """
        import hashlib
        def digest(data):
            return hashlib.sha256(data).digest()
            hashlib.sha1(data)
        if False:
            hashlib.md5(b"x")
        while 0:
            hashlib.sha224(b"x")
        if True:
            pass
        else:
            hashlib.blake2b(b"x")
    """})
    r = pack.run(tmp_path, "p")
    verdicts = {s.algo: s.verdict for s in r.sightings}
    assert verdicts["SHA-256"] == "accepted"
    assert all(verdicts[a] == "quarantined" for a in ("SHA-1", "MD5", "SHA-224", "BLAKE2"))
    off = {a for _, a, _ in accepted(pack.run(tmp_path, "p", roles=pack.Roles.without("reachability")))}
    assert {"SHA-1", "MD5"} <= off


def test_hostile_python_is_survived(tmp_path):
    write(tmp_path, {
        "deep.py": "import hashlib\nx = " + "+".join(["1"] * 20000) + "\nhashlib.sha256(b'')\n",
        "nested.py": "import hashlib\n" + "".join("    " * i + "if x:\n" for i in range(90)) + "    " * 90 + "hashlib.md5(b'')\n",
        "a.py": "from b import NAME\nfrom b import alias as alias\n",
        "b.py": "from a import NAME\nfrom a import alias\n",
        "broken.py": "def broken(:\n",
        "latin.py": b"# \xe9\xe9\nimport hashlib\nhashlib.sha384(b'')\n".decode("latin-1"),
        "recursive.py": "import hashlib\ndef f(n='md5'):\n    return f(n) or hashlib.new(n)\n",
    })
    r = pack.run(tmp_path, "p")
    algos = {s.algo for s in r.sightings if s.verdict == "accepted"}
    assert {"SHA-384", "MD5"} <= algos
