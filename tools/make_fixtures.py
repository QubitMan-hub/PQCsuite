"""Write the golden fixtures with today's code: python tools/make_fixtures.py tests/golden

Every key, certificate, token and passphrase here is synthetic and created on the spot; names end in .invalid.
Lifetimes reach past 2099 so the fixtures do not expire while the restructure uses them.
"""
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PW = b"golden-test-only"
DAYS = 36_500
EXPIRES = "2099-01-01T00:00:00+00:00"
README = """# Golden fixtures

Written by `tools/make_fixtures.py` from the suite at commit 5f8c349 (Stage 0 of the four-product restructure).
Every key, certificate, token and passphrase here is synthetic, made for these tests and disposable. Names end in
`.invalid`; the passphrase is `golden-test-only`. None of it protects anything.

Regenerate with `python tools/make_fixtures.py tests/golden` (with OpenSSL 3.5+ for the suite), then update
`MANIFEST.json` in the same commit. Regenerating changes every key, so do it only on purpose.
"""
APP = '''import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def cache_key(data):
    return hashlib.md5(data).hexdigest()  # wolfpack:ignore (cache key, not security)


def keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048), AESGCM(AESGCM.generate_key(bit_length=256))
'''


def _vault(out, ca):
    from pqcsuite import vault
    d = out / "vault"
    d.mkdir(parents=True)
    (d / "plain.txt").write_bytes(b"golden plaintext: legitimate data written before the restructure\n")
    for name, cnsa2 in (("recipient", False), ("cnsa2", True)):
        ident = vault.Identity.generate(cnsa2=cnsa2)
        ident.save(d / f"{name}.key", PW)
        (d / f"{name}.pub").write_bytes(ident.public.pem())
    rec = vault.Recipient.load(d / "recipient.pub")
    signer_dir, _ = ca.issue("signer.golden.invalid", "client", days=DAYS, out=out / "pki/signer", passphrase=PW)
    signer = vault.load_signer(signer_dir / "cert.pem", signer_dir / "key.pem", PW)
    vault.encrypt(d / "plain.txt", d / "unsigned.pqv", [rec])
    vault.encrypt(d / "plain.txt", d / "signed.pqv", [rec], signer)
    vault.encrypt(d / "plain.txt", d / "cnsa2.pqv", [vault.Recipient.load(d / "cnsa2.pub")])


def _pki(out):
    from pqcsuite.pki import CA
    root = out / "pki/ca"
    CA.init(root, "Golden Test CA", days=DAYS, passphrase=PW)
    ca = CA(root, PW)
    ca.issue("edge.golden.invalid", "server", days=DAYS, out=out / "pki/edge", passphrase=PW)
    _, rec = ca.issue("revoked.golden.invalid", "server", days=DAYS, out=out / "pki/revoked", passphrase=PW)
    ca.revoke(rec.serial, "keyCompromise")
    return ca


def _invite(out, ca):
    from cryptography.x509 import load_pem_x509_certificate
    from pqcsuite.pki.est import fingerprint
    d = out / "vpn"
    d.mkdir(parents=True)
    inv = {"pqcsuite_invite": 1, "name": "laptop.golden.invalid", "enroll": "https://enroll.golden.invalid:8443",
           "ca_fingerprint": fingerprint(load_pem_x509_certificate(ca.anchor.read_bytes())), "gateway": "gateway.golden.invalid:51821",
           "server_name": "gateway.golden.invalid", "expires": EXPIRES, "token": "golden-token-not-secret"}
    (d / "invite.pqcinvite").write_text(json.dumps(inv, indent=1))


def _readiness(out):
    project = out / "readiness/project"
    (project / "generated").mkdir(parents=True)
    (project / "app.py").write_text(APP)
    (project / "generated/skipped.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")
    (project / ".wolfpack.toml").write_text('exclude = ["generated"]\n')
    scan = out / "readiness/scan-output"
    subprocess.run([sys.executable, "-m", "wolfpack", "scan", str(project), "-o", str(scan)], check=True, cwd=ROOT / "wolf-pack",
                   stdout=subprocess.DEVNULL)
    (out / "readiness/baseline").mkdir()
    for name in ("cbom.json", "findings.json"):
        shutil.copy(scan / name, out / "readiness/baseline" / name)
    shutil.rmtree(scan)


def _configs(out):
    (out / "configs").mkdir()
    for name in ("edge.toml", "vpn-hq.toml", "vpn-branch.toml", "wireguard-gateway.toml"):
        shutil.copy(ROOT / "examples" / name, out / "configs" / name)


def main(out):
    out = Path(out).resolve()
    for child in ("vault", "pki", "vpn", "readiness", "configs"):
        shutil.rmtree(out / child, ignore_errors=True)
    ca = _pki(out)
    _vault(out, ca)
    ca.crl(days=DAYS)
    _invite(out, ca)
    _readiness(out)
    _configs(out)
    (out / "README.md").write_text(README)
    (out / ".gitattributes").write_text("* -text\n")
    skip = {"MANIFEST.json", "test_golden_old_code.py", "__pycache__"}
    manifest = {p.relative_to(out).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(out.rglob("*"))
                if p.is_file() and not skip & set(p.relative_to(out).parts)}
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=1) + "\n")
    return manifest


if __name__ == "__main__":
    print(f"{len(main(sys.argv[1]))} fixture files written")
