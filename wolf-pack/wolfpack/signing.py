"""Signed CBOMs: a detached signature over the exact bytes of a file, with ML-DSA-65 where the installed `cryptography` has it
(46 and later), else Ed25519. Verification against a public key you already trust proves who produced the inventory and that
nothing changed since."""
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:
    mldsa = None

CONTEXT = b"wolfpack-cbom"


def algorithm(key):
    return "ML-DSA-65" if mldsa and isinstance(key, (mldsa.MLDSA65PrivateKey, mldsa.MLDSA65PublicKey)) else "Ed25519"


def keygen(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    key = mldsa.MLDSA65PrivateKey.generate() if mldsa else ed25519.Ed25519PrivateKey.generate()
    priv, pub = out / "signing-key.pem", out / "signing-key.pub.pem"
    priv.write_bytes(key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption()))
    pub.write_bytes(key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo))
    try:
        priv.chmod(0o600)
    except OSError:
        pass
    return priv, pub, algorithm(key)


def _sign(key, data):
    return key.sign(data, CONTEXT) if algorithm(key) == "ML-DSA-65" else key.sign(data)


def _verify(pub, sig, data):
    pub.verify(sig, data, CONTEXT) if algorithm(pub) == "ML-DSA-65" else pub.verify(sig, data)


def fingerprint(pub):
    return hashlib.sha256(pub.public_bytes(ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)).hexdigest()[:32]


def sign(path, key_path):
    """Writes <file>.sig next to the file and returns its path."""
    data = Path(path).read_bytes()
    key = ser.load_pem_private_key(Path(key_path).read_bytes(), None)
    if algorithm(key) == "Ed25519" and not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("signing keys must be ML-DSA-65 or Ed25519 (make one with `wolfpack keygen`)")
    pub = key.public_key()
    sig = {"file": Path(path).name, "algorithm": algorithm(key), "sha256": hashlib.sha256(data).hexdigest(),
           "signature": base64.b64encode(_sign(key, data)).decode(), "key_fingerprint": fingerprint(pub),
           "public_key": pub.public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo).decode(),
           "signed": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    out = Path(str(path) + ".sig")
    out.write_text(json.dumps(sig, indent=1), encoding="utf-8")
    return out


def verify(path, pub_path=None, sig_path=None):
    """(ok, message). Without a trusted public key only integrity is checked, against the key carried in the signature file."""
    data = Path(path).read_bytes()
    sig = json.loads(Path(sig_path or str(path) + ".sig").read_text(encoding="utf-8"))
    pub = ser.load_pem_public_key(Path(pub_path).read_bytes() if pub_path else sig["public_key"].encode())
    if hashlib.sha256(data).hexdigest() != sig.get("sha256"):
        return False, "the file changed after it was signed"
    try:
        _verify(pub, base64.b64decode(sig["signature"]), data)
    except (InvalidSignature, ValueError, TypeError):
        return False, "the signature does not match this key"
    who = f"{sig['algorithm']} key {fingerprint(pub)}"
    if not pub_path:
        return True, f"intact, signed by {who}; pass --pub with the key you trust to check who signed it"
    return True, f"verified: signed by {who} on {sig.get('signed', '?')}"
