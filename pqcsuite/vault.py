"""Quantum-safe file and backup encryption.

Each recipient's copy of the file key is wrapped with a hybrid KEM: X25519 and ML-KEM-768 combined as in X-Wing
(SHA3-256 over both shared secrets, the X25519 ciphertext and public key), so breaking it needs both broken. The data is
AES-256-GCM in 1 MiB chunks; every nonce carries the chunk number and a last-chunk flag, so truncation, reordering and
tampering are all detected. An optional ML-DSA signature from a CA-issued certificate says who made the file. The recipient
list is not bound into the chunks, so access can be granted later without re-encrypting the data.
"""
import base64
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import struct
import tarfile
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .ca import PUBLIC as MLDSA_PUBLIC, CAError, check_revocation, signed_by

MAGIC, SIG_MAGIC = b"PQV1\n", b"SIG1"
class Suite:
    """A hybrid KEM for wrapping file keys: ML-KEM plus a classical Diffie-Hellman, combined X-Wing style."""

    def __init__(self, name, kem, kem_public, curve, digest):
        self.name, self.kem, self.kem_public, self.curve, self.digest = name, kem, kem_public, curve, digest

    def dh_generate(self):
        return x25519.X25519PrivateKey.generate() if self.curve is None else ec.generate_private_key(self.curve)

    def dh_bytes(self, pub):
        return pub.public_bytes_raw() if self.curve is None else pub.public_bytes(ser.Encoding.X962, ser.PublicFormat.UncompressedPoint)

    def dh_load(self, data):
        return x25519.X25519PublicKey.from_public_bytes(data) if self.curve is None else ec.EllipticCurvePublicKey.from_encoded_point(self.curve, data)

    def exchange(self, priv, pub):
        return priv.exchange(pub) if self.curve is None else priv.exchange(ec.ECDH(), pub)

    def owns(self, kem_key, dh_key):
        kem_ok = isinstance(kem_key, (self.kem, self.kem_public))
        if self.curve is None:
            return kem_ok and isinstance(dh_key, (x25519.X25519PrivateKey, x25519.X25519PublicKey))
        return kem_ok and isinstance(dh_key, (ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey)) and dh_key.curve.name == self.curve.name


SUITES = {s.name: s for s in (
    Suite("X25519+ML-KEM-768/AES-256-GCM", mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey, None, hashlib.sha3_256),
    Suite("P-384+ML-KEM-1024/AES-256-GCM", mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey, ec.SECP384R1(), hashlib.sha384),
)}
SUITE, CNSA2_SUITE = list(SUITES)
CHUNK = 1 << 20
LABEL = b"pqcsuite-vault-v1"
b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode


class VaultError(Exception):
    pass


def _suite_of(kem, dh):
    return next((s for s in SUITES.values() if s.owns(kem, dh)), None)


class Identity:
    """A recipient: an ML-KEM key and a Diffie-Hellman key of one suite (standard, or CNSA 2.0 with cnsa2=True)."""

    def __init__(self, kem, dh):
        self.kem, self.dh = kem, dh
        self.suite = _suite_of(kem, dh)

    @classmethod
    def generate(cls, cnsa2=False):
        s = SUITES[CNSA2_SUITE if cnsa2 else SUITE]
        return cls(s.kem.generate(), s.dh_generate())

    @property
    def public(self):
        return Recipient(self.kem.public_key(), self.dh.public_key())

    def save(self, path, passphrase):
        enc = ser.BestAvailableEncryption(passphrase) if passphrase else ser.NoEncryption()
        pem = b"".join(k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, enc) for k in (self.kem, self.dh))
        from .ca import write
        write(Path(path), pem, secret=True)

    @classmethod
    def load(cls, path, passphrase=None):
        blocks = _pem_blocks(Path(path).read_bytes())
        try:
            keys = [ser.load_pem_private_key(b, passphrase) for b in blocks]
        except (TypeError, ValueError) as e:
            raise VaultError(f"cannot open {path}: {e}") from None
        kem = next((k for k in keys if isinstance(k, (mlkem.MLKEM768PrivateKey, mlkem.MLKEM1024PrivateKey))), None)
        dh = next((k for k in keys if not isinstance(k, (mlkem.MLKEM768PrivateKey, mlkem.MLKEM1024PrivateKey))), None)
        if not (kem and dh and _suite_of(kem, dh)):
            raise VaultError(f"{path} is not a vault identity (needs an ML-KEM key and the matching X25519 or P-384 key)")
        return cls(kem, dh)


class Recipient:
    def __init__(self, kem, dh):
        self.kem, self.dh = kem, dh
        self.suite = _suite_of(kem, dh)

    @property
    def id(self):
        return hashlib.sha256(self.kem.public_bytes_raw() + self.suite.dh_bytes(self.dh)).hexdigest()[:16]

    def pem(self):
        return b"".join(k.public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo) for k in (self.kem, self.dh))

    @classmethod
    def load(cls, path):
        keys = [ser.load_pem_public_key(b) for b in _pem_blocks(Path(path).read_bytes())]
        kem = next((k for k in keys if isinstance(k, (mlkem.MLKEM768PublicKey, mlkem.MLKEM1024PublicKey))), None)
        dh = next((k for k in keys if not isinstance(k, (mlkem.MLKEM768PublicKey, mlkem.MLKEM1024PublicKey))), None)
        if not (kem and dh and _suite_of(kem, dh)):
            raise VaultError(f"{path} is not a vault recipient key")
        return cls(kem, dh)


def _pem_blocks(data):
    parts = data.split(b"-----END ")
    return [p + b"-----END " + parts[i + 1].split(b"\n")[0] + b"\n" for i, p in enumerate(parts[:-1])]


def _combine(suite, ss_kem, ss_dh, ct_dh, pk_dh):
    return suite.digest(ss_kem + ss_dh + ct_dh + pk_dh + LABEL).digest()[:32]


def wrap(dek, recipient, file_id):
    s = recipient.suite
    ss_kem, ct_kem = recipient.kem.encapsulate()
    eph = s.dh_generate()
    ct_dh, pk_dh = s.dh_bytes(eph.public_key()), s.dh_bytes(recipient.dh)
    kek = _combine(s, ss_kem, s.exchange(eph, recipient.dh), ct_dh, pk_dh)
    return {"id": recipient.id, "kem": b64(ct_kem), "dh": b64(ct_dh), "key": b64(AESGCM(kek).encrypt(b"\0" * 12, dek, file_id))}


def unwrap(entry, identity, file_id):
    s, ct_dh = identity.suite, unb64(entry["dh"])
    kek = _combine(s, identity.kem.decapsulate(unb64(entry["kem"])), s.exchange(identity.dh, s.dh_load(ct_dh)), ct_dh, s.dh_bytes(identity.dh.public_key()))
    return AESGCM(kek).decrypt(b"\0" * 12, unb64(entry["key"]), file_id)


def _nonce(prefix, i, last):
    return prefix + struct.pack(">IB", i, 1 if last else 0)


def _core(h):
    """The parts of the header every chunk is bound to. The signer is one of them, so a signature cannot be stripped unnoticed."""
    return json.dumps({k: h.get(k) for k in ("v", "suite", "id", "chunk", "nonce", "name", "kind", "created", "signer")}, sort_keys=True).encode()


class Writer(io.RawIOBase):
    """A file-like object that encrypts whatever is written to it into `out`."""

    def __init__(self, out, recipients, name, kind="file", signer=None):
        if not recipients:
            raise VaultError("at least one recipient is needed")
        suites = {r.suite.name for r in recipients}
        if len(suites) > 1:
            raise VaultError("all recipients of one file must use the same suite (standard or CNSA 2.0)")
        self.out, self.dek, self.buf, self.i = out, AESGCM.generate_key(256), bytearray(), 0
        self.aes = None
        self.h = {"v": 1, "suite": suites.pop(), "id": b64(os.urandom(16)), "chunk": CHUNK, "nonce": b64(os.urandom(7)), "name": name,
                  "kind": kind, "created": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()}
        self.signer = signer
        if signer:
            self.h["signer"] = signer[1].public_bytes(ser.Encoding.PEM).decode()
        self.aad = hashlib.sha256(_core(self.h)).digest()
        self.h["recipients"] = [wrap(self.dek, r, self.aad) for r in recipients]
        header = json.dumps(self.h).encode()
        out.write(MAGIC + struct.pack(">I", len(header)) + header)
        self.digest = hashlib.sha512(self.aad)

    def writable(self):
        return True

    def write(self, data):
        self.buf += data
        while len(self.buf) > CHUNK:
            self._emit(bytes(self.buf[:CHUNK]), False)
            del self.buf[:CHUNK]
        return len(data)

    def _emit(self, chunk, last):
        self.aes = self.aes or AESGCM(self.dek)
        ct = self.aes.encrypt(_nonce(unb64(self.h["nonce"]), self.i, last), chunk, self.aad)
        self.out.write(struct.pack(">I", len(ct)) + ct)
        self.digest.update(ct)
        self.i += 1

    def close(self):
        if self.closed:
            return
        self._emit(bytes(self.buf), True)
        if self.signer:
            sig = self.signer[0].sign(self.digest.digest())
            self.out.write(SIG_MAGIC + struct.pack(">I", len(sig)) + sig)
        super().close()


def read_header(f):
    if f.read(len(MAGIC)) != MAGIC:
        raise VaultError("not a pqcsuite vault file")
    (n,) = struct.unpack(">I", f.read(4))
    if n > 1 << 24:
        raise VaultError("header too large")
    h = json.loads(f.read(n))
    if h.get("v") != 1 or h.get("suite") not in SUITES:
        raise VaultError(f"unsupported vault format {h.get('v')}/{h.get('suite')}")
    return h


def chunks(f, h, identity):
    """Decrypted chunks, in order; raises on any tampering. Afterwards h["_signature"] holds the trailer, if any."""
    aad = hashlib.sha256(_core(h)).digest()
    entry = next((r for r in h["recipients"] if r["id"] == identity.public.id), None)
    if not entry or h["suite"] != identity.suite.name:
        raise VaultError("this file was not encrypted for this key")
    try:
        aes = AESGCM(unwrap(entry, identity, aad))
    except Exception:
        raise VaultError("cannot unwrap the file key: wrong key or corrupted header") from None
    prefix, digest, i = unb64(h["nonce"]), hashlib.sha512(aad), 0
    while True:
        head = f.read(4)
        if len(head) < 4:
            raise VaultError("the file is truncated")
        (n,) = struct.unpack(">I", head)
        if n > CHUNK + 16:
            raise VaultError("corrupted chunk length")
        ct = f.read(n)
        digest.update(ct)
        for last in (False, True):
            try:
                pt = aes.decrypt(_nonce(prefix, i, last), ct, aad)
                break
            except Exception:
                pt = None
        if pt is None:
            raise VaultError(f"chunk {i} was modified, reordered or truncated")
        yield pt
        i += 1
        if last:
            break
    trailer = f.read(4)
    if trailer == SIG_MAGIC:
        (n,) = struct.unpack(">I", f.read(4))
        h["_signature"] = (f.read(n), digest.digest())
    elif trailer:
        raise VaultError("unexpected data after the last chunk")


def verify_signer(h, ca=None, crl=None, expected=None):
    """Check the signature and, with a CA, that the signer's certificate chains to it. Returns the signer's name."""
    if "signer" not in h:
        raise VaultError("the file is not signed")
    if "_signature" not in h:
        raise VaultError("the signature is missing")
    cert = x509.load_pem_x509_certificate(h["signer"].encode())
    sig, digest = h["_signature"]
    try:
        cert.public_key().verify(sig, digest)
    except Exception:
        raise VaultError("the signature does not verify: the file was altered or signed by someone else") from None
    if ca:
        cas = x509.load_pem_x509_certificates(Path(ca).read_bytes())
        if not any(c.subject == cert.issuer and signed_by(c, cert.tbs_certificate_bytes, cert.signature) for c in cas):
            raise VaultError("the signer's certificate was not issued by this CA") from None
        now = dt.datetime.now(dt.timezone.utc)
        if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
            raise VaultError("the signer's certificate has expired")
        if crl:
            try:
                check_revocation(cert.serial_number, Path(crl).read_bytes(), cas)
            except CAError as e:
                raise VaultError(f"signer: {e}") from None
    name = cert.subject.rfc4514_string()
    if expected and f"CN={expected}" not in name.split(","):
        raise VaultError(f"signed by {name}, expected CN={expected}")
    return name


def load_signer(cert_path, key_path, passphrase=None):
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    key = ser.load_pem_private_key(Path(key_path).read_bytes(), passphrase)
    if not isinstance(cert.public_key(), tuple(MLDSA_PUBLIC.values())) or key.public_key() != cert.public_key():
        raise VaultError("signing needs an ML-DSA certificate and its matching key")
    return key, cert


def encrypt(src, dst, recipients, signer=None):
    """Encrypt a file or a whole folder (as a tar stream) to `dst`. Returns bytes of plaintext read."""
    src, dst = Path(src), Path(dst)
    tmp = dst.with_name(dst.name + ".part")
    with open(tmp, "wb") as out:
        w = Writer(out, recipients, src.name, "dir" if src.is_dir() else "file", signer)
        if src.is_dir():
            with tarfile.open(fileobj=w, mode="w|") as tar:
                tar.add(src, arcname=src.name)
        else:
            with open(src, "rb") as f:
                while block := f.read(CHUNK):
                    w.write(block)
        w.close()
    os.replace(tmp, dst)


class _ChunkReader(io.RawIOBase):
    def __init__(self, gen):
        self.gen, self.buf = gen, b""

    def readable(self):
        return True

    def readinto(self, b):
        while not self.buf:
            try:
                self.buf = next(self.gen)
            except StopIteration:
                return 0
        n = min(len(b), len(self.buf))
        b[:n], self.buf = self.buf[:n], self.buf[n:]
        return n


def decrypt(src, dst_dir, identity, ca=None, crl=None, expected_signer=None, require_signature=False):
    """Decrypt into `dst_dir`. Nothing is left behind unless every chunk and, when required, the signature verify."""
    dst_dir = Path(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    with open(src, "rb") as f:
        h = read_header(f)
        name = Path(h["name"]).name
        staging = dst_dir / f".{name}.pqv-partial"
        try:
            gen = chunks(f, h, identity)
            if h["kind"] == "dir":
                staging.mkdir()
                with tarfile.open(fileobj=io.BufferedReader(_ChunkReader(gen)), mode="r|") as tar:
                    tar.extractall(staging, filter="data")
                for _ in gen:
                    pass
            else:
                with open(staging, "wb") as out:
                    for pt in gen:
                        out.write(pt)
            signer = None
            if "signer" in h or require_signature or expected_signer:
                signer = verify_signer(h, ca, crl, expected_signer)
            target = dst_dir / name
            if target.exists():
                raise VaultError(f"{target} already exists")
            if h["kind"] == "dir" and not (staging / name).is_dir():
                raise VaultError("the archive does not contain the folder it names")
            os.replace(staging / name if h["kind"] == "dir" else staging, target)
            _remove(staging)
            return target, signer
        except Exception:
            _remove(staging)
            raise


def _remove(p):
    if p.is_dir():
        shutil.rmtree(p, ignore_errors=True)
    elif p.exists():
        p.unlink()


def add_recipients(path, identity, recipients):
    """Grant access to more recipients by re-wrapping the file key; the encrypted data is copied unchanged."""
    path = Path(path)
    with open(path, "rb") as f:
        h = read_header(f)
        aad = hashlib.sha256(_core(h)).digest()
        entry = next((r for r in h["recipients"] if r["id"] == identity.public.id), None)
        if not entry:
            raise VaultError("you can only share a file you can open")
        dek = unwrap(entry, identity, aad)
        if any(r.suite.name != h["suite"] for r in recipients):
            raise VaultError(f"this file uses {h['suite']}; new recipients must have keys of that suite")
        have = {r["id"] for r in h["recipients"]}
        h["recipients"] += [wrap(dek, r, aad) for r in recipients if r.id not in have]
        header = json.dumps(h).encode()
        tmp = path.with_name(path.name + ".part")
        with open(tmp, "wb") as out:
            out.write(MAGIC + struct.pack(">I", len(header)) + header)
            while block := f.read(CHUNK):
                out.write(block)
    os.replace(tmp, path)
    return len(h["recipients"])


def inspect(path):
    with open(path, "rb") as f:
        h = read_header(f)
    signer = x509.load_pem_x509_certificate(h["signer"].encode()).subject.rfc4514_string() if "signer" in h else None
    return {"name": h["name"], "kind": h["kind"], "created": h["created"], "suite": h["suite"],
            "recipients": [r["id"] for r in h["recipients"]], "signed_by": signer, "size": os.path.getsize(path)}


def backup(src, dest_dir, recipients, signer=None, keep=None):
    """A timestamped encrypted archive of `src` in `dest_dir`; with `keep`, only the newest `keep` archives of it remain."""
    src, dest_dir = Path(src), Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = dest_dir / f"{src.name}-{stamp}.pqv"
    encrypt(src, target, recipients, signer)
    pruned = []
    if keep:
        for old in sorted(dest_dir.glob(f"{src.name}-*.pqv"))[:-keep]:
            old.unlink()
            pruned.append(old.name)
    return target, pruned
