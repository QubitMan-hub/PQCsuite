"""Quantum-safe file and backup encryption.

Each recipient's copy of the file key is wrapped with a hybrid KEM: X25519 and ML-KEM-768 combined as in X-Wing
(SHA3-256 over both shared secrets, the X25519 ciphertext and public key), so breaking it needs both broken. The data is
AES-256-GCM in 1 MiB chunks; every nonce carries the chunk number and a last-chunk flag, so truncation, reordering and
tampering are all detected. An optional ML-DSA signature from a CA-issued certificate says who made the file. The recipient
list is not bound into the chunks, so access can be granted later without re-encrypting the data.

File layout: b"PQV1\n", a 4-byte big-endian length and the JSON header; then each chunk as a 4-byte length and its
ciphertext; then, if signed, b"SIG1", a 4-byte length and an ML-DSA signature over a SHA-512 of the header's core fields
(all but the recipient list) and every chunk ciphertext. Header format 2 adds "mac", an HMAC-SHA256 of the recipient list
keyed from the file key, so recipients cannot be removed or altered unnoticed; the format number is in the core fields, so a
format 2 file cannot pass as format 1. Format 1 files still open.
"""
import base64
import datetime as dt
import hashlib
import hmac
import io
import logging
import json
import os
import re
import shutil
import struct
import tarfile
import tempfile
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ec, mlkem, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .pki import PUBLIC as MLDSA_PUBLIC, CAError, check_revocation, signed_by

MAGIC, SIG_MAGIC = b"PQV1\n", b"SIG1"
log = logging.getLogger("pqcsuite.vault")


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
        from .pki import write
        write(Path(path), pem, secret=True)

    @classmethod
    def load(cls, path, passphrase=None):
        data = Path(path).read_bytes()
        if b"PRIVATE KEY" not in data:
            raise VaultError(f"{path} is not a vault private key; use the .key file from 'vault keygen'")
        blocks = _pem_blocks(data)
        try:
            keys = [ser.load_pem_private_key(b, passphrase) for b in blocks]
        except (TypeError, ValueError) as e:
            # a wrong passphrase usually fails the padding check, but about one time in 256 the garbage it decrypts to fails to
            # parse instead; with a passphrase given for an encrypted key, both mean the passphrase is wrong (or the file damaged)
            wrong = "Incorrect password" in str(e) or (passphrase is not None and b"ENCRYPTED" in data)
            why = "wrong passphrase" if wrong else "it needs its passphrase" if "not given" in str(e) else e
            raise VaultError(f"cannot open {path}: {why}") from None
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
        try:
            keys = [ser.load_pem_public_key(b) for b in _pem_blocks(Path(path).read_bytes())]
        except ValueError:
            raise VaultError(f"{path} is not a vault recipient key; recipients are .pub files from 'vault keygen'") from None
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


def _recipients_mac(dek, recipients):
    """Binds the recipient list to the file key: whoever can open the file can tell that no entry was changed or removed,
    and sharing, which knows the key, can extend the list. The list itself stays outside the chunks' AAD for that reason."""
    return b64(hmac.new(hashlib.sha256(b"pqv recipients" + dek).digest(), json.dumps(recipients, sort_keys=True).encode(), "sha256").digest())


def _check_recipients(h, dek):
    if h["v"] >= 2 and not hmac.compare_digest(str(h.get("mac", "")).encode(), _recipients_mac(dek, h["recipients"]).encode()):
        raise VaultError("the list of recipients was modified")


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
        self.h = {"v": 2, "suite": suites.pop(), "id": b64(os.urandom(16)), "chunk": CHUNK, "nonce": b64(os.urandom(7)), "name": name,
                  "kind": kind, "created": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()}
        self.signer = signer
        if signer:
            self.h["signer"] = signer[1].public_bytes(ser.Encoding.PEM).decode()
        self.aad = hashlib.sha256(_core(self.h)).digest()
        self.h["recipients"] = [wrap(self.dek, r, self.aad) for r in recipients]
        self.h["mac"] = _recipients_mac(self.dek, self.h["recipients"])
        header = json.dumps(self.h).encode()
        out.write(MAGIC + struct.pack(">I", len(header)) + header)
        self.digest = hashlib.sha512(self.aad) if signer else None

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
        self.out.write(struct.pack(">I", len(ct)))
        self.out.write(ct)
        if self.digest:
            self.digest.update(ct)
        self.i += 1

    def finish(self):
        """Write the last chunk and the signature. Only a finished file decrypts; close() alone never finishes one."""
        self._emit(bytes(self.buf), True)
        if self.signer:
            sig = self.signer[0].sign(self.digest.digest())
            self.out.write(SIG_MAGIC + struct.pack(">I", len(sig)) + sig)
        self.close()


DAMAGED = "the header is damaged, or the file was cut short (an incomplete copy?)"


def read_header(f):
    if f.read(len(MAGIC)) != MAGIC:
        raise VaultError("not a pqcsuite vault file")
    head = f.read(4)
    if len(head) < 4:
        raise VaultError(DAMAGED)
    (n,) = struct.unpack(">I", head)
    if n > 1 << 24:
        raise VaultError("header too large")
    try:
        h = json.loads(f.read(n))
        fields = all(isinstance(h.get(k), str) for k in ("suite", "id", "nonce", "name", "kind", "created")) and isinstance(h.get("signer", ""), str)
        entries = isinstance(h.get("recipients"), list) and all(
            isinstance(r, dict) and all(isinstance(r.get(k), str) for k in ("id", "kem", "dh", "key")) for r in h["recipients"])
    except (ValueError, UnicodeDecodeError, AttributeError):
        fields = entries = False
    if not (fields and entries and isinstance(h.get("chunk"), int)):
        raise VaultError(DAMAGED)
    if h.get("v") not in (1, 2) or h.get("suite") not in SUITES:
        raise VaultError(f"unsupported vault format {h.get('v')}/{h.get('suite')}")
    try:
        unb64(h["nonce"]), unb64(h["id"])
    except ValueError:
        raise VaultError(DAMAGED) from None
    return h


def chunks(f, h, identity):
    """Decrypted chunks, in order; raises on any tampering. Afterwards h["_signature"] holds the trailer, if any."""
    aad = hashlib.sha256(_core(h)).digest()
    entry = next((r for r in h["recipients"] if r["id"] == identity.public.id), None)
    if not entry or h["suite"] != identity.suite.name:
        raise VaultError("this file was not encrypted for this key")
    try:
        dek = unwrap(entry, identity, aad)
    except Exception:
        raise VaultError("cannot unwrap the file key: wrong key or corrupted header") from None
    _check_recipients(h, dek)
    aes = AESGCM(dek)
    prefix, digest, i = unb64(h["nonce"]), hashlib.sha512(aad), 0
    while True:
        head = f.read(4)
        if len(head) < 4:
            raise VaultError("the file is truncated")
        (n,) = struct.unpack(">I", head)
        if n > CHUNK + 16:
            raise VaultError("corrupted chunk length")
        ct = f.read(n)
        if len(ct) != n:
            raise VaultError("the file is truncated")
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
        length = f.read(4)
        if len(length) != 4:
            raise VaultError("the signature was modified or truncated")
        (n,) = struct.unpack(">I", length)
        if not 0 < n <= 1 << 16:  # all ML-DSA signatures fit; never trust a four-byte allocation request
            raise VaultError("corrupted signature length")
        sig = f.read(n)
        if len(sig) != n or f.read(1):
            raise VaultError("the signature was modified or truncated")
        h["_signature"] = (sig, digest.digest())
    elif trailer:
        raise VaultError("unexpected data after the last chunk")


def _signer_cert(h):
    try:
        return x509.load_pem_x509_certificate(h["signer"].encode())
    except ValueError:
        raise VaultError("the signer's certificate in the header is damaged") from None


def verify_signer(h, ca=None, crl=None, expected=None):
    """Check the signature and, with a CA, that the signer's certificate chains to it. Returns the signer's name."""
    if "signer" not in h:
        raise VaultError("the file is not signed")
    if "_signature" not in h:
        raise VaultError("the signature is missing")
    cert = _signer_cert(h)
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
    if expected and expected not in [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]:
        raise VaultError(f"signed by {name}, expected CN={expected}")
    return name


def load_signer(cert_path, key_path, passphrase=None):
    cert = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    key = ser.load_pem_private_key(Path(key_path).read_bytes(), passphrase)
    if not isinstance(cert.public_key(), tuple(MLDSA_PUBLIC.values())) or key.public_key() != cert.public_key():
        raise VaultError("signing needs an ML-DSA certificate and its matching key")
    return key, cert


def encrypt(src, dst, recipients, signer=None):
    """Encrypt a file or a whole folder (as a tar stream) to `dst`, which appears only once complete and on disk."""
    src, dst = Path(src), Path(dst)
    if not dst.parent.is_dir():
        raise VaultError(f"cannot write {dst}: the folder {dst.parent} does not exist")
    fd, temporary = tempfile.mkstemp(prefix=f".{dst.name}.", suffix=".part", dir=dst.parent)
    tmp = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as out:
            w = Writer(out, recipients, src.name, "dir" if src.is_dir() else "file", signer)
            if src.is_dir():
                with tarfile.open(fileobj=w, mode="w|", format=tarfile.GNU_FORMAT) as tar:
                    tar.add(src, arcname=src.name, filter=_restorable)
            else:
                with open(src, "rb") as f:
                    while block := f.read(CHUNK):
                        w.write(block)
            w.finish()
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, dst)
    finally:
        if tmp.exists():
            tmp.unlink()


def _restorable(t):
    """Leave out what a safe restore would refuse (special files, links leaving the folder), so every backup restores."""
    top = t.name.split("/")[0]
    target = os.path.normpath(os.path.join(os.path.dirname(t.name), t.linkname)).replace(os.sep, "/") if t.issym() else top
    if t.ischr() or t.isblk() or t.isfifo() or os.path.isabs(t.linkname) or target.split("/")[0] != top:
        log.warning("vault: left out %s (%s)", t.name, "a link outside the folder" if t.issym() else "not a regular file")
        return None
    return t


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
    if dst_dir.exists() and not dst_dir.is_dir():
        raise VaultError(f"{dst_dir} is a file: give the folder to restore into (the archive's own file name is used inside it)")
    created = not dst_dir.exists()
    try:
        return _decrypt(src, dst_dir, identity, ca, crl, expected_signer, require_signature)
    except tarfile.TarError as e:
        raise VaultError(f"the archive cannot be restored safely: {e}") from None
    finally:
        if created and dst_dir.is_dir() and not any(dst_dir.iterdir()):
            dst_dir.rmdir()


def _decrypt(src, dst_dir, identity, ca, crl, expected_signer, require_signature):
    with open(src, "rb") as f:
        h = read_header(f)
        name = Path(h["name"]).name
        if name in ("", ".", "..") or "\0" in name:
            raise VaultError("the archive names no usable file name")
        dst_dir.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".pqv-partial-", dir=dst_dir))
        payload = staging / name
        try:
            gen = chunks(f, h, identity)
            if h["kind"] == "dir":
                with tarfile.open(fileobj=io.BufferedReader(_ChunkReader(gen)), mode="r|") as tar:
                    tar.extractall(staging, filter="data")
                for _ in gen:
                    pass
            else:
                fd = os.open(payload, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
                with os.fdopen(fd, "wb") as out:
                    for pt in gen:
                        out.write(pt)
            signer = None
            if "signer" in h or require_signature or expected_signer:
                signer = verify_signer(h, ca, crl, expected_signer)
            target = dst_dir / name
            if os.path.lexists(target):
                raise VaultError(f"{target} already exists")
            if h["kind"] == "dir" and (payload.is_symlink() or not payload.is_dir()):
                raise VaultError("the archive does not contain the folder it names")
            if h["kind"] == "dir":
                payload.chmod(0o700)
            os.replace(payload, target)
            _remove(staging)
            return target, signer
        except Exception:
            _remove(staging)
            raise


def verify(src, identity, ca=None, crl=None, expected_signer=None, require_signature=False):
    """A restore drill that restores nothing: every chunk decrypts and authenticates, a folder's archive would extract safely,
    and the signature (if there is one, or if required) verifies. Returns what a restore would produce."""
    with open(src, "rb") as f:
        h = read_header(f)
        gen = chunks(f, h, identity)
        files = size = 0
        if h["kind"] == "dir":
            try:
                with tarfile.open(fileobj=io.BufferedReader(_ChunkReader(gen)), mode="r|") as tar:
                    for m in tar:
                        tarfile.data_filter(m, os.path.abspath("restore"))
                        files, size = files + m.isfile(), size + m.size
            except tarfile.TarError as e:
                raise VaultError(f"the archive would not restore safely: {e}") from None
            for _ in gen:
                pass
        else:
            files, size = 1, sum(len(pt) for pt in gen)
        signer = verify_signer(h, ca, crl, expected_signer) if "signer" in h or require_signature or expected_signer else None
    return {"name": h["name"], "kind": h["kind"], "files": files, "bytes": size, "recipients": len(h["recipients"]), "signed_by": signer}


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
        try:
            dek = unwrap(entry, identity, aad)
        except Exception:
            raise VaultError("cannot unwrap the file key: wrong key or corrupted header") from None
        _check_recipients(h, dek)
        if any(r.suite.name != h["suite"] for r in recipients):
            raise VaultError(f"this file uses {h['suite']}; new recipients must have keys of that suite")
        have = {r["id"] for r in h["recipients"]}
        h["recipients"] += [wrap(dek, r, aad) for r in recipients if r.id not in have]
        if h["v"] >= 2:
            h["mac"] = _recipients_mac(dek, h["recipients"])
        header = json.dumps(h).encode()
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".part", dir=path.parent)
        tmp = Path(temporary)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(MAGIC + struct.pack(">I", len(header)) + header)
                while block := f.read(CHUNK):
                    out.write(block)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
    try:
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)
    return len(h["recipients"])


def inspect(path):
    with open(path, "rb") as f:
        h = read_header(f)
    signer = _signer_cert(h).subject.rfc4514_string() if "signer" in h else None
    return {"name": h["name"], "kind": h["kind"], "created": h["created"], "suite": h["suite"],
            "recipients": [r["id"] for r in h["recipients"]], "signed_by": signer, "size": os.path.getsize(path)}


def backup(src, dest_dir, recipients, signer=None, keep=None):
    """A timestamped encrypted archive of `src` in `dest_dir`; with `keep`, only the newest `keep` archives of it remain."""
    src, dest_dir = Path(src), Path(dest_dir)
    if keep is not None and keep < 1:
        raise VaultError(f"keep must be at least 1 (the newest archive), not {keep}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    target = dest_dir / f"{src.name}-{stamp}.pqv"
    encrypt(src, target, recipients, signer)
    pruned = []
    if keep:
        mine = re.compile(rf"{re.escape(src.name)}-\d{{8}}T\d{{12}}Z\.pqv")
        for old in sorted(p for p in dest_dir.glob("*.pqv") if mine.fullmatch(p.name))[:-keep]:
            old.unlink()
            pruned.append(old.name)
    return target, pruned
