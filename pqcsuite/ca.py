"""A post-quantum certificate authority: ML-DSA root, server and client certificates, revocation and CRLs."""
import contextlib
import datetime as dt
import ipaddress
import json
import os
import threading
from dataclasses import dataclass, asdict
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ALGORITHMS = {"ML-DSA-44": mldsa.MLDSA44PrivateKey, "ML-DSA-65": mldsa.MLDSA65PrivateKey, "ML-DSA-87": mldsa.MLDSA87PrivateKey}
PUBLIC = {"ML-DSA-44": mldsa.MLDSA44PublicKey, "ML-DSA-65": mldsa.MLDSA65PublicKey, "ML-DSA-87": mldsa.MLDSA87PublicKey}
USAGE = {"server": [ExtendedKeyUsageOID.SERVER_AUTH], "client": [ExtendedKeyUsageOID.CLIENT_AUTH],
         "site": [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]}
REASONS = {r.value: r for r in x509.ReasonFlags if r not in (x509.ReasonFlags.unspecified, x509.ReasonFlags.remove_from_crl)}


class CAError(Exception):
    pass


_THREAD_LOCKS = {}


@contextlib.contextmanager
def locked(root):
    """Serialise changes to one CA across threads and processes (the CLI, the console and the enrollment server may share it)."""
    tl = _THREAD_LOCKS.setdefault(str(Path(root).resolve()), threading.RLock())
    with tl, open(Path(root) / ".lock", "a+b") as f:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


@dataclass
class Record:
    serial: str
    common_name: str
    kind: str
    algorithm: str
    not_after: str
    names: list
    status: str = "valid"
    revoked_at: str = ""
    reason: str = ""
    path: str = ""


def now():
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0)


def generate(algorithm):
    if algorithm not in ALGORITHMS:
        raise CAError(f"unknown algorithm {algorithm}; choose from {', '.join(ALGORITHMS)}")
    return ALGORITHMS[algorithm].generate()


def algorithm_of(public_key):
    return next((a for a, cls in PUBLIC.items() if isinstance(public_key, cls)), None)


def key_pem(key, passphrase=None):
    enc = serialization.BestAvailableEncryption(passphrase) if passphrase else serialization.NoEncryption()
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)


def cert_pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def write(path, data, secret=False):
    """Write atomically; secret files are created owner-only."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600 if secret else 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def general_names(names):
    out = []
    for n in names:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            out.append(x509.DNSName(n))
    return out


class CA:
    def __init__(self, root, passphrase=None):
        self.root = Path(root)
        if not (self.root / "ca.crt").exists():
            raise CAError(f"no CA at {self.root}; run 'pqcsuite ca init' first")
        self.cert = x509.load_pem_x509_certificate((self.root / "ca.crt").read_bytes())
        try:
            self.key = serialization.load_pem_private_key((self.root / "ca.key").read_bytes(), passphrase)
        except (TypeError, ValueError) as e:
            raise CAError(f"cannot open the CA key: {e}") from None

    @classmethod
    def init(cls, root, name, algorithm="ML-DSA-87", days=3650, passphrase=None):
        root = Path(root)
        if (root / "ca.crt").exists():
            raise CAError(f"a CA already exists at {root}")
        key = generate(algorithm)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now()).not_valid_after(now() + dt.timedelta(days=days))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
                .add_extension(ski, critical=False)
                .sign(key, None))
        write(root / "ca.key", key_pem(key, passphrase), secret=True)
        write(root / "ca.crt", cert_pem(cert))
        write(root / "index.json", b"[]")
        return cls(root, passphrase)

    def records(self):
        return [Record(**r) for r in json.loads((self.root / "index.json").read_text(encoding="utf-8"))]

    def _save(self, records):
        write(self.root / "index.json", json.dumps([asdict(r) for r in records], indent=1).encode())

    def find(self, serial):
        serial = serial.lower()
        match = [r for r in self.records() if r.serial == serial or r.serial.startswith(serial)]
        if len(match) != 1:
            raise CAError(f"{'no' if not match else 'more than one'} certificate matches serial {serial}")
        return match[0]

    def sign(self, public_key, common_name, kind, names=(), days=397):
        """Issue a leaf certificate for any ML-DSA public key."""
        if kind not in USAGE:
            raise CAError(f"kind must be one of {', '.join(USAGE)}")
        algorithm = algorithm_of(public_key)
        if not algorithm:
            raise CAError("only ML-DSA keys can be certified")
        names = list(names) or ([common_name] if kind != "client" else [])
        not_after = min(now() + dt.timedelta(days=days), self.cert.not_valid_after_utc)
        b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
             .issuer_name(self.cert.subject).public_key(public_key).serial_number(x509.random_serial_number())
             .not_valid_before(now()).not_valid_after(not_after)
             .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
             .add_extension(x509.ExtendedKeyUsage(USAGE[kind]), critical=False)
             .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
             .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False))
        if names:
            b = b.add_extension(x509.SubjectAlternativeName(general_names(names)), critical=False)
        cert = b.sign(self.key, None)
        with locked(self.root):
            rec = self._record(cert, common_name, kind, algorithm, not_after, names)
        return cert, rec

    def _record(self, cert, common_name, kind, algorithm, not_after, names):
        rec = Record(serial=format(cert.serial_number, "x"), common_name=common_name, kind=kind,
                     algorithm=algorithm, not_after=not_after.isoformat(), names=names)
        self._save(self.records() + [rec])
        return rec

    def issue(self, common_name, kind, names=(), days=397, algorithm="ML-DSA-65", out=None, passphrase=None):
        """Generate a key pair and certificate; writes cert.pem, key.pem and chain.pem to `out`."""
        key = generate(algorithm)
        names = list(dict.fromkeys(([common_name] if kind != "client" else []) + list(names)))
        cert, rec = self.sign(key.public_key(), common_name, kind, names, days)
        out = Path(out or self.root / "issued" / f"{common_name}-{rec.serial[:8]}")
        write(out / "key.pem", key_pem(key, passphrase), secret=True)
        write(out / "cert.pem", cert_pem(cert))
        write(out / "chain.pem", cert_pem(cert) + cert_pem(self.cert))
        rec.path = str(out.resolve())
        with locked(self.root):
            self._save([rec if r.serial == rec.serial else r for r in self.records()])
        return out, rec

    def sign_csr(self, csr_pem, kind, days=397):
        csr = x509.load_pem_x509_csr(csr_pem)
        if not csr.is_signature_valid:
            raise CAError("the CSR's signature does not verify")
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = san.get_values_for_type(x509.DNSName) + [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
        except x509.ExtensionNotFound:
            names = []
        return self.sign(csr.public_key(), cn[0].value if cn else "unnamed", kind, names, days)

    def revoke(self, serial, reason="unspecified"):
        if reason != "unspecified" and reason not in REASONS:
            raise CAError(f"reason must be one of: unspecified, {', '.join(REASONS)}")
        with locked(self.root):
            self._revoke(serial, reason)
        return self.crl()

    def _revoke(self, serial, reason):
        recs = self.records()
        rec = self.find(serial)
        for r in recs:
            if r.serial == rec.serial:
                if r.status == "revoked":
                    raise CAError(f"{r.serial} is already revoked")
                r.status, r.revoked_at, r.reason = "revoked", now().isoformat(), reason
        self._save(recs)

    def crl(self, days=7):
        """Sign and write a fresh CRL listing every revoked certificate."""
        b = x509.CertificateRevocationListBuilder().issuer_name(self.cert.subject).last_update(now()).next_update(now() + dt.timedelta(days=days))
        for r in self.records():
            if r.status == "revoked":
                rb = x509.RevokedCertificateBuilder().serial_number(int(r.serial, 16)).revocation_date(dt.datetime.fromisoformat(r.revoked_at))
                if r.reason in REASONS:
                    rb = rb.add_extension(x509.CRLReason(REASONS[r.reason]), critical=False)
                b = b.add_revoked_certificate(rb.build())
        crl = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False).sign(self.key, None)
        data = crl.public_bytes(serialization.Encoding.PEM)
        write(self.root / "crl.pem", data)
        return data

    def renew(self, serial, days=397, algorithm="ML-DSA-65", out=None, passphrase=None):
        """A new key and certificate with the same name and SANs; the old one stays valid until it expires or is revoked."""
        r = self.find(serial)
        return self.issue(r.common_name, r.kind, r.names, days, algorithm, out, passphrase)

    def maintain(self, renew_within=30, crl_days=7, algorithm="ML-DSA-65"):
        """Re-sign the CRL, and renew certificates expiring within `renew_within` days into the folder they were issued to, where
        edges and VPN gateways pick them up without a restart. Run it daily. Encrypted leaf keys are reported, not renewed."""
        newest = {}
        for r in self.records():
            if r.status == "valid" and r.path and (r.path not in newest or r.not_after > newest[r.path].not_after):
                newest[r.path] = r
        cutoff, renewed, skipped = now() + dt.timedelta(days=renew_within), [], []
        for r in newest.values():
            if dt.datetime.fromisoformat(r.not_after) > cutoff:
                continue
            key = Path(r.path) / "key.pem"
            if not key.exists() or b"ENCRYPTED" in key.read_bytes()[:64]:
                skipped.append(r)
                continue
            renewed.append(self.renew(r.serial, algorithm=algorithm, out=r.path)[1])
        self.crl(crl_days)
        return renewed, skipped

    def expiring(self, within_days=30):
        cutoff = now() + dt.timedelta(days=within_days)
        return [r for r in self.records() if r.status == "valid" and dt.datetime.fromisoformat(r.not_after) <= cutoff]


def check_revocation(serial, crl_pem, ca_cert):
    """Raise if the certificate with this serial number is revoked, or if the CRL is forged or stale. Fails closed."""
    crl = x509.load_pem_x509_crl(crl_pem)
    if crl.issuer != ca_cert.subject or not crl.is_signature_valid(ca_cert.public_key()):
        raise CAError("the CRL was not signed by this CA")
    if crl.next_update_utc and crl.next_update_utc < now():
        raise CAError(f"the CRL expired at {crl.next_update_utc.isoformat()}")
    r = crl.get_revoked_certificate_by_serial_number(serial)
    if r is not None:
        raise CAError(f"certificate {serial:x} was revoked on {r.revocation_date_utc.date()}")
