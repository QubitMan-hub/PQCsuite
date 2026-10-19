"""Writes certs/roots.pem (a bundle of five self-signed roots) and certs/chain.pem (a five-certificate chain, not a trust store)."""
import datetime
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID


def cert(cn, key, issuer=None, issuer_key=None, ca=True):
    name = lambda n: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, n)])
    start = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name(cn)).issuer_name(name(issuer or cn)).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start + datetime.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(issuer_key or key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM)


out = Path(sys.argv[1] if len(sys.argv) > 1 else "bench/corpus/certs")
keys = [rsa.generate_private_key(65537, 2048) for _ in range(3)] + [ec.generate_private_key(ec.SECP256R1()) for _ in range(2)]
(out / "roots.pem").write_bytes(b"".join(cert(f"Example Root CA {i + 1}", k) for i, k in enumerate(keys)))
keys = [rsa.generate_private_key(65537, 2048) for _ in range(5)]
names = ["Example Chain Root", "Example Intermediate 1", "Example Intermediate 2", "Example Intermediate 3", "shop.example.com"]
chain = [cert(names[i], keys[i], names[i - 1] if i else None, keys[i - 1] if i else None, ca=i < 4) for i in range(5)]
(out / "chain.pem").write_bytes(b"".join(reversed(chain)))
