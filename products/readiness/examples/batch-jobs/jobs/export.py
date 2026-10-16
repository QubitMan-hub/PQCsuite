import hashlib

from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes


def encrypt_export(public_key: rsa.RSAPublicKey, data_key: bytes) -> bytes:
    return public_key.encrypt(data_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))


def manifest_digest(path):
    with open(path, "rb") as f:
        return hashlib.sha1(f.read()).hexdigest()
