from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def sign(payload: bytes) -> bytes:
    return KEY.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())


def wrap(session_key: bytes) -> bytes:
    return KEY.public_key().encrypt(session_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
