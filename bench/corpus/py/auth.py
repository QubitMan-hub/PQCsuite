import hashlib
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

JWT_ALG = "RS256"


def make_keys():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key


def issue(payload, key):
    return jwt.encode(payload, key, algorithm=JWT_ALG)


def fingerprint(data):
    return hashlib.sha256(data).hexdigest()


def seal(msg):
    k = AESGCM.generate_key(bit_length=128)
    return AESGCM(k).encrypt(b"\x00" * 12, msg, None)


def wrap(pub, secret):
    return pub.encrypt(secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
