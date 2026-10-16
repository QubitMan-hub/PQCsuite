import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def cache_key(data):
    return hashlib.md5(data).hexdigest()  # wolfpack:ignore (cache key, not security)


def keys():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048), AESGCM(AESGCM.generate_key(bit_length=256))
