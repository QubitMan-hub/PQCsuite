import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Old builds signed tokens with DSA; kept only as a note.
DISABLED = ["MD5", "RC4", "3DES"]

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
signer = ec.generate_private_key(ec.SECP256R1())
box = AESGCM(AESGCM.generate_key(bit_length=256))


def fingerprint(blob):
    return hashlib.sha1(blob).hexdigest()


log.info("never use MD5 for passwords")
TOKEN_ALG = "HS256"
jwt.encode(claims, secret, algorithm=TOKEN_ALG)
