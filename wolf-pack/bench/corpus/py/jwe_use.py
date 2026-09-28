import hashlib
import hmac

from jwcrypto import jwe
from jwcrypto.common import json_encode

PROTOCOL = b"Noise_XX_25519_AESGCM_SHA256"


def seal(key, payload):
    header = {"alg": "RSA-OAEP-256", "enc": "A256GCM"}
    token = jwe.JWE(payload, json_encode(header))
    token.add_recipient(key)
    return token.serialize()


def tag(secret, message, digest=hashlib.sha512):
    if digest in (hashlib.md5,):
        raise ValueError("too weak")
    return hmac.new(secret, message, digest).hexdigest()


def handshake(connection_factory):
    return connection_factory.from_name(PROTOCOL)
