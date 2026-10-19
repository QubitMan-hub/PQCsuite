import hashlib

from .settings import DIGEST, CONFIG, KEY_BITS
from .primitives import make_key, fingerprint


class Signer:
    ALGO = "sha224"

    def __init__(self, bits=KEY_BITS):
        self.key = make_key(bits)

    def tag(self, data):
        return hashlib.new(self.ALGO, data).digest()

    def checksum(self, data, name=DIGEST):
        return hashlib.new(name, data).hexdigest()


def main():
    return fingerprint(b"payload", CONFIG["hash"])
