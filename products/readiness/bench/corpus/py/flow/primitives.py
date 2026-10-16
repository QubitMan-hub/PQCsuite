import hashlib

from cryptography.hazmat.primitives.asymmetric import rsa


def make_key(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def fingerprint(data, algo):
    return hashlib.new(algo, data).hexdigest()
