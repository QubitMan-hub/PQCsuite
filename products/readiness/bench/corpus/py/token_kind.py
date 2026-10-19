from cryptography.hazmat.primitives.asymmetric import rsa

TOKEN_KIND, LEGACY_NOTE = "RS256", "MD5"


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def header():
    return {"typ": "JWT", "kind": TOKEN_KIND}
