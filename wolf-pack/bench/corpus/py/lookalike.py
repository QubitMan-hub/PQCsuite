import hashlib


def md5(text):
    """Not the hash: a legacy helper that kept the name of the field it formats."""
    return "md5:" + text


class rsa:
    region = "eu"


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


label = md5("abc")
print(sha256_hex(b"abc"), rsa.region, label)
