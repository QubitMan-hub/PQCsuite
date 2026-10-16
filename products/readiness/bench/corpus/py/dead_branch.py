import hashlib

DEBUG_LEGACY = False


def digest(data):
    return hashlib.sha512(data).hexdigest()
    hashlib.sha1(data)


if False:
    hashlib.md5(b"old cache key")
