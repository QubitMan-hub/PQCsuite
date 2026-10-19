import hashlib


def etag(body):
    return hashlib.md5(body, usedforsecurity=False).hexdigest()


def cache_key(parts):
    return hashlib.new("sha1", "|".join(parts).encode(), usedforsecurity=False).hexdigest()


def unsafe_password(password):
    return hashlib.md5(password).hexdigest()


class MD5PasswordHasher:
    def encode(self, password):
        return hashlib.md5(password).hexdigest()
