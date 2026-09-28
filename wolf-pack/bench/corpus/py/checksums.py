import hashlib


def etag(body):
    return hashlib.md5(body, usedforsecurity=False).hexdigest()


def cache_key(parts):
    return hashlib.new("sha1", "|".join(parts).encode(), usedforsecurity=False).hexdigest()
