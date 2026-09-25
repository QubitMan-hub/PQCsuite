import hashlib


def cache_key(s):
    return hashlib.md5(s).hexdigest()  # wolfpack:ignore non-security cache key
