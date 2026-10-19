import hashlib


def test_md5_compat():
    assert hashlib.md5(b"x").hexdigest()
