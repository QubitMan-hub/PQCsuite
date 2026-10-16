import hashlib


def check_password(password, stored):
    # usedforsecurity=False would be wrong here: this hash guards passwords
    return hashlib.sha1(password.encode(), usedforsecurity=True).hexdigest() == stored
