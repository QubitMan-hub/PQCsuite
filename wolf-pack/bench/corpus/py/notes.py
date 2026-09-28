"""Legacy notes: this module used RSA and SHA1 years ago."""
import logging

log = logging.getLogger(__name__)

# TODO: we used MD5 here before, now removed
CONFIG = {"name": "payments", "region": "eu"}


def warn():
    log.warning("SHA1 and RC4 are deprecated, please upgrade your client")
    return "ok"
