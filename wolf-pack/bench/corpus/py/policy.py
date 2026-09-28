WEAK_ALGORITHMS = [
    "md5",
    "sha1",
    "rc4",
]

SUPPORTED_CIPHERS = (
    "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-ctr",
)


def is_weak(name):
    return name.lower() in WEAK_ALGORITHMS


def supported(name):
    return name in SUPPORTED_CIPHERS
