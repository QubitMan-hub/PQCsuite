from cryptography.hazmat.primitives.asymmetric import ec

FORMATS = (
    b"ssh-ed25519",
    b"ssh-rsa",
    b"ecdsa-sha2-nistp256",
)


def new_signing_key():
    return ec.generate_private_key(ec.SECP256R1())


def looks_like_ssh_key(data: bytes) -> bool:
    return data.startswith(FORMATS)


def mentions_ssh_key(data: bytes) -> bool:
    return any(prefix in data for prefix in FORMATS)
