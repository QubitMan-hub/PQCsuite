import oqs


def kem_roundtrip():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        pk = kem.generate_keypair()
        ct, ss = kem.encap_secret(pk)
    return ct, ss


def sign(msg):
    with oqs.Signature("ML-DSA-65") as s:
        s.generate_keypair()
        return s.sign(msg)
