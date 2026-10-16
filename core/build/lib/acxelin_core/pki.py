"""Certificate mechanisms shared by the products. Stage 2 adds the CA, CRLs, signers and EST here."""
from cryptography.hazmat.primitives.asymmetric import mldsa

PUBLIC = {"ML-DSA-44": mldsa.MLDSA44PublicKey, "ML-DSA-65": mldsa.MLDSA65PublicKey, "ML-DSA-87": mldsa.MLDSA87PublicKey}


def algorithm_of(public_key):
    """The ML-DSA parameter set of `public_key`, or None for any other key type."""
    return next((a for a, cls in PUBLIC.items() if isinstance(public_key, cls)), None)
