from cryptography.hazmat.primitives.asymmetric import ec, rsa


def rsa_key(exponent, modulus):
    return rsa.RSAPublicNumbers(exponent, modulus).public_key()


def ec_key(x, y):
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP384R1()).public_key()
