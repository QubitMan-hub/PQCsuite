import jwt


def issue(payload, key, alg):
    return jwt.encode(payload, key, alg)


def issue_ec(payload, key):
    return jwt.encode(payload, key, "ES256")
