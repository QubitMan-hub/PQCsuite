from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def legacy_decrypt(key, data):
    d = Cipher(algorithms.TripleDES(key), modes.CBC(data[:8])).decryptor()
    return d.update(data[8:]) + d.finalize()
