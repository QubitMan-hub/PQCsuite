import hashlib
from Crypto.Cipher import DES3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def etag(body):
    return hashlib.md5(body).hexdigest()


def old_encrypt(key, data):
    return DES3.new(key, DES3.MODE_CBC).encrypt(data)


def ecb(key, block):
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(block)
