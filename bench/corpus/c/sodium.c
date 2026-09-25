#include <sodium.h>

static unsigned char peer_key[crypto_box_PUBLICKEYBYTES];

int sign_file(unsigned char *sig, const unsigned char *msg, unsigned long long len, const unsigned char *sk)
{
    unsigned char digest[crypto_generichash_BYTES];
    crypto_generichash(digest, sizeof digest, msg, len, NULL, 0);
    return crypto_sign_detached(sig, NULL, digest, sizeof digest, sk);
}

int derive(unsigned char *key, const char *password, const unsigned char *salt)
{
    return crypto_pwhash_scryptsalsa208sha256(key, 32, password, strlen(password), salt,
                                              crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE,
                                              crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE);
}

int seal(unsigned char *c, const unsigned char *m, unsigned long long len, const unsigned char *n, const unsigned char *k)
{
    return crypto_secretbox_easy(c, m, len, n, k);
}
