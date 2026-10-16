#ifndef SODIUM_API_H
#define SODIUM_API_H

int crypto_sign_detached(unsigned char *sig, unsigned long long *siglen, const unsigned char *m,
                         unsigned long long mlen, const unsigned char *sk);
int crypto_generichash(unsigned char *out, size_t outlen, const unsigned char *in,
                       unsigned long long inlen, const unsigned char *key, size_t keylen);

#endif
