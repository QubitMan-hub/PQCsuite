#include <openssl/evp.h>
#include <openssl/rsa.h>

/* EVP_des_ede3_cbc() used to live here */

void digest(const unsigned char *d, size_t n, unsigned char *out) {
    EVP_Digest(d, n, out, NULL, EVP_md5(), NULL);
}

RSA *gen(void) {
    RSA *r = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(r, 2048, e, NULL);
    return r;
}

const EVP_CIPHER *cipher(void) {
    return EVP_aes_128_cbc();
}
