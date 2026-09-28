/* Prototypes only: a header that declares ciphers is not code that uses them. */
#ifndef CIPHER_API_H
#define CIPHER_API_H

void aes_encrypt(const unsigned char in[], unsigned char out[], const unsigned int key[], int keysize);
void aes_decrypt(const unsigned char in[], unsigned char out[], const unsigned int key[], int keysize);
extern int rsa_sign(const unsigned char *msg, int len);
void copy_des(unsigned char *dst, const unsigned char *src);

#endif
