/* A hand-written Blowfish, called by its own names: no library API to match. */
#include "cipher_api.h"

static unsigned int p_array[18];

void blowfish_key_setup(const unsigned char *key, int len)
{
	for (int i = 0; i < 18; i++)
		p_array[i] ^= key[i % len];
}

void blowfish_encrypt(const unsigned char in[], unsigned char out[])
{
	for (int i = 0; i < 8; i++)
		out[i] = in[i] ^ (unsigned char)p_array[i];
}

void seal(const unsigned char *key, const unsigned char in[], unsigned char out[])
{
	unsigned char des_addr[8];
	copy_des(des_addr, in);
	blowfish_key_setup(key, 16);
	blowfish_encrypt(des_addr, out);
}
