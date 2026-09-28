/* Constants that name their algorithm, used where the code chooses one. */
enum { KEY_RSA, KEY_DSA };

#ifdef OPENSSL_NO_RSA
#define NO_RSA_KEYS 1
#endif

int
kex_setup(struct kex *kex, struct sshkey *k)
{
	size_t n = SHA512_DIGEST_LENGTH;

	kex->kex[KEX_DH_GRP14_SHA256] = kex_gen_client;
	switch (k->type) {
	case KEY_ED25519:
		return sign_ed(k, n);
	}
	return -1;
}
