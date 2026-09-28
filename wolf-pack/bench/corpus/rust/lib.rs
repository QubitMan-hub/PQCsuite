use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use sha2::Sha256;

pub fn alg() -> &'static ring::signature::EcdsaSigningAlgorithm {
    &ECDSA_P256_SHA256_ASN1_SIGNING
}

pub fn h(d: &[u8]) -> Vec<u8> {
    let mut x = Sha256::new();
    x.update(d);
    x.finalize().to_vec()
}
