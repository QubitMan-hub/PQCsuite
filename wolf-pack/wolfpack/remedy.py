"""How to fix each finding where it was found: the replacement in that language, library or configuration, and which PQC Suite
product can do the job. Versions named here are the first releases that ship the feature."""
from .elders import CATALOG, LEGACY, SHOR, GROVER, classical_bits

KEX = {
    "java": "JDK 24+: ML-KEM through `KEM.getInstance(\"ML-KEM\")` and `KeyPairGenerator.getInstance(\"ML-KEM-768\")`; on older JDKs, BouncyCastle's ML-KEM",
    "go": "Go 1.24+: `crypto/mlkem` (`mlkem.GenerateKey768()`); `crypto/tls` already offers X25519MLKEM768 by default",
    "python": "liboqs-python: `oqs.KeyEncapsulation(\"ML-KEM-768\")`, combined with X25519 in a hybrid",
    "js": "`@noble/post-quantum` (`ml_kem768`), or Node.js built with OpenSSL 3.5+",
    "c": "OpenSSL 3.5+: `EVP_PKEY_CTX_new_from_name(NULL, \"ML-KEM-768\", NULL)`, or the X25519MLKEM768 group for TLS",
    "csharp": ".NET 10: `MLKem.GenerateKey(MLKemAlgorithm.MLKem768)`",
    "rust": "the `ml-kem` crate (RustCrypto), or rustls with aws-lc-rs, which offers X25519MLKEM768",
}
SIG = {
    "java": "JDK 24+: `KeyPairGenerator.getInstance(\"ML-DSA-65\")` and `Signature.getInstance(\"ML-DSA\")`; on older JDKs, BouncyCastle's ML-DSA",
    "go": "Cloudflare CIRCL `sign/mldsa/mldsa65` (Go's standard library has no ML-DSA yet)",
    "python": "liboqs-python: `oqs.Signature(\"ML-DSA-65\")`",
    "js": "`@noble/post-quantum` (`ml_dsa65`)",
    "c": "OpenSSL 3.5+: `EVP_PKEY_Q_keygen(NULL, NULL, \"ML-DSA-65\")`, or `openssl genpkey -algorithm ML-DSA-65`",
    "csharp": ".NET 10: `MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa65)`",
    "rust": "the `ml-dsa` crate (RustCrypto)",
}
HASH = {"java": "`MessageDigest.getInstance(\"SHA-256\")`", "go": "`crypto/sha256`", "python": "`hashlib.sha256()`",
        "js": "`crypto.createHash(\"sha256\")`", "c": "`EVP_sha256()`", "csharp": "`SHA256.HashData(...)`", "rust": "`sha2::Sha256`"}
AEAD = {"java": "`Cipher.getInstance(\"AES/GCM/NoPadding\")` with a 256-bit key", "go": "`cipher.NewGCM(aes.NewCipher(key32))`",
        "python": "`AESGCM(AESGCM.generate_key(bit_length=256))` from pyca/cryptography", "js": "`crypto.createCipheriv(\"aes-256-gcm\", key, iv)`",
        "c": "`EVP_aes_256_gcm()`", "csharp": "`new AesGcm(key32, tagSizeInBytes: 16)`", "rust": "`aes_gcm::Aes256Gcm`"}
PROTO = {"java": "`sslSocket.setEnabledProtocols(new String[] {\"TLSv1.3\", \"TLSv1.2\"})`", "go": "`tls.Config{MinVersion: tls.VersionTLS12}`",
         "python": "`ctx.minimum_version = ssl.TLSVersion.TLSv1_2`", "js": "`minVersion: \"TLSv1.2\"`",
         "c": "`SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)`", "csharp": "`SslProtocols.Tls12 | SslProtocols.Tls13`",
         "rust": "rustls (TLS 1.2 and 1.3 only)"}
CONFIG = {
    "nginx": {"kex": "`ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` (nginx built with OpenSSL 3.5+)",
              "proto": "`ssl_protocols TLSv1.2 TLSv1.3;`"},
    "apache": {"kex": "`SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519` (OpenSSL 3.5+)", "proto": "`SSLProtocol -all +TLSv1.2 +TLSv1.3`"},
    "haproxy": {"kex": "`ssl-default-bind-curves X25519MLKEM768:X25519` (OpenSSL 3.5+)", "proto": "`ssl-min-ver TLSv1.2`"},
    "sshd": {"kex": "`KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256` (OpenSSH 9.9+; the default from 10.0)",
             "proto": ""},
    "cloud": {"kex": "a load-balancer TLS policy with hybrid PQ key exchange, where the provider offers one", "proto": "a TLS 1.2+ policy, preferably TLS 1.3"},
}
SUITE = {"kex": "PQC Suite TLS 1.3 + mTLS: put `pqcsuite tls edge` in front of the service for hybrid ML-KEM without changing it",
         "sig": "PQC Suite CA: issue ML-DSA or hybrid certificates (`pqcsuite ca issue`)",
         "data": "PQC Suite Vault: re-encrypt stored data and backups with ML-KEM + AES-256-GCM (`pqcsuite vault`)",
         "tunnel": "PQC Suite IPsec VPN: hybrid ML-KEM site-to-site tunnels (`pqcsuite vpn`)"}


def contexts(a):
    """Where an asset was seen: languages of code, kinds of configuration, live endpoints, key material."""
    out = set()
    for s in a.sightings:
        f = s.file.lower()
        if s.evidence == "live" or f.startswith(("tls://", "ssh://", "pcap://")):
            out.add("live-ssh" if s.lang == "ssh" or f.startswith("ssh://") else "live-tls")
        elif s.evidence == "artifact":
            out.add("certificate")
        elif s.evidence == "config":
            name = f.rsplit("/", 1)[-1]
            out.add("sshd" if "ssh" in name else "haproxy" if "haproxy" in name else "apache" if "httpd" in name or "apache" in name
                    else "cloud" if name.endswith((".tf", ".hcl")) else "nginx" if "nginx" in name or name.endswith(".conf") else "config")
        elif s.lang in KEX:
            out.add(s.lang)
    return out


def kind(a):
    c = CATALOG[a.algo]
    bits = classical_bits(a.algo, a.params)
    if a.params.get("mode") == "ECB":
        return "ecb"
    if c.primitive == "protocol":
        return "proto" if c.threat == LEGACY else "kex" if c.threat == SHOR else None
    if c.threat == LEGACY or bits is not None and bits < 112:
        return "legacy-hash" if c.primitive in ("hash", "mac") else "legacy-cipher" if c.primitive in ("block-cipher", "stream-cipher", "ae") else "weak-key"
    if c.threat == SHOR:
        return "sig" if c.primitive == "signature" else "kex" if c.primitive in ("key-agree", "kem") else "pke"
    if c.threat == GROVER and a.algo == "AES":
        return "aes"
    return None


def remedies(a):
    """[(where, fix)] for one asset; empty when nothing needs doing."""
    k = kind(a)
    if not k:
        return []
    where, out = contexts(a), []
    code = sorted(w for w in where if w in KEX)
    for lang in code:
        if k in ("kex", "pke"):
            out.append((lang, KEX[lang]))
        if k in ("sig", "pke", "weak-key"):
            out.append((lang, SIG[lang]))
        if k == "legacy-hash":
            out.append((lang, f"use SHA-256 or stronger: {HASH[lang]}"))
        if k in ("legacy-cipher", "ecb", "aes"):
            out.append((lang, f"use AES-256-GCM: {AEAD[lang]}"))
        if k == "proto":
            out.append((lang, f"require TLS 1.2 or newer: {PROTO[lang]}"))
    for cfg in sorted(w for w in where if w in CONFIG):
        key = "proto" if k == "proto" else "kex" if k in ("kex", "pke", "weak-key") else None
        if key and CONFIG[cfg][key]:
            out.append((cfg, CONFIG[cfg][key]))
        if k in ("legacy-cipher", "legacy-hash") and cfg != "sshd":
            out.append((cfg, f"remove {a.variant} from the cipher list; keep AES-GCM and ChaCha20-Poly1305 suites"))
    if "live-tls" in where and k in ("kex", "pke", "proto", "weak-key"):
        out.append(("live endpoint", "enable X25519MLKEM768 on the server (OpenSSL 3.5+, Go 1.24+, rustls with aws-lc-rs) and turn off TLS below 1.2"))
    if "live-ssh" in where and k in ("kex", "pke"):
        out.append(("live endpoint", CONFIG["sshd"]["kex"]))
    if "certificate" in where and k in ("sig", "pke", "weak-key", "legacy-hash"):
        out.append(("certificate", "reissue from a CA that signs with ML-DSA (or a hybrid chain during the transition)"))
    if k == "legacy-hash":
        return out
    product = "sig" if k in ("sig", "weak-key") or "certificate" in where else "kex" if k in ("kex", "proto") or where & {"live-tls", "nginx", "apache", "haproxy", "cloud"} \
        else "tunnel" if "live-ssh" in where or "sshd" in where else "data" if k in ("pke", "legacy-cipher", "ecb", "aes") else "kex"
    out.append(("PQC Suite", SUITE[product]))
    return out
