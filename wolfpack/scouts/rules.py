import re

from ..elders import lookup, pq_from_text, curve, parse_transformation, parse_symmetric_name
from .suites import sig_scheme, cipher_string

Q = r"""['"`]"""
RULES = {}


def rule(langs, pattern, flags=0):
    rx = re.compile(pattern, flags)

    def deco(fn):
        for l in langs.split():
            RULES.setdefault(l, []).append((rx, fn))
        return fn
    return deco


def lit(s):
    return [(lookup(s) or pq_from_text(s), {})]


# JVM
@rule("java", r'Cipher\.getInstance\(\s*"([^"]+)"')
def _(m, x):
    a, p = parse_transformation(m.group(1))
    return [(a, p)]


@rule("java", r'\b(KeyPairGenerator|KeyGenerator|KeyAgreement|KeyFactory|MessageDigest|Mac|SecretKeyFactory|KEM)\.getInstance\(\s*"([^"]+)"')
def _(m, x):
    kind, s = m.group(1), m.group(2)
    if kind == "Mac":
        h = re.match(r"Hmac(\w+)", s, re.I)
        return [("HMAC", {"hash": lookup(h.group(1)) if h else None})]
    if kind == "SecretKeyFactory" and s.upper().startswith("PBKDF2"):
        h = re.search(r"Hmac(\w+)", s, re.I)
        return [("PBKDF2", {"hash": lookup(h.group(1)) if h else None})]
    if kind == "KeyGenerator" and s.lower().startswith("hmac"):
        return [("HMAC", {"hash": lookup(s[4:])})]
    a = lookup(s) or pq_from_text(s) or parse_transformation(s)[0]
    if kind == "KeyAgreement" and a == "ECC":
        a = "ECDH"
    return [(a, {})]


@rule("java", r'\bSignature\.getInstance\(\s*"([^"]+)"')
def _(m, x):
    return sig_scheme(m.group(1))


@rule("java", r'\.initialize\(\s*(\d{3,5})\b')
def _(m, x):
    x.attach({"key_size": int(m.group(1))}, ("RSA", "DSA", "DH", "ECC"))


@rule("java", r'\.init\(\s*(128|192|256)\s*[,)]')
def _(m, x):
    x.attach({"key_size": int(m.group(1))}, ("AES",))


@rule("java", r'new\s+ECGenParameterSpec\(\s*"([^"]+)"')
def _(m, x):
    x.attach({"curve": curve(m.group(1))}, ("ECC", "ECDSA", "ECDH"))


@rule("java", r'new\s+SecretKeySpec\([^;]*?,\s*"([^"]+)"\s*\)')
def _(m, x):
    return [parse_transformation(m.group(1))]


@rule("java", r'SSLContext\.getInstance\(\s*"([^"]+)"')
def _(m, x):
    return lit(m.group(1)) if m.group(1).upper() not in ("TLS", "SSL", "DEFAULT") else []


@rule("java", r'setEnabledProtocols\((.*)\)')
def _(m, x):
    return [(lookup(v), {}) for v in re.findall(r'"(TLSv1(?:\.\d)?|SSLv3)"', m.group(1))]


BC = {"RSAKeyPairGenerator": "RSA", "RSAEngine": "RSA", "RSADigestSigner": "RSA", "ECKeyPairGenerator": "ECC", "ECDSASigner": "ECDSA",
      "ECDHBasicAgreement": "ECDH", "AESEngine": "AES", "AESFastEngine": "AES", "DESedeEngine": "3DES", "DESEngine": "DES", "RC4Engine": "RC4",
      "BlowfishEngine": "Blowfish", "MD5Digest": "MD5", "SHA1Digest": "SHA-1", "SHA256Digest": "SHA-256", "SHA512Digest": "SHA-512",
      "Ed25519Signer": "Ed25519", "X25519Agreement": "X25519", "DSASigner": "DSA", "DHBasicAgreement": "DH"}


@rule("java", r'new\s+(\w+(?:Engine|Digest|Signer|Agreement|KeyPairGenerator|KEMGenerator|KEMExtractor))\s*\(')
def _(m, x):
    c = m.group(1)
    return [(BC.get(c) or pq_from_text(c), {"lib": "org.bouncycastle"})]


# Go
@rule("go", r'\b(md5|sha1|sha256|sha512|sha3)\.(New\w*|Sum\w*)\(')
def _(m, x):
    pkg, fn = m.group(1), m.group(2)
    size = re.search(r"(224|256|384|512)", fn)
    name = {"md5": "MD5", "sha1": "SHA-1"}.get(pkg) or (f"SHA3-{size.group(1)}" if pkg == "sha3" and size else f"SHA-{size.group(1) if size else pkg[3:]}")
    return [(lookup(name) or name, {})]


@rule("go", r'\brsa\.GenerateKey\(\s*[^,]+,\s*(\d+)')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1))})]


@rule("go", r'\brsa\.(SignPKCS1v15|SignPSS|EncryptOAEP|EncryptPKCS1v15|DecryptOAEP|DecryptPKCS1v15|VerifyPKCS1v15|VerifyPSS)\(')
def _(m, x):
    f = m.group(1)
    return [("RSA", {"padding": "oaep" if "OAEP" in f else "pss" if "PSS" in f else "pkcs1v15"})]


@rule("go", r'\becdsa\.GenerateKey\(\s*elliptic\.(P\d+)\(\)')
def _(m, x):
    return [("ECDSA", {"curve": curve(m.group(1))})]


@rule("go", r'\becdsa\.(Sign\w*|Verify\w*)\(')
def _(m, x):
    return [("ECDSA", {})]


@rule("go", r'\becdh\.(P256|P384|P521|X25519)\(\)')
def _(m, x):
    return [("X25519", {})] if m.group(1) == "X25519" else [("ECDH", {"curve": curve(m.group(1))})]


@rule("go", r'\bed25519\.(GenerateKey|Sign|Verify|NewKeyFromSeed|PublicKey|PrivateKey)\b')
def _(m, x):
    return [("Ed25519", {})]


@rule("go", r'\bcurve25519\.(X25519|ScalarMult|ScalarBaseMult)\(')
def _(m, x):
    return [("X25519", {})]


@rule("go", r'\baes\.NewCipher\(')
def _(m, x):
    return [("AES", {})]


@rule("go", r'\bcipher\.New(GCM|CBCEncrypter|CBCDecrypter|CTR|CFBEncrypter|CFBDecrypter|OFB)\w*\(')
def _(m, x):
    x.attach({"mode": m.group(1)[:3].upper() if m.group(1) != "OFB" else "OFB"}, ("AES", "3DES", "DES"), window=12)


@rule("go", r'\bdes\.(NewTripleDESCipher|NewCipher)\(')
def _(m, x):
    return [("3DES" if "Triple" in m.group(1) else "DES", {})]


@rule("go", r'\brc4\.NewCipher\(')
def _(m, x):
    return [("RC4", {})]


@rule("go", r'\bchacha20poly1305\.New\w*\(')
def _(m, x):
    return [("ChaCha20-Poly1305", {})]


@rule("go", r'\btls\.(VersionTLS1[0-3]|VersionSSL30|X25519MLKEM768|X25519|CurveP256|CurveP384|CurveP521)\b')
def _(m, x):
    t = m.group(1)
    if t.startswith("Curve"):
        return [("ECDH", {"curve": curve(t[5:])})]
    return lit("SSLv3" if t == "VersionSSL30" else t)


@rule("go", r'\bmlkem\.(GenerateKey|NewDecapsulationKey|NewEncapsulationKey)(768|1024)\(')
def _(m, x):
    return [(f"ML-KEM-{m.group(2)}", {})]


@rule("go", r'\bhmac\.New\(\s*(sha1|sha256|sha512|md5)\.New')
def _(m, x):
    return [("HMAC", {"hash": lookup(m.group(1))})]


@rule("go", r'\b(scrypt\.Key|hkdf\.(?:New|Extract|Expand|Key)|pbkdf2\.Key|argon2\.(?:ID)?Key|bcrypt\.GenerateFromPassword)\(')
def _(m, x):
    f = m.group(1).split(".")[0]
    return [({"scrypt": "scrypt", "hkdf": "HKDF", "pbkdf2": "PBKDF2", "argon2": "Argon2", "bcrypt": "bcrypt"}[f], {})]


@rule("go", r'\bdsa\.(GenerateParameters|GenerateKey|Sign|Verify)\(')
def _(m, x):
    return [("DSA", {})]


# JavaScript / TypeScript
@rule("js", r'\bcreateHash\(\s*' + Q + r'([\w-]+)' + Q)
def _(m, x):
    return lit(m.group(1))


@rule("js", r'\bcreateHmac\(\s*' + Q + r'([\w-]+)' + Q)
def _(m, x):
    return [("HMAC", {"hash": lookup(m.group(1))})]


@rule("js", r'\bcreate(?:Cipheriv|Decipheriv|Cipher|Decipher)\(\s*' + Q + r'([\w-]+)' + Q)
def _(m, x):
    return [parse_symmetric_name(m.group(1))]


@rule("js", r'\bgenerateKeyPair(?:Sync)?\(\s*' + Q + r'([\w-]+)' + Q)
def _(m, x):
    a = lookup(m.group(1)) or pq_from_text(m.group(1))
    near = x.window_text(6)
    p = {}
    ml = re.search(r"modulusLength\s*:\s*(\d+)", near)
    nc = re.search(r"namedCurve\s*:\s*" + Q + r"([\w-]+)", near)
    if ml:
        p["key_size"] = int(ml.group(1))
    if nc:
        p["curve"] = curve(nc.group(1))
    return [(a, p)]


@rule("js", r'\bcreate(?:Sign|Verify)\(\s*' + Q + r'([\w-]+)' + Q)
def _(m, x):
    return sig_scheme(m.group(1))


@rule("js", r'\bcreateECDH\(\s*' + Q + r'([\w-]+)' + Q)
def _(m, x):
    return [("ECDH", {"curve": curve(m.group(1))})]


@rule("js", r'\bcreateDiffieHellman(?:Group)?\(')
def _(m, x):
    return [("DH", {})]


@rule("js", r'\bpbkdf2(?:Sync)?\([^;]*?' + Q + r'(sha\w+|md5)' + Q)
def _(m, x):
    return [("PBKDF2", {"hash": lookup(m.group(1))})]


@rule("js", r'\bcrypto\.scrypt(?:Sync)?\(')
def _(m, x):
    return [("scrypt", {})]


@rule("js", r'\bsubtle\.(generateKey|importKey|sign|verify|encrypt|decrypt|deriveKey|deriveBits|digest)\(')
def _(m, x):
    near = x.window_text(4)
    out = []
    nm = re.search(r"name\s*:\s*" + Q + r"([\w-]+)" + Q, near) or (re.search(r"digest\(\s*" + Q + r"([\w-]+)" + Q, near) if m.group(1) == "digest" else None)
    if nm:
        a = lookup(nm.group(1)) or parse_symmetric_name(nm.group(1))[0]
        p = {}
        ml = re.search(r"modulusLength\s*:\s*(\d+)", near)
        nc = re.search(r"namedCurve\s*:\s*" + Q + r"([\w-]+)", near)
        ln = re.search(r"length\s*:\s*(128|192|256)\b", near)
        if ml:
            p["key_size"] = int(ml.group(1))
        if nc:
            p["curve"] = curve(nc.group(1))
        if a == "AES":
            p.update(parse_symmetric_name(nm.group(1))[1])
            if ln:
                p["key_size"] = int(ln.group(1))
        out.append((a, p))
    return out


@rule("js", r'\bjwt\.sign\(')
def _(m, x):
    alg = re.search(r"algorithm\s*:\s*" + Q + r"(\w+)" + Q, x.window_text(4))
    return sig_scheme(alg.group(1)) if alg else [("HMAC", {"hash": "SHA-256"})]


@rule("js", r'\bnew\s+NodeRSA\(')
def _(m, x):
    b = re.search(r"\bb\s*:\s*(\d+)", x.window_text(2))
    return [("RSA", {"key_size": int(b.group(1))} if b else {})]


@rule("js", r'\bpki\.rsa\.generateKeyPair\(\s*\{?\s*(?:bits\s*:\s*)?(\d+)?')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1))} if m.group(1) else {})]


@rule("js", r'\bnew\s+(?:elliptic\.)?(?:ec|EC)\(\s*' + Q + r'(\w+)' + Q)
def _(m, x):
    return [("ECC", {"curve": curve(m.group(1))})]


@rule("js", r'\b(?:minVersion|maxVersion)\s*:\s*' + Q + r'(TLSv1(?:\.\d)?)' + Q)
def _(m, x):
    return lit(m.group(1))


@rule("js", r'\bsecureProtocol\s*:\s*' + Q + r'(\w+?)_method' + Q)
def _(m, x):
    return lit(m.group(1)) if m.group(1).upper() not in ("TLS", "SSLV23") else []


# C / C++ (OpenSSL)
@rule("c", r'\bEVP_(md5|md4|sha1|sha224|sha256|sha384|sha512|sha3_256|sha3_384|sha3_512|blake2b512|blake2s256)\s*\(\s*\)')
def _(m, x):
    return lit(m.group(1))


@rule("c", r'\bEVP_(aes_\d+_\w+|des_ede3\w*|des_\w+|rc4|rc2_\w+|bf_\w+|chacha20_poly1305|chacha20)\s*\(\s*\)')
def _(m, x):
    return [parse_symmetric_name(m.group(1))]


@rule("c", r'\bRSA_generate_key(?:_ex)?\s*\([^,]*,\s*(\d+)')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1))})]


@rule("c", r'\bRSA_(public_encrypt|private_decrypt|sign|verify|new)\s*\(')
def _(m, x):
    return [("RSA", {})]


@rule("c", r'\bEVP_PKEY_CTX_new_id\(\s*(EVP_PKEY_\w+)')
def _(m, x):
    return lit(m.group(1))


@rule("c", r'\bEVP_PKEY_CTX_set_rsa_keygen_bits\([^,]+,\s*(\d+)')
def _(m, x):
    x.attach({"key_size": int(m.group(1))}, ("RSA",))


@rule("c", r'\bEVP_PKEY_CTX_set_ec_paramgen_curve_nid\([^,]+,\s*(NID_\w+)')
def _(m, x):
    x.attach({"curve": curve(m.group(1))}, ("ECC", "ECDSA", "ECDH"))


@rule("c", r'\bEVP_PKEY_(?:CTX_new_from_name|Q_keygen)\([^"]*"([^"]+)"(?:\s*,\s*(\d+))?')
def _(m, x):
    a = lookup(m.group(1)) or pq_from_text(m.group(1))
    return [(a, {"key_size": int(m.group(2))} if m.group(2) and a == "RSA" else {})]


@rule("c", r'\bEC_KEY_new_by_curve_name\(\s*(NID_\w+)')
def _(m, x):
    return [("ECC", {"curve": curve(m.group(1))})]


@rule("c", r'\b(ECDSA_do_sign|ECDSA_sign|ECDSA_verify|ECDSA_do_verify|ECDH_compute_key|DH_generate_key|DH_compute_key|DH_new|DSA_generate_parameters_ex|DSA_sign|DSA_do_sign)\s*\(')
def _(m, x):
    f = m.group(1)
    return [(f.split("_")[0], {})]


@rule("c", r'\b(MD5|SHA1|SHA256|SHA512)(?:_Init|_Update|_Final)?\s*\(')
def _(m, x):
    return lit(m.group(1))


@rule("c", r'\bSSL_CTX_set_(?:min|max)_proto_version\([^,]+,\s*(\w+)')
def _(m, x):
    return lit(m.group(1))


@rule("c", r'\b(TLSv1_method|TLSv1_1_method|SSLv3_method|SSLv2_method|TLSv1_client_method|TLSv1_server_method)\s*\(')
def _(m, x):
    return lit(m.group(1).split("_method")[0].split("_client")[0].split("_server")[0])


@rule("c", r'\bSSL_CTX_set1_(?:groups|curves)_list\([^,]+,\s*"([^"]+)"')
def _(m, x):
    return [("ECDH", {"curve": curve(g)}) if curve(g) else (lookup(g) or pq_from_text(g), {}) for g in m.group(1).split(":")]


@rule("c", r'\bSSL_CTX_set_(?:cipher_list|ciphersuites)\([^,]+,\s*"([^"]+)"')
def _(m, x):
    return cipher_string(m.group(1))


@rule("c", r'\bHMAC\(\s*EVP_(\w+)\(\)')
def _(m, x):
    return [("HMAC", {"hash": lookup(m.group(1))})]


@rule("c", r'\bPKCS5_PBKDF2_HMAC(?:_SHA1)?\(')
def _(m, x):
    return [("PBKDF2", {})]


# C#
CS = {"RSA": "RSA", "DSA": "DSA", "ECDsa": "ECDSA", "ECDiffieHellman": "ECDH", "Aes": "AES", "TripleDES": "3DES", "DES": "DES", "RC2": "RC2",
      "MD5": "MD5", "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "HMACSHA256": "HMAC", "HMACSHA1": "HMAC",
      "HMACMD5": "HMAC", "Rfc2898DeriveBytes": "PBKDF2", "RSACryptoServiceProvider": "RSA", "DSACryptoServiceProvider": "DSA",
      "TripleDESCryptoServiceProvider": "3DES", "DESCryptoServiceProvider": "DES", "RC2CryptoServiceProvider": "RC2", "MD5CryptoServiceProvider": "MD5",
      "SHA1CryptoServiceProvider": "SHA-1", "SHA1Managed": "SHA-1", "SHA256Managed": "SHA-256", "RijndaelManaged": "AES", "AesManaged": "AES",
      "AesGcm": "AES", "AesCcm": "AES", "ChaCha20Poly1305": "ChaCha20-Poly1305", "ECDsaCng": "ECDSA", "RSACng": "RSA", "MLKem": "ML-KEM", "MLDsa": "ML-DSA"}


def _cs(m, x):
    c, n = m.group(1), m.group(2)
    a = CS.get(c)
    p = {}
    if a in ("RSA", "DSA") and n:
        p["key_size"] = int(n)
    if a == "HMAC":
        p["hash"] = lookup(c[4:])
    if c in ("AesGcm", "AesCcm"):
        p["mode"] = c[3:].upper()
    return [(a, p)]


rule("csharp", r'\b(' + "|".join(CS) + r')\.Create\s*\(\s*(\d+)?')(_cs)
rule("csharp", r'\bnew\s+(' + "|".join(CS) + r')\s*\(\s*(\d+)?')(_cs)


@rule("csharp", r'\bCipherMode\.(ECB|CBC|CFB|OFB|CTS)\b')
def _(m, x):
    x.attach({"mode": m.group(1)}, ("AES", "3DES", "DES", "RC2"))


@rule("csharp", r'\bSslProtocols\.(Tls13|Tls12|Tls11|Tls|Ssl3|Ssl2)\b')
def _(m, x):
    t = {"Tls": "TLSv1", "Tls11": "TLSv1.1", "Tls12": "TLSv1.2", "Tls13": "TLSv1.3", "Ssl3": "SSLv3", "Ssl2": "SSLv2"}[m.group(1)]
    return lit(t)


@rule("csharp", r'\bECCurve\.NamedCurves\.nistP(256|384|521)')
def _(m, x):
    x.attach({"curve": f"P-{m.group(1)}"}, ("ECDSA", "ECDH", "ECC"), window=4)


@rule("csharp", r'\bHashAlgorithmName\.(SHA1|SHA256|SHA384|SHA512|MD5)\b')
def _(m, x):
    return lit(m.group(1))


# Rust
@rule("rust", r'\bRsaPrivateKey::new\([^,]+,\s*(\d+)')
def _(m, x):
    return [("RSA", {"key_size": int(m.group(1))})]


RING = {"ECDSA_P256": ("ECDSA", "P-256"), "ECDSA_P384": ("ECDSA", "P-384"), "ED25519": ("Ed25519", None), "RSA_PKCS1": ("RSA", None),
        "RSA_PSS": ("RSA", None), "X25519": ("X25519", None), "ECDH_P256": ("ECDH", "P-256"), "ECDH_P384": ("ECDH", "P-384")}


@rule("rust", r'\b(ECDSA_P256|ECDSA_P384|RSA_PKCS1|RSA_PSS|ECDH_P256|ECDH_P384)_\w+|\b(?:signature|agreement)::(ED25519|X25519)\b')
def _(m, x):
    a, c = RING[m.group(1) or m.group(2)]
    h = re.search(r"SHA(256|384|512)", m.group(0))
    return [(a, {"curve": c, "lib": "ring"} if c else {"lib": "ring"})] + ([(f"SHA-{h.group(1)}", {"lib": "ring"})] if h else [])


@rule("rust", r'\baead::(AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305)\b')
def _(m, x):
    return [parse_symmetric_name(m.group(1))]


@rule("rust", r'\b(Md5|Sha1|Sha224|Sha256|Sha384|Sha512)::(?:new|digest)\b|\bmd5::compute\(')
def _(m, x):
    return lit(m.group(1) or "MD5")


@rule("rust", r'\bAes(128|192|256)(Gcm|GcmSiv|Ctr|Cbc)?\b')
def _(m, x):
    return [("AES", {"key_size": int(m.group(1)), "mode": (m.group(2) or "")[:3].upper() or None})]


@rule("rust", r'\b(?:MlKem|ml_kem::MlKem)(512|768|1024)\b')
def _(m, x):
    return [(f"ML-KEM-{m.group(1)}", {})]


@rule("java go js c csharp rust", r'\b[\w.]*(?:ml[-_]?kem|ml[-_]?dsa|slh[-_]?dsa|MLKem|MLDsa|MlKem|MlDsa|mlkem|mldsa)[-_]?(?:512|768|1024|44|65|87)?\w*')
def _(m, x):
    a = pq_from_text(m.group(0))
    return [(a, {}, "identifier")] if a else []
