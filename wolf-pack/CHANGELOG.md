# Changelog

Versions of Wolf Pack CBOM. A release is a tag `wolf-pack-vX.Y.Z` on the PQC Suite repository; its GitHub release carries the wheel and build provenance.

## 1.2.0 (28 September 2026)

Much higher recall on real code. The changes were made after reading the held-out benchmark's misses, so held-out scores for this version are reported as "after tuning on held-out data" (see `eval/heldout/README.md` and `eval/unseen/README.md`).

- **Used or declared:** a finding that is only named in an algorithm list or table (supported-algorithm arrays, OID tables, TypeScript unions) is marked `declared`. It shows in the CBOM (`wolfpack:usage`), the report and the terminal, and becomes a SARIF note, so what actually runs stands out.
- **Values through parameters (`--without parameters`):** a crypto API called with a parameter, such as `MessageDigest.getInstance(algorithm)` inside a helper, is resolved from the literals its callers pass (Java, JavaScript/TypeScript, Python).
- **Incremental scans:** `--changed-since REF` reads only the files changed since a git ref (and uncommitted ones), for fast pull-request checks.
- **Keyboard access:** the report's and the dashboard's wide tables can be scrolled with the keyboard.
- **Signed CBOMs:** `wolfpack keygen`, then `scan --sign KEY` or `wolfpack sign`, writes a detached ML-DSA-65 signature (Ed25519 with cryptography older than 46) over the exact bytes of `cbom.json`. `wolfpack verify --pub` checks who signed it and that nothing changed.
- **Readiness over time:** `merge --history FILE` keeps one line per day and charts the quantum-safe share, systems at critical or high, and policy breaches.
- **PyPI:** the release workflow can publish `wolfpack-cbom` to PyPI with trusted publishing, once the `PYPI_PUBLISH` repository variable is set.
- **How to fix:** every finding gets concrete fixes for where it was found. That means the replacement API in its language (JDK 24 ML-KEM/ML-DSA, Go 1.24 `crypto/mlkem`, OpenSSL 3.5, .NET 10, liboqs-python, @noble/post-quantum, RustCrypto), the configuration line for nginx, Apache, HAProxy, sshd or a cloud load balancer, a reissue for certificates, and the PQC Suite product that does the job. Fixes appear in the report, the CBOM (`wolfpack:remediation`) and SARIF rule help.
- **Traffic captures:** `wolfpack scan --pcap traffic.pcap` reads the TLS and SSH handshakes in a packet capture (pcap or pcapng) and reports what was actually negotiated per server: version, cipher suite and key-exchange group, and how many clients offered a PQ group. Pure Python; nothing is decrypted or sent.
- **Kubernetes and cloud TLS:**
  - certificates in Kubernetes TLS Secrets (base64 `tls.crt`);
  - ingress-nginx `ssl-ciphers` and `ssl-protocols` annotations;
  - AWS ELB/ALB and Azure Application Gateway predefined TLS policies, decoded from their names, including AWS's PQ policies;
  - minimum-TLS-version settings in Terraform.
- **Swift and PHP:** CryptoKit (`P256.Signing`, `Curve25519`, `ChaChaPoly`, `HMAC<SHA256>`), Security framework key types, and PHP's `hash_hmac`, `password_hash` and `openssl_pkey_new`.
- **Fix:** functions whose names start with `hash`, `can` or `is` in lower case (`hash_hmac`) were wrongly skipped as predicates.
- **Policy and compliance:** `--policy nist-ir-8547` and `--policy cnsa-2.0` check the findings against those standards' algorithms and dates. Your own rules go in `[policy]` in `.wolfpack.toml`: forbidden algorithms, minimum key sizes, and required hybrid key exchange. Rules already broken are "overdue", and `--fail-on-policy` exits 2 on them. Rules with a future deadline are listed as "due later". Results appear in the report, `findings.json` and the CBOM (`wolfpack:policy`), and `merge` counts them per system.
- **Names (`--without names`):** code named for its algorithm is found without any library API: `aes_encrypt()`, `md5_update()`, `BCrypt.HashPassword()`, `class HkdfSha256`, `curve25519_generate_public()`. Declarations are not counted: header prototypes, `extern`/`partial`, Java enum constants, `.d.ts` typings, test names, predicates, and error or not-supported helpers.
- **Constants (`--without symbols`):** all-caps constants and enum members that name an algorithm where code uses them: `case KEY_ED25519:`, `kex[KEX_DH_GRP14_SHA256]`, `crypto.SHA1`, and TLS cipher-suite constants. Sizes, error names, feature flags, definitions, headers, and `case` labels that only throw are not counted.
- **Names built at run time (`--without concat`):** `"RSA-SHA" + bits` reports RSA; `"SHA-" + bits` still reports nothing.
- **Multi-line YAML and JSON lists (`--without lists`)** in configuration files.
- **Organisation inventory:** `wolfpack merge` combines the CBOMs of many systems into one dashboard (`inventory.html`), a summary (`inventory.json`) and a merged CycloneDX 1.6 CBOM. The dashboard ranks systems weakest first, lists what to migrate first, and shows where each algorithm family is used. CBOMs from other tools work too, with tiers estimated from the algorithm. `--fail-on` gates CI on the whole estate.
- **Container images:** `wolfpack scan image.tar` unpacks a `docker save` or OCI archive layer by layer, with whiteouts applied, and scans the result.
- **Cloud KMS and HSM keys:** AWS KMS key specs, Google Cloud KMS algorithms and Azure Key Vault key types, in Terraform, CloudFormation or code.
- **JavaScript and TypeScript imports:** `export const` values imported by name from a relative module now propagate (part of `cross-file`).
- **New formats and APIs:**
  - Noise protocol names (`Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s`) and Go's `flynn/noise`;
  - JOSE identifiers (`A256GCM`, `PBES2-HS512+A256KW`, `RSA-OAEP-256`, `ECDH-ES`);
  - PyNaCl's `SecretBox`, `Box`, hash and pwhash;
  - `hashlib.sha1` passed as a value, but not when it is only compared against;
  - WireGuard's `wg genkey` and `wg pubkey` in shell scripts.
- **The flow check** now follows byte and raw literals (`b"..."`) and code that branches on an algorithm name (`case "AES256":`, `alg == "EdDSA"`).
- **More APIs:**
  - Go types of an imported crypto package (`*ecdsa.PrivateKey`) and `x509` signature-algorithm constants;
  - .NET `SecurityAlgorithms.*`;
  - Python `isinstance(k, rsa.RSAPublicKey)`.
- **Faster:** large repositories scan up to 8 times faster (spring-security took 210 s and now takes 24 s), with the same results.
- **New algorithms:** MD2, SHA3-224, AEGIS-128L, AEGIS-256, ConcatKDF, ANSI X9.63 KDF, Balloon hashing and SPAKE2.

## 1.1.0 (28 September 2026, not released)

- **Trust stores:** a file of five or more self-signed certificates and nothing else (such as certifi's `cacert.pem`) is one line, "Trust store of 121 root certificates", ranked low, instead of one alert per root. Switch: `--without trust-store`.
- **Declared non-security hashes:** Python `hashlib` calls with `usedforsecurity=False` rank low and are SARIF notes. Switch: `--without purpose`.
- **Nothing skipped silently:** Python files the running interpreter cannot parse, and source files over 2 MB, are named in the report. The Docker image and GitHub Action run Python 3.14.
- RIPEMD-160 recognised; `itest/` and bare `unit/` folders count as tests; the deliberate TLS 1.0/1.1 probes no longer raise deprecation warnings.
- Moved into the PQC Suite repository, under `wolf-pack/`. The GitHub Action is now `QubitMan-hub/PQCsuite/wolf-pack@main`.

## 1.0.0

First production release: CycloneDX 1.6 CBOM, SARIF, HTML report; source, configuration, key and certificate, binary, dependency and live TLS/SSH scouts; Docker image, GitHub Action, `.wolfpack.toml`, `--exclude`.
