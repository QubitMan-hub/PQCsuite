# Changelog

Versions of Wolf Pack CBOM. A release is a tag `wolf-pack-vX.Y.Z` on the PQC Suite repository; its GitHub release carries the wheel and build provenance.

## 1.2.0 (28 September 2026)

Much higher recall on real code. The changes were made after reading the held-out benchmark's misses, so held-out scores for this version are reported as "after tuning on held-out data" (see `eval/heldout/README.md` and `eval/unseen/README.md`).

- **Names (`--without names`):** code named for its algorithm is found without any library API: `aes_encrypt()`, `md5_update()`, `BCrypt.HashPassword()`, `class HkdfSha256`, `curve25519_generate_public()`. Declarations are not counted: header prototypes, `extern`/`partial`, Java enum constants, `.d.ts` typings, test names, predicates, and error or not-supported helpers.
- **Constants (`--without symbols`):** all-caps constants and enum members that name an algorithm where code uses them: `case KEY_ED25519:`, `kex[KEX_DH_GRP14_SHA256]`, `crypto.SHA1`, and TLS cipher-suite constants. Sizes, error names, feature flags, definitions, headers, and `case` labels that only throw are not counted.
- **Names built at run time (`--without concat`):** `"RSA-SHA" + bits` reports RSA; `"SHA-" + bits` still reports nothing.
- **Multi-line YAML and JSON lists (`--without lists`)** in configuration files.
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
