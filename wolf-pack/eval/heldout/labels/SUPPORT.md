# Label-support check and AI audit (amendment 3)

Both checks ran on 28 September 2026, after the audit sheets were committed (60c57b6) and before any scoring. No label in `final/` was changed.

## 1. Support check

`python heldout.py support` checked 393 `used` labels: 355 have a name for their family in the file's code, 38 do not. Each of the 38 was read by hand. Verdicts:

- **a. Blind spot of the check.** The code does name the family, in a form the token table misses.
- **b. Inferred correctly.** The code names no family, but the label follows from what the code calls, under `LABELLING.md`.
- **c. Doubtful.** The file does not appear to support the label.

| Repo | File | Label | Verdict | Why |
|---|---|---|---|---|
| bcrypt-net | benchmarks/Method-Benchmarks/EnhancedHashingBenchmark.cs | HMAC | b | Calls `BCryptExtendedV3.HashPassword(Hmackey, ...)`, which HMACs the key first; `Hmackey` is not matched as a word |
| bcrypt-net | benchmarks/Method-Benchmarks/EnhancedHashingV3Benchmark.cs | SHA3-256, SHA3-384, SHA3-512 | a | `HMACSHA3_256`, `HMACSHA3_384`, `HMACSHA3_512`; the table writes these tokens as `sha3256`, which splits as `sha` + `3256` |
| bcrypt-net | benchmarks/Method-Benchmarks/EnhancedHashingValidation.cs | HMAC | b | Calls `BCryptExtendedV3.HashPassword(Hmackey, ...)` |
| bcrypt-net | benchmarks/Method-Benchmarks/EnhancedHashingValidation.cs | SHA3-384 | b, borderline | Only through the call into `BCryptExtendedV3` (HMAC-SHA3-384 behind `HashType.SHA384`). The audit left it out; see section 2 |
| bcrypt-net | src/BCrypt.Net/BCryptExtendedV3.cs | SHA3-256, SHA3-384, SHA3-512 | a | `HMACSHA3_256.TryHashData` and its siblings; same token split |
| crypto-algorithms | des.c, des_test.c | 3DES | a | `three_des_key_setup`, `three_des_crypt`; "three des" is not in the table |
| cryptopasta | tls.go | ECDH | b | `CurvePreferences: []tls.CurveID{tls.CurveP256, ...}` selects ECDHE groups |
| golang-jwt | cmd/jwt/main.go | ECDSA | b | `isEs()` and `jwt.ParseECPublicKeyFromPEM` for ES* signing |
| jwcrypto | jwcrypto/jwk.py | SHA3-256, SHA3-384, SHA3-512 | a | `hashes.SHA3_256()` and siblings; same token split |
| jwcrypto | jwcrypto/tests-cookbook.py | PBKDF2 | b | `PBES2-HS512+A256KW` is PBKDF2 by definition (RFC 7518) |
| jwcrypto | jwcrypto/tests-cookbook.py | SHA-1 | b | `RSA-OAEP` uses SHA-1 and MGF1-SHA-1 (RFC 7518) |
| jwcrypto | jwcrypto/tests-cookbook.py | SHA-384 | c | The only 384 in the file is the curve `"crv": "P-384"` for ECDH-ES, whose KDF is SHA-256. No SHA-384 found |
| jwcrypto | jwcrypto/tests.py | 3DES | a | `DEK-Info: DES-EDE3-CBC` on a PEM key the tests load; `des-ede3` is not in the table |
| jwcrypto | jwcrypto/tests.py | SHA-1 | b | `{"alg":"RSA-OAEP", ...}` |
| magic-wormhole | src/wormhole/_dilation/connector.py | X25519 | a | `Noise_NNpsk0_25519_ChaChaPoly_BLAKE2s`; a bare `25519` is not in the table |
| magic-wormhole | src/wormhole/_key.py, transit.py | OTHER:SALSA20 | a | `nacl.secret.SecretBox` is XSalsa20-Poly1305. The table has no entries for OTHER families, so none can be supported |
| node-bcrypt | bcrypt.js | bcrypt | b | The package's wrapper: `bindings.gen_salt`, `bindings.encrypt`, `compare`; the name appears only in comments |
| nsec | src/Cryptography/Ed25519ph.cs | SHA-512 | b, borderline | Ed25519ph prehashes with SHA-512 by definition (RFC 8032). The audit left it out; see section 2 |
| otp-java | src/main/java/com/bastiaanjansen/otp/TOTPGenerator.java | SHA-1 | b | Delegates to `HOTPGenerator`, whose default algorithm is HMAC-SHA1 |
| wireguard-tools | contrib/external-tests/go/main.go | X25519 | a | `noise.DH25519` |
| wireguard-tools | contrib/external-tests/python/main.py, rust/src/main.rs | X25519 | a | `Noise_IKpsk2_25519_...` |
| wireguard-tools | contrib/keygen-html/wireguard.js | X25519 | b | A Curve25519 implementation in JS (`gf`, `cswap`, `pack`) with no name for it |
| wireguard-tools | contrib/embeddable-wg-library/wireguard.c, test.c | X25519 | b | `wg_generate_public_key` / `wg_generate_private_key` are Curve25519 |
| wireguard-tools | contrib/ncat-client-server/client-quick.sh, client.sh, server.sh; contrib/synergy/synergy-client.sh, synergy-server.sh | X25519 | b | `wg genkey`, `wg pubkey`, `private-key`: WireGuard keys are X25519 |

Totals over the 38 cells: 18 a, 19 b (2 borderline), 1 c. Only one label looks wrong: SHA-384 in jwcrypto's `tests-cookbook.py`. It stays in `final/` and in the score. It is one pair out of the repo's labels. If it is wrong, it lowers precision for any tool that does not report it and raises recall for none.

The check also listed 49 files labelled `-` whose code contains a family name. None needs a new label:

- **Project or package names.** 26 files: `bcrypt` in bcrypt-net (namespaces, exceptions, build files, docs, Dockerfile) and in node-bcrypt (`Dockerfile`, `build-all.sh`, `package.json`).
- **Parameter holders, error messages and banners with no crypto call.** nsec `Argon2Parameters.cs`, `ScryptParameters.cs`, `Pbkdf2Parameters.cs` and `Error.cs`; password4j `Utils.java`, which prints an ASCII banner of supported algorithms.
- **Manifests.** otp-java `pom.xml`, password4j `pom.xml`, speakeasy `package.json` and `jsdoc.json`, tiny-aes-c `library.json`, `library.properties` and `test_package/conanfile.py`.
- **Declarations and wrappers.** tiny-aes-c `aes.hpp` only includes `aes.h`, which is where AES is labelled. wireguard-tools `ipc-uapi-*.h` carry no crypto; the table's matches there are false tokens.
- **False tokens.** `bf`, `ec` and similar short tokens in the armadillo layout XML, in the AssemblyInfo files, in magic-wormhole `_wordlist.py` and `update-version.py`, and in wireguard-tools `fuzz/stringlist.c`.
- **Borderline.**
  - jwcrypto `jwt.py` names `RSA1_5` only in a list that checks whether the allowed algorithms are a subset of the JWE ones.
  - pyotp `utils.py` imports `hmac.compare_digest`, a constant-time compare that is not HMAC, and names `"sha1"` only as a default value to compare against.
  - sio `dare.go` uses `CHACHA20_POLY1305` only as an upper bound when validating a header byte; the cipher is built in `sio.go`.

  A reader could label any of these, but `-` follows `LABELLING.md`.

## 2. AI-audit agreement (`heldout.py agree final audit`, 63 files)

| Policy | final pairs | audit pairs | both | Dice |
|---|---|---|---|---|
| strict (used) | 33 | 33 | 31 | 0.939 |
| inclusive (used + declared) | 38 | 37 | 36 | 0.960 |

Sixteen repos agree exactly. The cells that differ:

| Repo | File | final | audit | Note |
|---|---|---|---|---|
| bcrypt-net | EnhancedHashingValidation.cs | + SHA3-384 | - | Only reachable through the call into `BCryptExtendedV3` (section 1) |
| iron | lib/index.d.ts | declared AES, SHA-256 | declared AES, SHA-256, HMAC | The typings declare the `integrity` options and an HMAC result type |
| nsec | Ed25519ph.cs | + SHA-512 | - | The prehash is fixed by RFC 8032 |
| nsec | KeyAgreementAlgorithm.cs | declared X25519 | used X25519 | A static `X25519` property that constructs the algorithm: used or declared |
| nsec | SignatureAlgorithm.cs | declared Ed25519 | used Ed25519 | Same, for `Ed25519` |

The other cells differ only in the order or case of the family names, which `agree` ignores. Every difference is a judgement call on the used/declared line or on an implied hash. None is a family that one side found in code and the other missed.

The auditor is the assistant that develops Wolf Pack, so this is a consistency check, not an independent one (amendment 3, item 2). It cannot change the score.
