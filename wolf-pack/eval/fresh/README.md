# Fresh-repo check

Seven small repositories that Wolf Pack had never seen, scanned on 25 September 2026 to check that it works on new code before the held-out benchmark. None of them is in the held-out set. Every accepted (file, algorithm family) pair in non-test files was reviewed by hand under the strict reading of `eval/heldout/LABELLING.md` (used, not merely named). This was one reviewer, not blind, and recall was only spot-checked.

| Repo | Commit | Language | What it does with crypto |
|---|---|---|---|
| FiloSottile/mkcert | 1c1dc4e | Go | Local CA: RSA and ECDSA keys, SHA-1 key IDs, trust-store fingerprints |
| pallets/itsdangerous | 672971d | Python | HMAC-signed tokens, SHA-1 by default |
| auth0/node-jwa | 1b54a3b | JavaScript | JWA for Node: HMAC, RSA, RSA-PSS, ECDSA, picked by name at runtime |
| patrickfav/bcrypt | d068562 | Java | A bcrypt implementation, SHA-512 pre-hashing for long passwords |
| jedisct1/minisign | 4ade112 | C | Signing tool on libsodium: Ed25519, BLAKE2b, scrypt |
| mozilla/ssl-config-generator | 99178dc | JavaScript and JSON | Mozilla's server TLS configuration profiles |
| neosmart/SecureStore | 8b35f96 | C# | Encrypted secrets: AES, PBKDF2, HMAC-SHA1 |

## First run

| Repo | Pairs | Correct | Wrong | Misses found by spot-check |
|---|---:|---:|---:|---|
| mkcert | 6 | 5 | 1: `flag.Bool("ecdsa", …)`, a flag name | none |
| itsdangerous | 2 | 2 | 0 | none |
| node-jwa | 2 | 1 | 1: `createHmac('sha' + bits)` read as SHA-1 | RSA, ECDSA, SHA-256/384/512 (names built at runtime) |
| bcrypt | 1 | 1 | 0 | bcrypt itself (an implementation with no library call) |
| minisign | 1 | 1 | 0 | Ed25519, BLAKE2, scrypt through libsodium |
| ssl-config-generator | 44 | declared | see below | ciphers, curves and certificate types in multi-line JSON arrays |
| SecureStore | 4 | 3 | 1: `[JsonProperty(PropertyName = "hmac")]`, a field name | HMAC (`HMAC.Create("HMACSHA1")` gave SHA-1 only) |

ssl-config-generator's 44 pairs are TLS versions in the profile data (`"tls_versions": ["TLSv1.2", "TLSv1.3"]`). They are declared support: correct under the inclusive policy, wrong under the strict one. Scanners and people will disagree on this kind of file, which is why the benchmark reports both policies.

Excluding that repo, the first run had 16 pairs: 13 correct and 3 wrong. Spot-checking found 10 misses.

## Fixes, each with a corpus trap, a must-fire case and a test

- **libsodium calls** in C, PHP and JS (`crypto_sign_*`, `crypto_generichash*`, `crypto_pwhash_*`, `crypto_secretbox*`, `crypto_box*`, AEADs and more). Prototypes in headers don't count, because they are declared API. Salsa20 was added to the elders for NaCl's secretbox. (`c/sodium.c`, `c/sodium_api.h`)
- **HMAC names carry their hash:** `HMACSHA1` is HMAC with SHA-1, not bare SHA-1, following the confirmed labelling convention. (`java/Macs.java`)
- **JS literal completeness:** the JS rules read a literal only when it is the whole argument, so `'sha' + bits` gives HMAC with an unknown hash. (`js/hmac_bits.js`)
- **Flow exclusions:** a literal passed to a flag, option or serialization-name call is not a flow into crypto. (`go/flags.go`, `cs/Blob.cs`)

## After the fixes

| Repo | Pairs | Correct | Wrong | Still missed |
|---|---:|---:|---:|---|
| mkcert | 5 | 5 | 0 | none found |
| itsdangerous | 2 | 2 | 0 | none found |
| node-jwa | 1 | 1 | 0 | RSA, ECDSA, SHA-256/384/512 |
| bcrypt | 1 | 1 | 0 | bcrypt |
| minisign | 4 | 4 | 0 | none found |
| ssl-config-generator | 44 | declared | declared | ciphers, curves, certificate types |
| SecureStore | 4 | 4 | 0 | none found |

These repos shaped the fixes, so the "after" numbers are after tuning on them. They show that the fixes work, not how well Wolf Pack generalises. That is the held-out benchmark's job.

## CBOMkit on the four repos in its languages

CBOMkit-action (sonar-cryptography 1.7.0) ran with the same settings as `eval/cbomkit/`, and patrickfav/bcrypt was built with Maven first.

| Repo | Wolf Pack pairs | CBOMkit pairs | Both | Wolf Pack only | CBOMkit only |
|---|---:|---:|---:|---:|---:|
| mkcert | 5 | 3 | 3 | 2 (`rsa.GenerateKey`, `ecdsa.GenerateKey`) | 0 |
| itsdangerous | 2 | 0 | 0 | 2 | 0 |
| bcrypt | 1 | 0 | 0 | 1 | 0 |
| SecureStore | 4 | 5 | 4 | 0 | 1 (`NATIVEPRNG`, a random-number generator) |

Wolf Pack found every algorithm pair CBOMkit found. CBOMkit's one extra pair is a random-number generator, which the labelling guide leaves out.
