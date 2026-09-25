# 40-repo stress test

Forty open-source repositories were scanned on 25 September 2026 to find where Wolf Pack breaks, and it was fixed on what they showed. The sample spans:

- **Languages:** Python, Go, Java, JavaScript/TypeScript, C, C# and Rust.
- **Pure implementations:** Monocypher, cifra, BLAKE2, tiny_sha3, sjcl, and gm (China's SM2/SM3/SM4).
- **Bindings:** pynacl and libsodium-core.
- **Configs:** h5bp's nginx configs, Cloudflare's sslconfig, and the ssh-audit algorithm database.

**These repos are tuned on and are never evidence of accuracy.** None of them is in the held-out set, the fresh set or the CBOMkit comparison set.

## Robustness

All 40 scanned without a crash, every CBOM validated against CycloneDX 1.6 with 0 errors, and every repo took under 10 seconds (most under 2).

## Results

"Pairs" are accepted (file, algorithm family) pairs in non-test files. CBOMkit (sonar-cryptography 1.7.0 via cbomkit-action) ran on the 22 repos in its languages, with Java unbuilt. A blank CBOMkit cell means the repo is outside its languages.

| Repo | Commit | Language | Pairs, first run | Pairs, now | CBOMkit pairs | Both | CBOMkit only |
|---|---|---|---:|---:|---:|---:|---:|
| acmez | e289d7f | Go | 9 | 9 | 6 | 5 | 1 |
| argon2-cffi | 7ac05ea | Python | 1 | 1 | 0 | 0 | 0 |
| argon2-jvm | 501a33c | Java | 1 | 1 | 0 | 0 | 0 |
| BLAKE2 | ed1974e | C | 11 | 11 |  |  |  |
| certmagic | 722bda8 | Go | 4 | 4 | 5 | 2 | 3 |
| certstrap | 258f480 | Go | 4 | 6 | 6 | 4 | 2 |
| cifra | 90f7631 | C | 32 | 38 |  |  |  |
| commons-codec | 68289e5 | Java | 6 | 15 | 8 | 7 | 1 |
| crypto-js | ac34a5a | JS | 12 | 16 |  |  |  |
| curve25519-dalek | 97a020d | Rust | 0 | 0 |  |  |  |
| DataProtection | 88a191f | C# | 22 | 26 | 7 | 7 | 0 |
| djangorestframework-simplejwt | a7cb077 | Python | 9 | 9 | 0 | 0 | 0 |
| fusionauth-jwt | 1c82711 | Java | 25 | 25 | 11 | 9 | 2 |
| gm | 950ad09 | Go | 0 | 3 | 0 | 0 | 0 |
| go-minisign | a09352b | Go | 3 | 3 | 0 | 0 | 0 |
| http-signatures-java | 51027f6 | Java | 12 | 12 | 2 | 2 | 0 |
| jasypt | 3e36dab | Java | 10 | 10 | 0 | 0 | 0 |
| jose-jwt | 20abc4e | C# | 37 | 40 | 11 | 11 | 0 |
| josepy | 7069e07 | Python | 8 | 9 | 1 | 1 | 0 |
| jwt (kataras) | 87a77ff | Go | 20 | 20 | 5 | 2 | 3 |
| libsodium-core | 334066b | C# | 0 | 23 | 0 | 0 | 0 |
| Monocypher | 1830c06 | C | 0 | 1 |  |  |  |
| nkeys | c1eebf3 | Go | 4 | 4 | 4 | 2 | 2 |
| noble-curves | e7316eb | TS | 5 | 6 |  |  |  |
| noble-hashes | 17cbd0b | TS | 6 | 10 |  |  |  |
| node-argon2 | 786de71 | JS | 1 | 1 |  |  |  |
| node-jws | 44e9094 | JS | 6 | 6 |  |  |  |
| pynacl | fddb5f3 | Python | 103 | 104 | 0 | 0 | 0 |
| python-ecdsa | bff40c6 | Python | 6 | 7 | 0 | 0 | 0 |
| python-fido2 | d1fd711 | Python | 33 | 35 | 2 | 2 | 0 |
| rage | b5b68c4 | Rust | 14 | 14 |  |  |  |
| SecurityDriven.Inferno | db1db2e | C# | 5 | 6 | 1 | 1 | 0 |
| server-configs-nginx | d2f2c3e | config | 11 | 11 |  |  |  |
| signify | 133c411 | C | 6 | 10 |  |  |  |
| sjcl | 35b0641 | JS | 3 | 28 |  |  |  |
| ssh-audit | 111399e | Python (algorithm DB) | 71 | 71 |  |  |  |
| sslconfig | c1be76a | config | 0 | 11 |  |  |  |
| tiny_sha3 | dcbb319 | C | 0 | 1 |  |  |  |
| tinyssh | 165ea4b | C | 34 | 34 |  |  |  |
| tweetnacl-js | e6141a2 | JS | 8 | 8 |  |  |  |
| **Total** | | | **542** | **649** | **69** | **55** | **14** |

## What the first run got wrong

**Misses.** CBOMkit-only pairs and repos where Wolf Pack found almost nothing pointed to these:

- **Implementations with no library call:** gm, tiny_sha3, and the C implementation libraries.
- **C# libsodium bindings and their `SecretBox`-style API:** libsodium-core.
- **sjcl's namespaces.**
- **A server config in a file with no extension:** sslconfig's `conf`.
- **Go key generation with a variable size or curve:** certstrap.
- **C# classes missing from the table:** `HMACSHA512`, `ECDiffieHellmanCng` and others.
- **commons-codec `DigestUtils`**, the most common Java hashing helper.
- **Python keys built from their numbers:** `rsa.RSAPublicNumbers`, `ec.EllipticCurvePublicNumbers`.

**False positives.** A random sample of 40 pairs that rest on string literals alone had about 6 wrong. They fall into two classes:

- **Test code not recognised as tests:** C# `UnitTestsNet46/`, `browserTest/`, `benches/`.
- **Algorithm names used as labels:** benchmark names, report tables, build module lists.

## Fixes, each with a corpus trap, a must-fire case and a test

- **Implementation scout** (`scouts/implementations.py`, role `implementations`). It recognises MD5, SHA-1, SHA-2, SHA-3, SM3, SM4, AES, DES, SM2 and P-256 by their published constants: round constants, initial values, S-boxes and curve primes.
  - Ambiguous constants are skipped by design: MD5 and SHA-1 share initial values, BLAKE2b and SHA-512 share them too, and ChaCha20 and Salsa20 share their sigma.
  - SM2, SM3, SM4 and generic SHA-3 were added to the elders.
- **libsodium in C#:** `extern` P/Invoke declarations are declared API, not use, and a rule covers the Sodium.Core classes (`SecretBox`, `PublicKeyAuth`, `GenericHash`, …).
- **sjcl:** its namespaces name the algorithm (`sjcl.cipher.aes`, `sjcl.misc.pbkdf2`, …).
- **Configs:** a file with no extension counts as config when two or more different TLS/SSH directives start its lines.
- **Go, C#, Python:** `rsa.GenerateKey` and `ecdsa.GenerateKey` with variables; the HMAC-SHA2/SHA3, ECDH and OpenSSL-backed .NET classes; and Python `*Numbers` key construction.
- **commons-codec:** `MessageDigestAlgorithms.*`, `DigestUtils.sha256Hex(…)`-style calls and `getDigest("…")`. A variable algorithm name gives nothing.
- **Test scope:** C# test projects (`*.Tests`, `UnitTests*`), `bench`, `benches`, `benchmark(s)`, `browserTest` and `test-classes` are now test code.
- **Flow:** literals passed to benchmark or test harness calls (`bench(…)`, `describe(…)`, `do_table(…)`) are labels, not flows.

## After the fixes

- **Pairs:** Wolf Pack reports 649 pairs, up from 542. No pair from the first run was lost.
- **CBOMkit:** on the 22 repos in its languages, Wolf Pack reports 259 pairs. CBOMkit reports 69, of which 55 are shared. By the held-out labelling guide, none of CBOMkit's other 14 is a Wolf Pack miss:
  - random-number generators (6);
  - MGF1 inside RSA-PSS (2);
  - SHA-512 inside Ed25519 key generation (5);
  - SHA3-224, which is outside the vocabulary (1).

## Still open

- **Rust implementations:** curve25519-dalek, whose field arithmetic has no recognisable constant tables, still yields nothing.
- **cifra's report script:** consecutive `do_table('Salsa20', …)` lines still count as a three-entry registry.
- **Names chosen at runtime:** algorithms built from strings at runtime (node-jwa's `'RSA-SHA' + bits`) are still missed.
- **Precision after the fixes:** it was not re-sampled. The held-out benchmark measures it properly.
