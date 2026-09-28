# Unseen-repo check of the 1.2.0 additions

Version 1.2.0 was tuned on the held-out repositories, so their scores no longer show whether the new rules generalise. This check used ten repositories that no earlier set had touched (held-out, fresh, stress, CBOMkit). It asks one question: of the pairs that 1.2.0 reports and 1.1.0 did not, how many are right?

| Repo | Commit | Language | 1.1.0 pairs | 1.2.0 pairs |
|---|---|---|---:|---:|
| FiloSottile/age | b74dce4 | Go | 25 | 42 |
| jedisct1/libhydrogen | f45478a | C | 0 | 4 |
| panva/jose | 55c959f | TypeScript | 96 | 158 |
| pyca/bcrypt | 59b41aa | Python, Rust | 1 | 1 |
| authlib/joserfc | 27d7c8a | Python | 35 | 39 |
| wg/scrypt | 0675236 | Java, C | 7 | 23 |
| sshnet/SSH.NET | f099365 | C# | 61 | 108 |
| dalek-cryptography/curve25519-dalek | 97a020d | Rust | 0 | 10 |
| emersion/go-msgauth | 704519e | Go | 6 | 8 |
| ecies/py | fb9f851 | Python | 10 | 12 |

A pair is (file, algorithm family), accepted, outside test folders. The 1.2.0 column is the committed version, after the fixes below. 1.2.0 removed no 1.1.0 pair.

## Method

1. Two random samples were drawn from the pairs 1.2.0 added: 60 with seed 0, then, after the first round of fixes, 40 more with seed 1 from the pairs not already drawn.
2. The developer (the assistant that develops Wolf Pack) read each pair's file and graded it:
   - **used:** the file uses or implements the family;
   - **declared:** the file only names it as supported, such as a TypeScript union type or a runtime support check;
   - **wrong.**

Every verdict and its reason is in `review.csv`. The reviewer was not blind and wrote the rules, which is a bias toward "used". The paper should say so.

## Result

| Sample | Used | Declared | Wrong |
|---|---:|---:|---:|
| 1 (60 pairs) | 47 | 9 | 4 |
| 2 (40 pairs) | 30 | 5 | 5 |
| **Both (100)** | **77** | **14** | **9** |

So 77% of the added pairs are used, and 91% are used or declared. Wolf Pack counts declared support by design (`registries`).

The nine errors had four causes, and all were fixed after the review:

- crate names in Rust attribute macros (`#[curve25519_dalek_derive::...]`);
- ECDH reported beside X25519 for `ecdh.X25519()`;
- JWK `kty: "oct"` read as AES;
- a key-exchange message class shared with the sntrup761x25519 hybrid.

One cause remains unfixed: BouncyCastle's `DsaDigestSigner` wrapping an ECDSA signer is still reported as DSA.

**These ten repositories are now tuned on as well** and are no longer evidence. Recall was not measured here, because the files are not labelled.

## Round 2: twelve larger repositories

Twelve larger repositories, none used before, were scanned to find what 1.2.0 still missed, and to measure its speed.

| Repo | Commit | Language | Files |
|---|---|---|---:|
| spring-projects/spring-security | c097292 | Java | 7127 |
| apache/shiro | 9a7bf22 | Java | 1237 |
| smallstep/certificates | 7d2e320 | Go | 549 |
| go-jose/go-jose | 25b55fe | Go | 90 |
| authlib/authlib | c529a61 | Python | 493 |
| sigstore/sigstore-python | 1952e05 | Python | 214 |
| digitalbazaar/forge | 7232404 | JavaScript | 158 |
| kjur/jsrsasign | c1b8432 | JavaScript | 543 |
| openssh/openssh-portable | ccc26c7 | C | 874 |
| libssh2/libssh2 | 2e17174 | C | 534 |
| openiddict/openiddict-core | fb2134b | C# | 1573 |
| rustls/rustls | 99f2358 | Rust | 1061 |

**Precision** (the developer's own review, as above):

- 80 random accepted pairs before this round: 73 used, 7 declared (OID tables, algorithm-constant files, headers), 0 wrong.
- The additions from this round:
  - 60 random pairs from `symbols` and the new API rules: 56 used, 3 declared, 1 wrong (`PSK_DHE_KE` read as finite-field DH).
  - All 12 pairs from the new `dh` name token: 7 used, 5 wrong. The wrong ones were an error name, a `#define`, header structs, and a profiler named `dh_runner`. Three of those four causes were fixed; `dh_runner` still matches.

**Recall.** Misses were found by listing every (file, family) where the held-out kit's independent name table matches the code but Wolf Pack reported nothing, then reading a random 70, and after the fixes another 60. The real misses were:

- all-caps constants used as values (`case KEY_ED25519:`, `kex[KEX_DH_GRP1_SHA1]`, `SSH_DIGEST_SHA256`, `crypto.SHA1`, rustls cipher-suite constants), now the `symbols` role;
- Go types of an imported crypto package (`*ecdsa.PrivateKey`);
- .NET `SecurityAlgorithms.RsaSha256`;
- Python `isinstance(k, rsa.RSAPublicKey)`;
- Diffie-Hellman functions (`ssh2_dh_init`).

The rest were comments, prose and false tokens in the table.

Pairs found, outside tests, went from 1,242 to 1,657 across the twelve repos. The 42 that were dropped are all `#define` lines and struct declarations in headers, mostly openssh's `pkcs11.h`, a table of PKCS#11 constants for algorithms openssh never uses.

**Speed.** The scan of spring-security fell from 210 s to 24 s, and openiddict from 50 s to 16 s. There were three causes:

- a regex compiled for every string literal (`concat`);
- one huge alternation of every cross-file constant name (`propagate`);
- a character-by-character lexer loop.

The lexer rewrite gives identical output on all 7,986 source files of these repos.

These twelve repositories are now tuned on too.
