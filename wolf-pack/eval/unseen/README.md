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
