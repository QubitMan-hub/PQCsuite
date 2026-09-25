# Wolf Pack vs IBM CBOMkit

First head-to-head run against CBOMkit (PQCA `cbomkit-action`, built on sonar-cryptography 1.7.0 and cbomkit-lib 1.3.0) on six real repositories, scored at (file, algorithm family) level. These repos are **unlabelled**, so this is an agreement study with a hand review of the disagreements. It does not measure precision or recall. It is not the blind benchmark planned in CLAUDE.md.

## Setup

CBOMkit scans Java, Python, Go and C#. `compare.py` keeps only files in those languages, and drops test files on both sides (`is_test`). CBOMkit ran with `CBOMKIT_EXCLUDE=""` so that the filter is the same for both tools. CBOMkit component names are mapped to Wolf Pack families with `elders.lookup` on the longest prefix: `ECDSA-SHA-256` becomes ECDSA and `EC-secp256r1` becomes ECC. CBOMkit emits the hash as its own component, which matches our convention.

| Repo | Commit | Build before the CBOMkit scan |
|---|---|---|
| auth0/java-jwt | 29f252b | Gradle 6.9 does not run on JDK 21, so `lib/` was compiled with `javac` against Jackson 2.17.2 |
| jwtk/jjwt | fb71496 | `mvn install -DskipTests` |
| jpadilla/pyjwt | 1d41a64 | none |
| paramiko/paramiko | 142f593 | none |
| mpdavis/python-jose | 018b310 | none |
| sybrenstuvel/python-rsa | 42b0e14 | none |

## Result

| Repo | Wolf Pack pairs | CBOMkit pairs | Both | Wolf Pack only | CBOMkit only |
|---|---:|---:|---:|---:|---:|
| java-jwt | 6 | 0 | 0 | 6 | 0 |
| jjwt | 51 | 7 | 2 | 49 | 5 |
| pyjwt | 21 | 1 | 1 | 20 | 0 |
| paramiko | 39 | 8 | 3 | 36 | 5 |
| python-jose | 25 | 2 | 2 | 23 | 0 |
| python-rsa | 12 | 0 | 0 | 12 | 0 |
| **Total** | **154** | **18** | **8** | **146** | **10** |

### The 10 CBOMkit-only pairs, reviewed by hand

- **5 CBOMkit false positives** in paramiko `kex_mlkem.py`: Ed25519, Ed448, X448, SHA-512 and SHAKE256 are all reported on the `mlkem.MLKEM768PrivateKey.generate()` lines. CBOMkit also misses the ML-KEM-768 that those lines create. Wolf Pack reports ML-KEM-768 and X25519 there, which is correct.
- **2 Wolf Pack misses** in jjwt `ConcatKDF.java` and `Pbes2HsAkwAlgorithm.java`, where AES is used through `new SecretKeySpec(bytes, AesAlgorithm.KEY_ALG_NAME)`. The constant is defined in another file, and Wolf Pack only propagates constants within a file for Java (CLAUDE.md next-work item 4).
- **3 convention differences** in jjwt `Keys.java`: `SecretKeySpec(bytes, "HmacSHA256")` and the 384/512 variants. CBOMkit reports HMAC and the SHA-2 hash; Wolf Pack reports HMAC only. Wolf Pack does emit the hash for `HS256` and `SHA256withRSA`, so it is inconsistent with itself here. This needs a labelling decision, not a quick fix.

### The 146 Wolf Pack-only pairs

By strongest evidence, **112 rest on string literals** and 34 on calls or imports. The literals are algorithm names in registries, enums, JWA identifier tables and SSH negotiation lists. Wolf Pack counts these as declared support; CBOMkit only reports what flows into a crypto API it models. Whether they count as true positives depends on the open labelling question in `docs/HANDOFF.md` ("how should declared-support lists be labelled?"). So this table **does not** show that Wolf Pack is more accurate. It shows that the two tools answer different questions about the same code.

One reviewer (not blind) checked every Wolf Pack-only pair:

- **1 bug, fixed in this commit series:** jjwt `RsaSignatureAlgorithm.java` builds `"SHA-" + digestBitLength`, and the `"SHA-"` prefix was read as SHA-1. The corpus now has a trap for it (`java/Digests.java`).
- **8 known false positives:** SSH key-format prefixes in pyjwt `utils.py` and python-jose `utils.py` (DSA, ECDSA, Ed25519, RSA in each). This is CLAUDE.md next-work item 3; python-jose has the same key-format list.
- The rest are direct use or declared support as described above.

### Current version (tuned on these repos)

Two changes made since the first run come from these six repos:
- **Stage 3** fixed the two Wolf Pack misses and the eight false positives found above, with cross-file constant propagation and the alpha's recognition check for format-sniffing lists.
- **The confirmed labelling convention** now counts the hash of an HMAC (`HmacSHA256` is HMAC and SHA-256), which turns the three convention pairs into agreements.

Because these fixes came from these six repos, the numbers below are **after tuning on them** and are no longer a fair comparison. The first run above is the untuned record. The fair test is the held-out benchmark in `eval/heldout/`.

| Repo | Wolf Pack pairs | CBOMkit pairs | Both | Wolf Pack only | CBOMkit only |
|---|---:|---:|---:|---:|---:|
| java-jwt | 6 | 0 | 0 | 6 | 0 |
| jjwt | 56 | 7 | 7 | 49 | 0 |
| pyjwt | 17 | 1 | 1 | 16 | 0 |
| paramiko | 39 | 8 | 3 | 36 | 5 |
| python-jose | 21 | 2 | 2 | 19 | 0 |
| python-rsa | 12 | 0 | 0 | 12 | 0 |
| **Total** | **151** | **18** | **13** | **138** | **5** |

The 5 remaining CBOMkit-only pairs are its false positives in paramiko `kex_mlkem.py`. Of the 138 Wolf Pack-only pairs, 104 rest on string literals and 34 on calls or imports.

### Things that make CBOMkit look worse than it may be

- **java-jwt returned 0 findings.** Its log warns about unresolved imports/types even with compiled classes in `lib/build/classes/java/main` and Jackson in `CBOMKIT_JAVA_JAR_DIR`. java-jwt passes the algorithm name through constructor fields (`Signature.getInstance(algorithm)`), and CBOMkit did not follow it. A real Gradle build might change the result.
- **python-rsa returned 0 findings.** It implements RSA in pure Python and never calls a library CBOMkit models, so this is expected behaviour, not a failure.
- **Timings are not comparable.** Wolf Pack also scans configs, certificates, manifests and every JAR in `target/`. jjwt took 7.9 s unbuilt and 26 s after the Maven build left JARs behind; CBOMkit took 20.6 s.

### Dev corpus (sanity check only)

On `bench/corpus`, limited to Java/Python/Go/C# non-test files, CBOMkit gets P 1.000, R 0.423 and Wolf Pack gets P 1.000, R 1.000. The corpus is overfit to Wolf Pack by construction (CLAUDE.md rule 3), so this only shows that the harness works. CBOMkit found nothing in `go/server.go`, which has no `go.mod`, and missed MD5, SHA-256 and 3DES in the Python files, ML-KEM/ML-DSA via liboqs, RSA in C#, and the `MGF1ParameterSpec("SHA-256")` in `java/Digests.java`. It did not fall for the `"SHA-" + bits` trap in that file either.

## Reproducing

Pulling `ghcr.io/cbomkit/cbomkit-action` is the easy path. Where GitHub Packages is unreachable, as in the cloud box used here, build it from source (JDK 21 and Maven 3.9):

```bash
git clone --depth 1 -b 1.7.0  https://github.com/cbomkit/sonar-cryptography
git clone --depth 1 -b v1.3.0 https://github.com/cbomkit/cbomkit-lib
git clone --depth 1           https://github.com/cbomkit/cbomkit-action
F="-B -q -DskipTests -Dspotless.check.skip=true -Dspotless.apply.skip=true -Dcheckstyle.skip"
(cd sonar-cryptography && mvn $F install)
(cd cbomkit-lib && mvn $F install)
(cd cbomkit-action && mvn $F package)          # target/CBOMkit-action.jar
```

Scan a repo with each tool, then compare:

```bash
GITHUB_WORKSPACE=$PWD/repo GITHUB_OUTPUT=$PWD/gh_out CBOMKIT_OUTPUT_DIR=$PWD/ck \
CBOMKIT_EXCLUDE="" CBOMKIT_GENERATE_MODULE_CBOMS=false CBOMKIT_JAVA_REQUIRE_BUILD=false \
  java -jar cbomkit-action/target/CBOMkit-action.jar
python -m wolfpack scan repo -o wp -q
python eval/cbomkit/compare.py repo --wolfpack wp/findings.json --cbomkit ck/cbom.json [--truth labels.json]
```

With `--truth` (same format as `bench/truth.json`), the script also prints precision, recall and F1 for both tools. That is the mode the blind held-out benchmark should use.
