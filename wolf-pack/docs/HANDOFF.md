# Handoff: how Wolf Pack CBOM got here

This project was built over one long Claude.ai chat session on 25 September 2026, then moved into this repo for Claude Code. This file records what happened, why things are the way they are, and what has actually been verified.

Current implementation and validation are summarized in [the project handoff](../../docs/AGENT-HANDOFF.md) and [Code Crawler](../../docs/CODE-CRAWLER.md). The dated history below is not the current roadmap or corpus count.

## Origin

The owner started with a "wolf pack" idea: wise elders lead at the front, aggressive young wolves come next, the vulnerable are protected in the middle, and the alpha watches from the back. The viral story behind it is a myth, and the Grey Wolf Optimizer (Mirjalili 2014) already exists, so the metaphor alone is not novel. It is useful as an architecture, though:

| Pack role | Component | Job |
|---|---|---|
| Elders | `elders.py` | Rule base: algorithms, OIDs, security levels, NIST IR 8547 dates, replacements |
| Young wolves (scouts) | `scouts/` | Aggressive discovery that over-reports on purpose |
| Protected centre (den) | `den.py` | Only verified findings get in; everything else is held with a reason |
| Alpha | `alpha.py` | Sends scouts back for a second look, follows trails, prioritises the hunt |

A quantum-computing version of the pack (classical priors, VQE/QAOA explorers, verified elite pool) was discussed and parked. The decision was to build the CBOM version first, because it can be measured against ground truth and compared with a named competitor, and a paper needs measurable results rather than a metaphor.

## The competitor

IBM CBOMkit's scanner is sonar-cryptography. It needs a running SonarQube instance and analyses source code only: Java (JCA, BouncyCastle), Python (pyca/cryptography) and Go, with C# in development and C/C++ in an unmerged PR. It has no config, certificate, binary, dependency or live endpoint scanning, and no risk prioritisation. It is semantically deeper than our regex rules for Java and Go, and that is the fair comparison point.

## Version history

v0.1: the core pack. It had a Python AST scout, regex rules for six more languages, config, artifact, dependency and basic live TLS scouts, the den with confidence scores and an audit trail, the alpha with Mosca-based tiers and hybrid awareness, CycloneDX 1.6 output, SARIF, an HTML report, CI gating and a trap-filled dev corpus.

v0.2 ("100x better, but don't overcomplicate") added:

- **Live TLS group probe:** a pure-Python ClientHello with an empty key_share. The server must answer with a HelloRetryRequest naming its chosen group, which reveals hybrid ML-KEM support without OpenSSL 3.5 on the scanning machine.
- **Live SSH probe:** reads the KEXINIT algorithm lists before authentication.
- **Binary scout:** exact algorithm constants, embedded library versions, and JCA constants in JAR/WAR class files.
- **Constant propagation:** now covers the C-like languages, not just Python.
- **Den additions:** algorithm-registry clusters (deny-lists excluded by variable name), shared fate for split literals such as "RS256" (RSA plus SHA-256), and `wolfpack:ignore` suppression.
- **Trail following:** a certificate referenced by nginx is weighted as deployed.
- **CBOM additions:** library `provides` relationships and live endpoints as services.
- **CI baseline mode:** `--baseline` so CI can fail only on newly introduced crypto.
- **Report and tests:** an endpoints table and baseline section in the report, and tests grown from 8 to 14.

## Session 2: moved to Claude Code (25 September 2026)

- **Bugs fixed, each with a regression test:**
  - the SSH probe looped forever when a server closed after its banner;
  - one corrupt JAR entry aborted the whole scan;
  - NuGet references without an inline version were dropped;
  - a config `key_size` blanked an ECDSA curve;
  - `[::1]` kept its brackets;
  - the `"SHA-" + bits` prefix was read as SHA-1 (found in jjwt).
- **CBOMkit head-to-head:** CBOMkit was built from source (no Docker) and run on six real repos. Harness and hand-reviewed results are in `eval/cbomkit/`.
- **Structure:** the second look and trail-following moved from den/pack into `alpha.py`, so each module is exactly one role. `pack.Roles` switches every role off individually, and `bench` prints one ablation per role (docs/PACK.md).
- **What the ablation exposed:**
  - Corroboration and siblings changed nothing on the corpus, so neither had a must-fire case. Adding one (`py/token_kind.py`) exposed a bug: siblings matched by source line, so an unrelated literal next to `"RS256"` was accepted. It now matches by literal.
  - Propagation's only family-level effect was masking another bug: `jwt.encode` assumed HS256 whenever it could not read the algorithm, including positional or unresolvable arguments (`py/jwt_calls.py`).
  - Propagation's real value is parameters (RSA-1024 vs RSA), which family-level scoring cannot see. Java integer constants are not propagated at all yet.

## Stage 3: closing the gaps CBOMkit exposed

- **Recognition (alpha):** a list whose entries are only searched for inside input data is format sniffing. It is never promoted, and `alpha.recognise` holds its entries back even when the den let them in through corroboration, which is what happened in pyjwt. This removed all 8 SSH-list false positives on pyjwt and python-jose.
- **Cross-file (scouts' shared memory):** `Owner.NAME` constants in Java, Kotlin and C#, exported Go `pkg.Name`, and `#define` in included C headers. A name with two different values is dropped. This recovered jjwt's two AES misses.
- **Integer constants:** these now propagate, but only from `final`/`const`/`readonly`/`#define` declarations. A reassigned local is left unknown on purpose.
- **Tuned status:** the six comparison repos are now "tuned on"; `eval/cbomkit/README.md` keeps the untuned first run.
- **Still open:** the HMAC-hash and SHA-512/256 labelling conventions, pending the owner.

## Conventions, pre-registration, fresh repos

- **Conventions:** the owner confirmed both labelling conventions (HMAC and KDFs count their hash; SHA-512/t is SHA-512) and signed off the held-out pre-registration. The scanner was aligned on the dev corpus only (`scouts.carried_hashes`, `elders.named_hash`, aliases). The held-out kit's vocabulary is frozen, so catalog growth cannot change what labellers write.
- **Fresh-repo check:** seven unseen repos, recorded in `eval/fresh/`. The first run had 13 of 16 pairs right (excluding Mozilla's TLS profile data, which is declared support), with 10 misses found by spot-check.
- **Fixes from it:**
  - libsodium rules (header prototypes excluded) and Salsa20;
  - `HMACSHA1` as HMAC;
  - JS literal completeness;
  - flow exclusions for flag and serialization-name calls.
- **Result after the fixes:** everything right on the six non-profile repos, with RSA/ECDSA via runtime names in node-jwa and the bcrypt implementation still missed. CBOMkit, run on the four repos in its languages, found nothing Wolf Pack missed except a random-number generator.

## Held-out labels and the 40-repo stress test

- **Labelling:** held-out labelling moved to AI under pre-registration amendment 1, because two human labellers were not available.
  - Labeller A (Opus) and labeller B (Sonnet) each labelled all 607 files in an isolated workspace. They agreed on 1,103 of 1,214 cells.
  - Three Opus adjudicators resolved the other 111 cells.
  - The labels were committed before any tool ran on the held-out repos (`52e3bac`).
  - A human audit of 63 sampled files is the last step before scoring.
  - Amendment 2 fixes the headline Wolf Pack version at `158d69f`, because the labellers' reports, which described some of their judgement calls, reached the assistant that develops the tool.
- **Stress test:** 40 new repositories, recorded in `eval/stress/`. There were no crashes and every CBOM was valid.
  - **New:** an implementation scout (constants), SM2/SM3/SM4/SHA-3, libsodium in C#, sjcl, commons-codec, extensionless configs, Go/C#/Python key-construction gaps, and test and benchmark directory detection.
  - **Result:** 542 pairs grew to 649 with none lost. CBOMkit's remaining extra pairs are all outside the labelling guide (RNGs, MGF1, internal hashes).

## Simplification pass

- **What changed:** the package went from 3,694 to 3,500 lines.
  - Language rules without logic are one-line `simple(...)` entries.
  - Tables that restated other tables are now derived: binary constants come from the implementation scout, certificate key OIDs from the elders, tier weights, evidence rank, library import markers, FFDHE sizes and PQ groups.
  - One deny-list pattern is shared by configs and algorithm lists.
  - Dead code and the duplicate CLI flags `--raw` and `--no-second-look` were removed (use `--without den` and `--without second-look`).
- **How it was checked:** a snapshot of every sighting, verdict, asset, tier and CBOM component on 54 roots (the dev corpus, the 6 comparison repos, the 7 fresh repos and the 40 stress repos, never the held-out set) was compared before and after each step.
  - **Only intended differences:** occurrence order inside 10 components, and the secp256k1 prime is now recognised in source as well as binaries (noble-curves, python-ecdsa).
  - The bench is unchanged and the CBOM validates with 0 errors.

## Design decisions worth knowing

Scoring is at (file, algorithm family) granularity, not line level, so labelling stays tractable. Signature schemes such as SHA256withECDSA, RS256 and certificate signatures emit the hash as its own finding, consistently everywhere.

Curve names are parameters, not algorithms. Early on "secp256r1" mapped to ECDH and produced a false positive, so curve names were removed from the ECDH aliases. Group and config parsers map curves to ECDH explicitly.

In code, the literal "ssh-rsa" is an SSH key-type name, so it yields RSA only. In negotiation lists (sshd config, live SSH) it means RSA with SHA-1 signatures, and SHA-1 is emitted there.

Deny-lists are judged by the variable name the list is assigned to, not by nearby comments. paramiko has a comment mentioning `disabled_algorithms` directly above its real cipher list, and reading the comment wrongly suppressed that list.

The binary scout walks `bin/`, `build/`, `dist/`, `target/` and `obj/`, because shipped artifacts live there. The source scouts skip those folders to avoid noise from generated code.

Generic EC keys are assumed to be used for confidentiality, which errs toward over-prioritising. TLS 1.3 next to a configured hybrid group is tier ok. The classical groups beside it are flagged as a fallback (medium), not as failures.

The default CRQC year of 2035 mirrors the NIST IR 8547 disallow date. It is an adjustable assumption, not a prediction.

## What has been verified, and how

CycloneDX 1.6: every generated CBOM validated against the official schema (bom-1.6, spdx, jsf) with 0 errors, including services and provides.

TLS group probe:

- A real OpenSSL 3.5.5 server (a Node 22 TLS server): X25519MLKEM768 correctly detected as preferred.
- A classical-only server: correctly reported no PQ groups.
- github.com: prefers X25519 and accepts X25519 and secp256r1, with no PQ.

A scripted HelloRetryRequest server is also used in the unit tests.

SSH probe: a paramiko 5.0 server's real KEXINIT was parsed correctly. It flagged 3des-cbc and hmac-md5/sha1 as critical, which is accurate for that server's offer list.

Binary scout:

- System libcrypto: AES, SHA-256/512, ChaCha20, P-256 and secp256k1 constants found, plus OpenSSL 3.0.13.
- The Node binary: OpenSSL 3.5.5 with ML-KEM and ML-DSA found.
- PDFBox 1.8 JAR: MD5, RC4, AES and SHA-1 found, which matches the PDF security handlers.
- Non-crypto JARs: no noise.

Dev corpus (24 files, 53 labels, overfit by construction): full pack P=1.000 R=1.000. Without the second look, R=0.962. Without the den, P=0.757.

Unseen real code: pyjwt 2.9.0, node-jsonwebtoken 9.0.2, age 1.2.1 and paramiko 3.5.0, each scanned in under 2.5 s. Every accepted (file, algorithm) pair in non-test code was hand reviewed. There were 98 pairs and 3 false positives, about 97% precision. The three FPs are pyjwt `utils.py` listing SSH key-format prefixes that it only uses to detect key types. This was a single reviewer (not blind), and recall was not measured.

## Bugs that real code exposed (all fixed, with tests or traps)

1. A local variable named `jwt` was treated as the PyJWT module. Now only imported names resolve to modules.
2. The SHA-256 half of "RS256" was held while the RSA half was accepted. Split literals now share fate.
3. There was no Go rule for `scrypt.Key`, `hkdf.New` or the `ed25519` types, so age's KDFs and keys were missed.
4. paramiko's cipher, MAC, kex and host-key negotiation lists were held as weak strings. They are now recognised as registries.
5. A comment near a list caused a false deny, so deny detection now reads the variable name only.
6. The `"AES_SALT"` field name was classified as AES. Symmetric-name parsing now requires the remaining tokens to be sizes or modes.

## Scoring, gaps closed, and 1.2.0 (28 September 2026)

- **Audit:** no person was available for the human audit. Amendment 3 replaced it with two checks (`eval/heldout/labels/SUPPORT.md`):
  - a mechanical label-support check: 355 of 393 `used` labels are named in their file's code; of the other 38, 18 are blind spots of the check, 19 are correct inferences and 1 is doubtful;
  - an AI audit of the 63-file sample: Dice 0.939 strict and 0.960 inclusive.
- **First scores** (strict):
  - headline 158d69f: P 0.886, R 0.336;
  - 1.1.0: P 0.820, R 0.430.

  Precision held up on unseen code. Recall did not: most misses were code named for its algorithm with no library API (`aes_encrypt`, `BCrypt.HashPassword`, `class HkdfSha256`), plus Noise and JOSE names, and hashlib functions passed as values.
- **1.2.0** was built from those misses:
  - the `names`, `symbols`, `concat` and `lists` roles;
  - Noise, JOSE and KMS formats, PyNaCl, JS imports and container images;
  - eight algorithms added to the catalog;
  - the flow look now follows byte literals and branches.

  Held-out (after tuning on held-out data): strict P 0.803, R 0.911, F1 0.853. Removing `names` drops recall to 0.646.
- **Generalisation check** (`eval/unseen/`): ten repos never used before. Of 100 random pairs that 1.2.0 adds, 77 are used, 14 declared and 9 wrong, by the developer's own review. The error causes were fixed after the review, so those repos are tuned on now too.
- **Round 2** (`eval/unseen/`, twelve larger repos): found the `symbols` gap and three slow spots. Large scans are up to 8x faster.
- **Next for the paper:** a second blind-labelled held-out set to measure 1.2.0 honestly; then the CBOMkit run for H1. Building CBOMkit from source in the cloud session was refused by the session's permission check.

## Known limitations

- **Analysis depth:** only Python has true AST analysis. Other languages rely on rules plus intra-file constant propagation.
- **Missing parameters:** key sizes and modes are recovered only when visible near the call.
- **Declared support:** algorithm lists count as declared support, including detection-only lists.
- **Binary constants:** compiler immediates (for example OpenSSL's MD5 and SHA-1 initial values) are missed, and "found in a binary" means implemented or linked, not necessarily used.
- **Group probe coverage:** the probe needs RFC 8446-conforming servers, and TLS 1.2-only servers get no group list.
- **Container images:** only `docker save` and OCI archives. Registries are not pulled, and zstd-compressed layers are skipped with a note.
- **Names:** the `names` role trusts code that names its algorithm. A class that only mentions one, such as a factory property returning `new Aes256Gcm()`, counts as used, which the held-out labellers sometimes called declared (nsec).

## Open questions for the paper

- **Evidence claims:** should the paper claim precision at file level, line level, or both? File level is what is labelled today.
- **Benchmark labels:** how should declared-support lists be labelled? That choice changes precision for JWT libraries noticeably.
- **Ablation shape:** the second-look ablation shows less effect since constant propagation was added. The ablation table may need to separate propagation, registries and second look.
- **Baseline for comparison:** a fair CBOMkit comparison should restrict to the languages and libraries it supports, and then report breadth separately.

## Other baselines (surveyed September 2026, none run yet)

- **OWASP cdxgen `--include-crypto`**: the most credible second baseline. It is the official CycloneDX generator, widely used, and emits CBOM components from Java (keystores, certificates) and JS/TS source (node:crypto, WebCrypto, JWT) using constant propagation. Easy to run on the held-out Java and JS repos.
- **CodeQL crypto queries via Santander's cryptobom-forge**: semantic analysis, like CBOMkit, but it needs a CodeQL database per repo. Worth adding if reviewers ask for a second semantic tool.
- **Scanners closest in scope, all small projects:**
  - `csnp/cryptoscan`: Go, regex with confidence scoring, its own CBOM format rather than CycloneDX.
  - `jimbo111/open-quantum-secure`: Go, 14 languages, configs, binaries, TLS/SSH, CycloneDX 1.7.
  - `TAIPANBOX/qryx`: code, binaries, images, TLS, KMS.
  - `CipherIQ/cbom-generator`: Linux filesystems, binaries, certificates and services, no source code.
  - They are useful to show breadth, but too young to carry a headline comparison.
- **Not comparable:** AWS CryptaMap and keycensus scan cloud KMS and HSM, not code. Crypto-misuse checkers such as CryptoGuard and CogniCrypt answer a different question.

## Demo and duplicate assets

- **Duplicate assets:** a bare sighting, such as an import, used to become its own asset next to its parameterised use, for example RSA beside RSA-2048 from the same file.
  - It now joins that variant when the file has exactly one variant of the algorithm (`den.assets`).
  - Sightings and the bench are unchanged. Across 54 roots, assets went from 722 to 718, and counts moved to the specific variants.
- **Site demo:** the "Watch a hunt" demo shows `site/demo/app.py` and the real output of `wolfpack hunt site/demo`. `test_site_demo_matches_the_pack` fails if the page drifts from what the pack reports on that file.


## Code Crawler integration (unreleased 1.3.0)

The repository-level `docs/CODE-CRAWLER.md` documents shared file enumeration, reused Python ASTs, bounded static migration relationships, private unified project scans, evidence limits and pinned real-project measurements. The 163-pair development regression corpus and every ablation match the preceding `8c81743` source; official CBOM schema validation has zero errors. This is not a new accuracy claim or a new detector heuristic. See `docs/AGENT-HANDOFF.md` for final validation and remaining product work.


## Optional web ASTs and scoped repository onboarding

The 1.3.0 checkout now has optional Tree-sitter JavaScript/TypeScript adapters feeding the same graph index and impact walk as Python. Package/CommonJS aliases preserve supported public-entrypoint caller chains. Base dependency behavior and crypto detectors remain intact; unsupported/deep/malformed syntax reports gaps. Root `docs/CODE-CRAWLER.md` and `docs/AGENT-HANDOFF.md` contain pinned seven-project runs, regression/privacy/failure checks, source audit, scoped Add repository and remaining limits. CI uses pytest and enables optional parser fixtures. No native parser requirement was added to the base package.
