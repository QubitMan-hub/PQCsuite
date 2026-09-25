# Handoff: how Wolf Pack CBOM got here

This project was built over one long Claude.ai chat session on 25 September 2026, then moved into this repo for Claude Code. This file records what happened, why things are the way they are, and what has actually been verified.

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

## Known limitations

- **Analysis depth:** only Python has true AST analysis. Other languages rely on rules plus intra-file constant propagation.
- **Missing parameters:** key sizes and modes are recovered only when visible near the call.
- **Declared support:** algorithm lists count as declared support, including detection-only lists.
- **Binary constants:** compiler immediates (for example OpenSSL's MD5 and SHA-1 initial values) are missed, and "found in a binary" means implemented or linked, not necessarily used.
- **Group probe coverage:** the probe needs RFC 8446-conforming servers, and TLS 1.2-only servers get no group list.
- **Not yet scanned:** containers, cloud KMS and HSMs.

## Open questions for the paper

- **Evidence claims:** should the paper claim precision at file level, line level, or both? File level is what is labelled today.
- **Benchmark labels:** how should declared-support lists be labelled? That choice changes precision for JWT libraries noticeably.
- **Ablation shape:** the second-look ablation shows less effect since constant propagation was added. The ablation table may need to separate propagation, registries and second look.
- **Baseline for comparison:** a fair CBOMkit comparison should restrict to the languages and libraries it supports, and then report breadth separately.
