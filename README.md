# Wolf Pack CBOM

A zero-setup scanner that inventories the cryptography in a codebase, its compiled artifacts and its live TLS and SSH endpoints, writes a CycloneDX 1.6 CBOM, and ranks what to migrate first for the post-quantum transition.

Pure Python, one dependency (`cryptography`), runs on Windows, macOS and Linux with Python 3.11 or newer.

## Quick start (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"          # gives you the `wolfpack` command; or: pip install -r requirements.txt

py -m wolfpack scan C:\path\to\repo
py -m wolfpack scan C:\path\to\repo --tls api.example.com:443 --ssh bastion.example.com
py -m wolfpack scan --tls api.example.com:443                 # endpoints only, no folder
py -m wolfpack scan . --shelf-life 15 --migration 6 --crqc-year 2033
py -m wolfpack scan . --fail-on critical                       # CI: exit 2 if anything critical
py -m wolfpack scan . --baseline main-cbom.json --fail-on high # CI: fail only on crypto added since main
py -m wolfpack bench bench\corpus
py -m unittest discover -s tests
```

Output lands in `wolfpack-out\`. `cbom.json` is the CycloneDX 1.6 CBOM, validated against the official schema. `report.html` is a self-contained report that works offline. `wolfpack.sarif` is SARIF 2.1.0 for GitHub code scanning. `findings.json` is the full audit trail, including everything the den rejected and why.

To silence a finding you have reviewed, put `wolfpack:ignore` in a comment on that line or the line above. Suppressed findings stay in the audit trail.

## How the pack works

Elders (`elders.py`) hold the knowledge: about 60 algorithms with OIDs, CycloneDX primitives, classical and NIST quantum security levels, NIST IR 8547 transition dates, hybrid PQ groups, and a replacement for each.

Scouts (`scouts/`) are deliberately aggressive and over-report.
Source: AST analysis for Python, and rules plus a code/comment/string lexer with constant propagation for Java/Kotlin, Go, JavaScript/TypeScript, C/C++ (OpenSSL), C# and Rust.
Config: nginx, Apache, HAProxy, sshd, openssl.cnf, Java/Spring properties, YAML, INI, TOML.
Artifacts: certificates, private and public keys, OpenSSH keys, PEM blocks embedded in code.
Binaries: exact algorithm constants (AES S-box, SHA-2 round constants, MD5 table, P-256 and secp256k1 primes, ChaCha20), embedded OpenSSL, LibreSSL, mbed TLS, wolfSSL and Go versions, and JCA constants inside JAR, WAR and class files.
Dependencies: pip, pyproject, npm, Maven, Gradle, go.mod, Cargo, NuGet, cross-checked against actual imports.
Live TLS: handshake, cipher suite, certificate, TLS 1.0/1.1 acceptance, and a pure-Python ClientHello probe that asks the server which key-exchange groups it accepts, so hybrid ML-KEM (X25519MLKEM768 and friends) is confirmed on the wire without needing OpenSSL 3.5 locally.
Live SSH: reads the server's key exchange, host key, cipher and MAC lists before login.

The den (`den.py`) sits between the scouts and the CBOM. Each sighting gets a confidence from its evidence type (live, artifact, config, call, constant, binary, identifier, import, bare string). Comments, docstrings and prose are rejected. Same-file corroboration from a different evidence type raises confidence. Anything under the threshold is held, not deleted.

The alpha (`alpha.py`) directs the second hunt and makes the call. It sends the den back to held string literals and promotes only those that flow into a crypto call, sit in an algorithm list of three or more entries (never a list named like `WEAK_` or `disabled`), or come from the same literal as an accepted sighting. It follows trails from keys and certificates to the configs and code that load them, so deployed material is weighted as deployed. It then tiers every asset: broken today, harvest-now-decrypt-later via Mosca's inequality, signature risk, Grover margin, or safe. It is hybrid-aware, weights by exposure (live endpoint, deployed config or key, compiled artifact, code), demotes test-only findings, and raises hygiene alerts such as committed private keys, certificates valid past 2030 on quantum-vulnerable keys, end-of-life OpenSSL, unmaintained libraries, and declared-but-unused ones.

The CBOM records evidence locations, confidence and rationale on every asset, which library provides which algorithm (CycloneDX 1.6 `provides`), certificates linked to their key and signature algorithms, key material, and live endpoints as services.

## Compared with IBM CBOMkit

CBOMkit's scanner (sonar-cryptography) does deep semantic analysis of Java (JCA, BouncyCastle), Python (pyca/cryptography) and Go, and needs a SonarQube instance. Wolf Pack trades some of that depth outside Python for breadth and zero setup: seven languages, configs, keys and certificates, binaries and JARs, dependency manifests, live TLS and SSH with on-the-wire PQ group detection, a verification layer with an audit trail, risk-based prioritisation, SARIF, and baseline-aware CI gating from one `pip install`.

## Evaluation so far

Development corpus: `bench/corpus` has 24 files across 7 languages plus configs, certificates, a compiled binary and manifests, full of traps (algorithms in comments, docstrings and log messages, a Java `disabledAlgorithms` list, OpenSSL `!MD5` exclusions, a `WEAK_ALGORITHMS` deny-list, an unused import, a suppressed line). Ground truth is 53 (file, algorithm) pairs.

| configuration | precision | recall | F1 |
|---|---|---|---|
| full pack | 1.000 | 1.000 | 1.000 |
| no second look | 1.000 | 0.962 | 0.981 |
| no den (raw scouts) | 0.757 | 1.000 | 0.862 |

This corpus was written alongside the scanner, so treat it as a regression test and ablation demo, not a result.

Unseen real code: pyjwt 2.9.0, node-jsonwebtoken 9.0.2, age 1.2.1 and paramiko 3.5.0, each scanned in under 2.5 seconds. Every accepted (file, algorithm) pair in non-test code was reviewed by hand: 98 pairs, 3 false positives (pyjwt listing SSH key-format names it uses only to detect key types), about 97% precision. This is a single, non-blind reviewer, and recall on these repos is not measured.

Live probes were verified against a real OpenSSL 3.5 server (hybrid X25519MLKEM768 detected), a classical OpenSSL server (correctly none), a paramiko SSH server, and github.com.

## Limitations

Only Python gets true AST analysis. Other languages use rules with intra-file constant propagation, which misses values passed across functions or files, reflection, and dynamically built names.

Key sizes and modes are found only when they are visible near the call; otherwise assets are reported without them (`AES` rather than `AES-256-GCM`).

Generic EC keys are assumed to be used for confidentiality, which errs toward over-prioritising.

Algorithm lists are treated as declared support. A list that only names formats for detection, as in pyjwt's SSH key sniffing, will be counted.

The binary scout misses constants that compilers emit as instruction immediates (OpenSSL's MD5 and SHA-1 initial values, for example), and finding an algorithm in a binary means it is implemented or linked, not necessarily used.

The TLS group probe relies on servers answering an empty key share with a HelloRetryRequest, as RFC 8446 requires. A non-conforming server may show no groups. TLS 1.2-only servers get no group list.

Containers, HSMs and cloud KMS configuration are not scanned yet. The CRQC year is an assumption you set; the default of 2035 mirrors the NIST IR 8547 disallow date, not a prediction.

## Development

See `CLAUDE.md` for architecture, conventions and the rules the bench must keep, and `docs/HANDOFF.md` for the project history. CI (`.github/workflows/ci.yml`) runs tests, the bench, a scan and CycloneDX schema validation on Windows and Linux.

## Layout

```
wolfpack/
  elders.py        knowledge base, NIST timeline, hybrid groups
  scouts/          source, pysrc (AST), rules, lexer, suites, config,
                   artifacts, binary, deps, tls, probe (raw TLS/SSH)
  den.py           verification, second look, registries, suppression
  alpha.py         tiers, Mosca, hybrid awareness, exposure, alerts
  cbom.py          CycloneDX 1.6, SARIF, audit trail
  report.py        HTML and terminal output
  pack.py          orchestration, key trails, baseline diff
  cli.py, bench.py
bench/corpus, bench/truth.json
tests/test_core.py
```
