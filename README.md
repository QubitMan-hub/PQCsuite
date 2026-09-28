# Wolf Pack CBOM

A zero-setup scanner that inventories the cryptography in a codebase, its compiled artifacts and its live TLS and SSH endpoints, writes a CycloneDX 1.6 CBOM, and ranks what to migrate first for the post-quantum transition.

Pure Python, one dependency (`cryptography`), runs on Windows, macOS and Linux with Python 3.11 or newer.

Project site: [`site/index.html`](site/index.html), a single self-contained page. Open it locally, or serve it with GitHub Pages from the `site/` folder.

## Quick start (PowerShell)

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"          # gives you the `wolfpack` command

py -m wolfpack scan C:\path\to\repo
py -m wolfpack scan C:\path\to\repo --tls api.example.com:443 --ssh bastion.example.com
py -m wolfpack scan --tls api.example.com:443                 # endpoints only, no folder
py -m wolfpack scan . --shelf-life 15 --migration 6 --crqc-year 2033
py -m wolfpack scan . --fail-on critical                       # CI: exit 2 if anything critical
py -m wolfpack scan . --baseline main-cbom.json --fail-on high # CI: fail only on crypto added since main
py -m wolfpack hunt . --without den                          # ablation: leave a member of the pack out
py -m wolfpack bench bench\corpus                            # full pack plus one ablation per role
py -m unittest discover -s tests
```

Output lands in `wolfpack-out\`. `cbom.json` is the CycloneDX 1.6 CBOM, validated against the official schema. `report.html` is a self-contained report that works offline. `wolfpack.sarif` is SARIF 2.1.0 for GitHub code scanning. `findings.json` is the full audit trail, including everything the den rejected and why.

To silence a finding you have reviewed, put `wolfpack:ignore` in a comment on that line or the line above. Suppressed findings stay in the audit trail.

## Install and run

| Where | How |
|---|---|
| Any machine with Python 3.11+ | `pip install .` from this folder (or the wheel from CI), then `wolfpack scan PATH` |
| Docker | `docker build -t wolfpack .`, then `docker run --rm -u "$(id -u):$(id -g)" -v "$PWD:/scan" wolfpack scan .` |
| GitHub Actions | the Action in this repository, below |

The code never leaves the machine that runs the scan. Only `--tls` and `--ssh` open network connections, to the endpoints you name.

### GitHub Actions

```yaml
permissions:
  contents: read
  security-events: write          # for code scanning; drop it with upload-sarif: false
steps:
  - uses: actions/checkout@v4
  - uses: QubitMan-hub/WolfPack-CBOM@main
    with:
      fail-on: critical           # empty never fails the build
      # baseline: cbom-main.json  # then only cryptography added since it fails
      # args: --tls api.example.com:443 --exclude generated
```

Findings appear in the repository's code scanning alerts, and the whole output folder is attached to the run as the `wolfpack` artifact. Code scanning on private repositories needs GitHub Advanced Security; without it, set `upload-sarif: "false"`.

### Settings file

Put `.wolfpack.toml` in the scanned folder, or pass `--config FILE`. Keys are the long option names with underscores. Options on the command line win; `exclude`, `tls` and `ssh` add to the file's lists.

```toml
exclude = ["generated", "*.min.js", "docs/archive/*"]   # a name, or a path from the root
fail_on = "high"
shelf_life = 15          # years your data must stay secret
migration = 6            # years your migration will take
crqc_year = 2035
tls = ["api.example.com:443"]
ssh = ["bastion.example.com"]
```

`vendor/`, `node_modules/`, virtual environments and build output are skipped unless you pass `--include-vendor`. Files over 2 MB are skipped, except binaries and archives (up to 256 MB).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan finished; nothing at or above `--fail-on` (or no `--fail-on`) |
| 1 | The scan could not run: a mistyped option, a missing folder, an unreadable or invalid settings file |
| 2 | Something at or above `--fail-on`; with `--baseline`, only what is new counts |

An endpoint that cannot be reached is reported in the output and the report, and does not change the exit code.

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

Every role can be left out of a hunt (`--without den`, `--without second-look`, `--without config`, and so on), and `wolfpack bench` runs one ablation per role. [docs/PACK.md](docs/PACK.md) maps each role to its module, its switch and what it contributes.

## Compared with IBM CBOMkit

CBOMkit's scanner (sonar-cryptography) does deep semantic analysis of Java (JCA, BouncyCastle), Python (pyca/cryptography) and Go, and needs a SonarQube instance. Wolf Pack trades some of that depth outside Python for breadth and zero setup: seven languages, configs, keys and certificates, binaries and JARs, dependency manifests, live TLS and SSH with on-the-wire PQ group detection, a verification layer with an audit trail, risk-based prioritisation, SARIF, and baseline-aware CI gating from one `pip install`.

## Evaluation so far

Development corpus: `bench/corpus` has 55 files across 7 languages plus configs, certificates, a compiled binary and manifests. It is full of traps:
- algorithms in comments, docstrings and log messages;
- a Java `disabledAlgorithms` list, OpenSSL `!MD5` exclusions and a `WEAK_ALGORITHMS` deny-list;
- an unused import and a suppressed line;
- a digest name built at runtime (`"SHA-" + bits`), and an unrelated literal on the same line as `"RS256"`;
- a `jwt.encode` whose algorithm cannot be resolved;
- an SSH key-prefix list used only to sniff formats;
- a same-named constant in the wrong class, and a reassigned local key size;
- a JS `'sha' + bits`, a command-line flag named `ecdsa`, a JSON field named `hmac`, libsodium prototypes in a header and in C# P/Invoke;
- MD5 initial values that must not read as SHA-1, prose that looks like an SSH directive, benchmark labels, and `getDigest(name)` with a variable name.

Ground truth is 100 (file, algorithm family) pairs.

| configuration | precision | recall | F1 |
|---|---|---|---|
| full pack | 1.000 | 1.000 | 1.000 |
| without den | 0.781 | 1.000 | 0.877 |
| without corroboration | 1.000 | 0.990 | 0.995 |
| without second look | 1.000 | 0.960 | 0.980 |
| &nbsp;&nbsp;without flow | 1.000 | 0.990 | 0.995 |
| &nbsp;&nbsp;without registries | 1.000 | 0.980 | 0.990 |
| &nbsp;&nbsp;without siblings | 1.000 | 0.990 | 0.995 |
| without recognition | 0.971 | 1.000 | 0.985 |
| without propagation | 1.000 | 0.990 | 0.995 |
| without cross-file | 1.000 | 0.990 | 0.995 |
| without source scouts | 1.000 | 0.320 | 0.485 |
| without implementation scouts | 1.000 | 0.960 | 0.980 |
| without config scouts | 1.000 | 0.770 | 0.870 |
| without artifact scouts | 1.000 | 0.970 | 0.985 |
| without binary scouts | 1.000 | 0.980 | 0.990 |

This corpus was written alongside the scanner, so treat it as a regression test and ablation demo, not a result. Propagation also recovers parameters (RSA-1024 rather than RSA), which family-level scoring does not see.

Unseen real code: pyjwt 2.9.0, node-jsonwebtoken 9.0.2, age 1.2.1 and paramiko 3.5.0, each scanned in under 2.5 seconds. Every accepted (file, algorithm) pair in non-test code was reviewed by hand: 98 pairs, 3 false positives, about 97% precision. The 3 were pyjwt listing SSH key-format names it uses only to detect key types; the alpha's recognition check has since removed them. This was a single, non-blind reviewer, and recall on these repos was not measured.

Seven more unseen repos (mkcert, itsdangerous, node-jwa, patrickfav/bcrypt, minisign, Mozilla's ssl-config-generator, SecureStore) were checked by hand in [eval/fresh](eval/fresh/README.md). The first run had 13 of 16 pairs right, with 10 misses found by spot-check. The fixes that followed are listed there. On the four repos in CBOMkit's languages, Wolf Pack found every algorithm pair CBOMkit found.

A 40-repo stress test across seven languages is in [eval/stress](eval/stress/README.md). All 40 scanned without a crash and with valid CBOMs; the misses and false positives it exposed were fixed. After the fixes, CBOMkit found nothing on those repos that the labelling guide would count as a Wolf Pack miss. These repos are tuned on, so none of this is evidence of accuracy.

The real held-out test is being prepared in [eval/heldout](eval/heldout/README.md): 18 pinned repositories, to be labelled blind before any tool runs on them.

A first head-to-head against IBM CBOMkit on six real repositories, with a hand review of every disagreement, is in [eval/cbomkit](eval/cbomkit/README.md). Those repos are unlabelled, so it is an agreement study, not a precision or recall result.

Live probes were verified against a real OpenSSL 3.5 server (hybrid X25519MLKEM768 detected), a classical OpenSSL server (correctly none), a paramiko SSH server, and github.com.

## Limitations

Algorithms implemented in source are recognised by their published constants (MD5, SHA-1, SHA-2, SHA-3, SM3, SM4, AES, DES, SM2, P-256). Implementations without such tables, such as most Curve25519, ChaCha20 and Blowfish code, are not.

Only Python gets true AST analysis. Other languages use rules plus constant propagation: within a file, and across files for `Owner.NAME` constants in Java, Kotlin and C#, exported Go constants, and C header macros. Values passed through function parameters, JavaScript imports, reflection and dynamically built names are still missed.

Key sizes and modes are found only when they are visible near the call; otherwise assets are reported without them (`AES` rather than `AES-256-GCM`).

Generic EC keys are assumed to be used for confidentiality, which errs toward over-prioritising.

Algorithm lists are treated as declared support. Lists used only to sniff formats are recognised when the code searches for their entries inside input data (`startswith`, `in`, `HasPrefix`); a sniffer written some other way will still be counted.

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
