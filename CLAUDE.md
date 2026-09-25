# CLAUDE.md

Guide for Claude Code working in this repo. Read this first, then `docs/HANDOFF.md` for the full history.

## What this is

Wolf Pack CBOM is a pure-Python scanner that inventories cryptography in source code, configs, keys and certificates, binaries and JARs, dependency manifests, and live TLS/SSH endpoints. It writes a CycloneDX 1.6 CBOM and ranks what to migrate first for the post-quantum transition. The goal is to be clearly better than IBM CBOMkit (sonar-cryptography) and to publish a paper on it.

Owner: Lakshmi Monish (QubitMan), CS student at BITS Pilani. He develops on Windows with PowerShell. He works one stage at a time, wants honest assessments including limitations, pushes back on overclaiming, and prefers code with minimal comments and no unnecessary lines.

Current version: 0.2.0. It was built in a Claude.ai chat, then moved here.

## Commands

```powershell
py -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python -m unittest discover -s tests -v          # 14 tests, must stay green
python -m wolfpack bench bench/corpus            # precision/recall + ablations
python -m wolfpack scan bench/corpus -o wolfpack-out
python scripts/validate_cbom.py wolfpack-out/cbom.json   # must report 0 errors
python -m wolfpack scan PATH --tls host:443 --ssh host --baseline old.json --fail-on high
```

Run tests, the bench, and schema validation after any change to scouts, den, alpha or cbom. Report the bench table before and after in your summary.

## Architecture (the wolf pack)

Data flows one way: scouts produce `Sighting`s, the den gives each a verdict, the den groups accepted sightings into `Asset`s, the alpha tiers the assets, and `cbom.py` writes the outputs.

```
wolfpack/
  model.py       Sighting, Library, Artifact, Asset dataclasses
  elders.py      knowledge base: CATALOG (~60 algos: family, CycloneDX primitive,
                 threat shor/legacy/grover/safe, bits, NIST level, OID, replacement),
                 aliases, lookup(), pq_from_text(), curve(), variant(), nist_status(), HYBRIDS
  scouts/        deliberately noisy; over-reporting is the design
    __init__.py  iter_files (SKIP_DIRS, BUILD_DIRS), rel, is_test, read
    lexer.py     splits code / comments / string literals per language family
    pysrc.py     Python AST scout: import aliasing, constant propagation, params, lib attribution
    rules.py     regex rules per language (java, go, js, c, csharp, rust); rule decorator
    source.py    runs rules on code and comments, constant propagation, string scout, classify_literal
    suites.py    TLS cipher suites, OpenSSL cipher strings (skips ! and -), SSH names, sig schemes
    config.py    nginx, Apache, HAProxy, sshd, openssl.cnf, properties, YAML/INI/TOML; DENY skips disabled lists
    artifacts.py certs, keys, OpenSSH keys, embedded PEM; OID maps incl. ML-DSA/ML-KEM
    binary.py    native constants, embedded lib versions, JAR/WAR class constants
    deps.py      manifests across 6 ecosystems, KNOWN crypto libs, usage cross-check
    probe.py     raw TLS ClientHello (empty key_share -> HelloRetryRequest reveals groups), SSH KEXINIT
    tls.py       live TLS scout (handshake, cert, legacy probes, groups) and SSH scout
  den.py         verification: confidence by evidence, hard rejects, corroboration, suppression,
                 second_look, registries, siblings, assets()
  alpha.py       Horizon (Mosca), tiers critical/high/medium/low/ok, hybrid awareness,
                 exposure weighting, test demotion, alerts, readiness
  pack.py        orchestration, follow_trails (key/cert references), baseline diff
  cbom.py        CycloneDX 1.6 builder (provides, services), SARIF 2.1.0, audit trail
  report.py      self-contained monochrome HTML report and terminal summary
  cli.py         scan / bench subcommands
  bench.py       scores at (file, algorithm family) granularity across 3 configs
bench/corpus     dev corpus with deliberate traps; bench/truth.json holds 53 labelled pairs
bench/fixtures-src  source for compiled corpus fixtures (legacy_tool.c)
scripts/validate_cbom.py  official CycloneDX 1.6 schema check (downloads schemas to .cache/)
tests/test_core.py
docs/HANDOFF.md  history, decisions, validation evidence, open questions
```

## Key concepts

Evidence types and base confidence (den.BASE): live 1.0, artifact .95, config .9, call .9, constant .85, binary .8, identifier .65, import .45, string .35. Params found add .05. Same-file corroboration from a different evidence type adds .25 (ECC/ECDSA/ECDH count as kin). Threshold is 0.6.

Verdicts: accepted, quarantined (held, still in findings.json), rejected (comment, docstring, prose, unknown algo), suppressed (`wolfpack:ignore` on the line or the line above).

Alpha second hunt: a held literal is promoted if it flows into a call, sits in an algorithm list of 3+ entries whose variable name is not deny-like (weak, disabled, deny...), or shares a literal with an accepted sighting.

Tiers: legacy, sub-112-bit, ECB, or MD5/SHA-1 signatures are critical when exposure is code or stronger. Shor-vulnerable confidentiality is high when shelf_life + migration > years to CRQC. Classical groups next to a configured hybrid group become medium "fallback". AES-192/256 is ok.

## Rules you must not break

1. Never edit `bench/truth.json` to make the detector look better. Labels follow what a human would say the file actually uses, at the family level (`CATALOG[algo].family`). If a label is wrong, say so explicitly and explain why.
2. Every new heuristic ships with a trap in the corpus that it must NOT fire on, plus a case it must fire on, plus a test.
3. The dev corpus is overfit by construction. Never present its numbers as a result. Real-world claims need unseen repos.
4. `cbom.json` must validate against CycloneDX 1.6 with 0 errors.
5. Pure Python, one runtime dependency (`cryptography`). No C extensions, no OpenSSL CLI calls. Must run on Windows (pathlib, utf-8 with errors="replace", no fork, no shell-specific behaviour).
6. Keep it simple. Prefer a small, well-tested rule over a framework. Minimal comments; docstrings only where the why is not obvious.
7. Don't overclaim. Distinguish "implemented in a binary" from "used", "declared support" from "called", and "assumed" (e.g. CRQC year, EC key use) from "observed".
8. `bench/corpus/certs/signing.key` is a deliberate test private key. It is not a secret. If GitHub secret scanning flags it, dismiss the alert as a test fixture.

## Adding things

New algorithm: add to `CATALOG` and `_ALIASES` in elders.py, then check lookup() with a quick one-liner.

New language rule: add a `@rule("lang", pattern)` function in rules.py returning `[(algo, params)]`, or `(algo, params, evidence)`. Use `x.attach(params, algos)` for parameters found near an earlier call. Add a corpus file and truth labels.

New scout: return a list of `Sighting`s with the right evidence type, and wire it into pack.run. Add its evidence type to den.BASE, den.RANK and alpha.EXPOSURE.

## Next work, in priority order

1. Held-out benchmark for the paper: 15 to 20 real GitHub repos across Java, Python, Go, JS, C and C#, labelled blind by someone other than the author before running any tool. Store under `eval/` (not bench/), with a labelling guide.
2. Head-to-head with CBOMkit on the Java/Python/Go subset: run sonar-cryptography via its Docker setup, convert both CBOMs to (file, family) pairs, and score both against the same labels.
3. Known false positive: algorithm lists used only for key-format detection (pyjwt `utils.py` SSH prefixes). Find a principled fix or document it.
4. Cross-file constant propagation for non-Python languages (currently intra-file only).
5. Container images (walk layers, reuse existing scouts) and cloud KMS/HSM config.
6. Recall measurement on real code.

Before starting any of these, propose a short plan and confirm with the owner. Work one stage at a time.
