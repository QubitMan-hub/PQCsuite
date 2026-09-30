# Code Crawler and one project scan

Run from the checkout with Python 3.11+ (use the project's interpreter or newer):

```sh
pip install ./wolf-pack '.[scan]'
pqcsuite scan ./payments-api --out pqcsuite-out --open
pqcsuite console --project ./payments-api --project-history project-history.json
```

Wolf Pack 1.3.0 is the scanner version in this checkout. It has not been published by this change. A base PQCsuite installation keeps scanning optional and gives an installation message when the capability is missing.

The console's Readiness page puts **Scan project** first when folders are registered. Pick a folder and scan once. The result shows crypto assets, priorities, supported functions/callers, evidence limits and completion time. Search and filter the migration queue; inspect a finding's affected code. Assessment and relationship JSON can be downloaded. Endpoint probing remains a separate explicit action, because a source finding cannot establish the state of a deployed endpoint.

## Pipeline and evidence

One file snapshot feeds the existing Wolf Pack scouts. Python ASTs already parsed by the crypto detector also feed Code Crawler; there is no second Python parser or new runtime dependency. Accepted findings are attached to enclosing function bodies. Supported lexical and cross-module references provide reverse caller chains. Names, relative locations, imports, class bases, symbols and references form `relationships.json`.

Direct definitions, aliases, conventional `src` layouts, relative imports, nested functions and async functions are supported. Parameter/reassignment shadowing, duplicate definitions, wildcard imports, anonymous callbacks and dynamic method dispatch remain unresolved. Default argument and decorator expressions are not attributed to the function body. Other languages retain Wolf Pack's existing detectors but do not get Python relationship coverage. A static chain is evidence of a source reference, not proof of runtime reachability, business ownership or protection.

Traversal skips vendor/cache/output folders and symlinks and honors Git's tracked-file/ignore rules. Git filesystem-monitor hooks are disabled. If Git is unavailable or the folder is not a repository, the ordinary directory/exclusion rules apply; standalone `.gitignore` parsing is not provided. Default source input size remains 2 MB per file. Compiled artifacts retain their existing separate size/build-directory rules. Oversized/unparseable source is reported by existing scanner notes.

Graphs cap symbols at 20,000, calls/imports at 100,000 each, and each reverse impact walk at 500 symbols. Partial graph/impact flags remain visible. The file snapshot stores paths and sizes only. Fresh scans intentionally reread source: no persistent customer-source cache or uncertain invalidation scheme was added. Scan cost still includes file detection and AST parsing; these limits do not impose a whole-project CPU/time quota.

## Privacy, exports and history

No project code is executed, uploaded, or sent to an AI service. Unified scans remove source snippets and raw source literals before writing reports. The standalone `wolfpack` audit retains its existing detailed findings behavior. Algorithm names, key sizes and other security parameters remain available for assessment. Even sanitized results contain file/symbol names and certificate or dependency metadata: treat them as private.

CLI output includes `report.html`, `cbom.json`, `wolfpack.sarif`, `findings.json`, `relationships.json` and `assessment.json`. Individual files are published atomically with owner-only permissions on POSIX; this is not a transaction across the entire output folder. User-selected output/history paths inside the scan root are excluded from that scan. The default `pqcsuite-out` is excluded across ordinary scans.

Optional history stores the last 100 project/time/summary records, caps input at 1 MB, and uses private atomic writes. Keep one writer per history file; cross-process history merging is not implemented. Full console results remain in memory and clear with process restart; history is an operator artifact, not a fleet database or identity/RBAC system. Browsers can request only administrator-registered folder IDs. Scans have real stage messages, no fabricated percentage or automatic endpoint probes.

## Measured validation

Pinned public repositories were cloned and scanned statically; their code and dependencies were not executed or installed. These are single runs on the prepared Linux/Python 3.12 host, not universal performance claims. Peak RSS includes the Python process and existing scanner.

| Project and commit | Python files | Functions | Resolved / observed calls | Crypto assets | Seconds | Peak RSS KiB |
|---|---:|---:|---:|---:|---:|---:|
| Paramiko `142f593e40ad767c5e3556cbace66dc84589620c` | 70 | 1,446 | 930 / 7,773 | 45 | 1.45 | 40,752 |
| ItsDangerous `672971d66a2ef9f85151e53283113f33d642dabd` | 15 | 115 | 59 / 372 | 5 | 0.10 | 26,908 |
| PyJWT `b5bd6fe6d7ac0370ba90557c7a1e3d50a9414572` | 26 | 545 | 604 / 2,853 | 19 | 0.62 | 36,600 |
| CryptoJS `ac34a5a584337b33a2e567f50d96819a96ac44bf` | 0 | 0 | 0 / 0 | 17 | 0.52 | 27,392 |

No graph cap was hit. Real-repository counts measure successful processing, not precision/recall: these projects have no complete independent call/crypto truth labels. Existing Wolf Pack benchmark/held-out tooling remains the path to a labeled accuracy study. CryptoJS explicitly demonstrates language limits rather than claiming a complete graph.

Focused fixtures verify RSA wrappers across modules, ECDSA, ECDH, AES, SHA, TLS and ML-KEM impact, aliases/relative/nested/async references, shadowing, ambiguous definitions, deferred expressions, malformed/mixed-language files, Git ignores, binary retention, hook suppression, private exports, registered API paths, bounded history and retryable errors. Browser validation includes a real project scan and graph download alongside existing console and mobile/accessibility tests.

### Detector regression baseline

The 163-pair development corpus is a regression fixture, deliberately tuned on. Its numbers are not real-world accuracy evidence. Baseline source was exported from `8c81743`; all 20 full/ablation configurations matched after this change.

| Development fixture check | Before | After |
|---|---:|---:|
| Full-pack false positives | 0 | 0 |
| Full-pack false negatives | 0 | 0 |
| Full-pack precision / recall / F1 | 1 / 1 / 1 | 1 / 1 / 1 |

Official CycloneDX 1.6 validation reported zero schema errors on the unified scan CBOM. Full Python validation passed 339 tests with 12 prerequisite skips; all 33 browser tests passed. Both built wheels were installed into a fresh virtual environment and the local project CLI ran successfully there. Ruff, basic mypy (58 source files), dependency consistency, doctor, the existing CBOM baseline gate and repeatable site publishing passed.

## Minimal-code audit

Compared with `8c81743`, production source in `pqcsuite`, `wolf-pack/wolfpack`, `site` and `scripts` grows from 70 to 72 files, 61 to 63 Python files and 12,867 to about 13,250 nonblank lines. The feature adds two focused modules rather than a framework. Initial wheels grow from 166,656 to 171,051 bytes (suite) and 132,851 to about 137,002 bytes (scanner). Each package still has one direct required runtime dependency; the suite adds the existing scanner as an optional extra.

The simplification is fewer duplicated responsibilities: one directory enumeration per scan, one Python AST shared with the existing detector, one report writer reused by both CLIs, and one customer project action instead of scan/export/manual-CBOM-import. Cryptographic implementations, protocol adapters and standalone forensic exports remain intact. No artificial line-count reduction or security-sensitive rewrites were used. Embedded assets in offline reports and separate package/site distributions are intentional, not dead duplicates.

## Remaining work

Language-specific graphs beyond Python, verified deployment/workflow mapping, signed desktop installers, shared fleet storage/RBAC, cancellation/resource quotas and independent security review remain separate work. Privileged VPN dataplane, live cloud/Kubernetes and long-duration reliability validation require their real environments. This change does not establish market superiority or eliminate those release gates.

Repository workflow skill: [PQCsuite project scan](../.agents/skills/pqcsuite-project-scan/SKILL.md).
