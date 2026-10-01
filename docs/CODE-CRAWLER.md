# Code Crawler and repository readiness

From a source checkout:

```sh
pip install './wolf-pack[crawler]' '.[scan-web]'
pqcsuite scan ./payments-api --out pqcsuite-out --open
pqcsuite console --repositories ./repositories --project-history project-history.json
```

The administrator selects a local parent folder once. Customers choose **Add repository**, scan, review exposure and migration candidates, then inspect the affected modules and recommended action. Only immediate child folder names are accepted; absolute paths, traversal, hidden names and symlinks are rejected. `--project PATH` remains available for individual authorized folders. Registration is local to the running console; source folders are not cloned, installed, uploaded or executed.

The default queue focuses on accepted production assets. Advanced views expose test-only/declared assets, language/file coverage, unresolved calls and JSON downloads. History summaries survive console restarts. Source findings and endpoint observations remain distinct evidence; no code-to-deployment mapping or universal readiness score is invented.

Wolf Pack 1.3.0 is checkout code, unreleased by this change. For a base Python-only installation use `./wolf-pack` and `.[scan]`. Web relationships add three optional dependencies: Tree-sitter plus JavaScript/TypeScript grammars, with native bindings. No new required runtime dependency was added to either package.

## One shared pipeline

One file snapshot feeds existing Wolf Pack detectors. Python crypto discovery shares its AST with Code Crawler; JavaScript/TypeScript source already read by the scanner feeds optional syntax-tree adapters. Both adapters normalize into one symbol/import/call/alias index and one reverse impact walk. The existing crypto detectors still establish algorithms, confidence, tier and remediation; graph context adds supported functions, callers and modules. This avoids building a second crypto scanner.

Files → modules → classes → functions → calls/imports → crypto evidence → migration action. Dependency references and Python package re-exports/direct CommonJS aliases preserve supported public-entrypoint chains. Caller references establish source relationships, not runtime reachability or business ownership. Real method dispatch, proxies, ES export-star/barrel chains, callbacks and arbitrary computed expressions require review. Constructors and inheritance are not expanded into runtime dispatch graphs.

Malformed optional-parser syntax and analysis-depth failures retain existing crypto findings while reporting a relationship gap. Missing optional parsers retain the base scan and explicit missing-language counts. Unsupported languages such as Go, C/C++, Java and Rust keep their existing detectors, with no relationship adapter claimed.

Traversal honors Git ignore/tracked rules, default exclusions and explicit scope, disables Git filesystem-monitor hooks, and skips symlinks. Compiled artifacts retain their distinct build-folder/size handling. Without Git the regular directory/exclusion rules apply; standalone `.gitignore` parsing is not provided. Source size remains 2 MB per file. Graph limits are 20,000 symbols, 100,000 calls/imports/aliases each, 20 alias hops, and 500 symbols per reverse caller walk. Limits/cycles do not establish complete reachability. There is no persistent source cache or whole-project time/memory quota.

## Shared storage and privacy

Private atomic writes, Windows sharing retries and reentrant process/thread locks live in `pqcsuite.storage`, reused by CA state and project history. Existing PKI imports remain compatible. History append/read uses a named lock, bounded reads and the last 100 project/time/summary records, preventing competing writers from losing records. Invalid history does not discard a successful scan. The console reads persisted summaries and reports history errors separately.

Individual reports are written atomically, with owner-only POSIX permissions; this is not a transaction over the complete folder. Unified exports remove source snippets and raw source literals; algorithm names, key sizes, certificate/dependency metadata and symbol/file names remain assessment evidence and should be treated as private. Standalone Wolf Pack retains its forensic audit behavior. Output/history paths inside a project are excluded from that scan. Progress polling fetches small job status instead of repeatedly transferring full graphs.

One report writer now serves both CLIs without making the suite load Wolf Pack's command parser. Offline reports, CBOM, SARIF, raw findings, relationship JSON and unified assessment JSON retain their formats/functionality. Fleet identity/RBAC and a shared fleet database remain separate work.

## Validation and accuracy boundaries

Pinned public projects were cloned and scanned statically. Their code and dependencies were not executed or installed. These are single Linux/Python 3.12 runs, not universal performance/accuracy claims. RSS includes the interpreter and existing scanner.

| Project and commit | AST files by language | Functions | Resolved / observed calls | Crypto assets | Seconds | Peak RSS KiB |
|---|---|---:|---:|---:|---:|---:|
| node-jsonwebtoken `b924272f29192e12926b5414546f7c5bfcc9579d` | JavaScript: 46 | 30 | 59 / 370 | 18 | 0.42 | 28772 |
| paramiko `142f593e40ad767c5e3556cbace66dc84589620c` | Python: 70 | 1446 | 1114 / 7773 | 45 | 1.51 | 39868 |
| jose `55c959fd16852462498b0d82c52c4eca07d48f26` | JavaScript: 17, TypeScript: 122 | 371 | 753 / 2513 | 42 | 1.71 | 37480 |
| itsdangerous `672971d66a2ef9f85151e53283113f33d642dabd` | Python: 15 | 115 | 59 / 372 | 5 | 0.11 | 25784 |
| pyjwt `b5bd6fe6d7ac0370ba90557c7a1e3d50a9414572` | Python: 26 | 545 | 647 / 2853 | 19 | 0.79 | 35364 |
| golang-jwt `73c870b18e68b6e654b2b03f485aa3c9fab32cea` | no supported AST files | 0 | 0 / 0 | 17 | 0.29 | 25836 |
| crypto-js `ac34a5a584337b33a2e567f50d96819a96ac44bf` | JavaScript: 105 | 6 | 3 / 117 | 17 | 0.62 | 28004 |

All seven runs completed. Go intentionally has no AST relationships; CryptoJS anonymous wrappers also limit relationships despite valid parsing. Shell files in ItsDangerous/Jose explicitly report unsupported relationship coverage. There is no independent complete truth set for these repositories, so their counts do not establish precision or recall. Existing labeled/held-out tooling remains available for accuracy studies.

Focused fixtures cover RSA/ECC/ECDSA/ECDH/AES/SHA/TLS/ML-KEM, aliases, Python package and CommonJS re-exports, ES imports/default exports, TypeScript arrows, classes, parameter shadowing, private exports, cycles, deferred expressions, directory/dotted imports, malformed/deep syntax, missing parsers, Git ignores/hooks, private artifacts, scope restrictions, concurrent history and retryable failures. Browser tests exercise actual Python and TypeScript scans, scoped Add repository, advanced evidence and exports, history, mobile layouts and accessibility.

The 163-pair development corpus is a tuned regression fixture, not real-world accuracy evidence. Every full/ablation configuration matches the previous classifier results: full-pack FP/FN remain 0/0. Full Python validation: 359 passed, 12 prerequisite skips, plus final focused regressions. Browser validation covers 35 cases, including cold-start onboarding. Both built wheels were installed in an isolated environment: the base package scanned JavaScript with explicit missing-parser coverage, then parser extras enabled TypeScript relationships. Ruff, basic mypy (60 source files), pip check, doctor, production CBOM baseline and repeatable publishing passed. A targeted vulnerability audit of the three installed parser dependencies found no known vulnerabilities. Official CycloneDX 1.6 schema validation reports zero errors. CI now runs pytest and provisions optional parser fixtures; previous unittest discovery did not execute function-style crawler/project tests. Existing targeted privileged protocol checks remain intact.

## Whole-repository audit and minimal complexity

The final repository scan is kept outside the checkout. It includes intentional weak examples, detector corpora, tests and catalogs; its findings are evidence for review, not automatically production vulnerabilities. Existing reviewed `docs/cbom.json` baseline gating is also checked against production `pqcsuite`.

Static unused-symbol checking found only unused exception parameters required by context-manager interfaces, not confirmed dead callables. They were retained. Unused imports and CLI/report coupling were removed. Storage implementation moved once, with compatibility imports, instead of adding a separate history-locking framework. Source adapters share graph resolution and impact; existing regex/config/binary detectors remain necessary for their supported inputs and were preserved.

Current source measurement: 74 production source files; 65 Python files; 13603 nonblank production lines. Previous pass: 72 source files, 63 Python files and about 13,250 nonblank lines. New AST and onboarding capabilities add code; this is a complexity/consolidation improvement, not a claimed net line-count reduction. Embedded offline assets and independently packaged branding copies remain intentional. Required runtime dependencies remain one per package; parser/testing extras are explicit.

## Remaining release work

Additional language AST adapters, verified runtime/deployment mapping, hard process isolation/incremental scans, signed desktop installers, fleet identity/RBAC and external fleet storage remain open. Privileged real VPNs, cloud/Kubernetes, long-duration reliability and independent security review require their real environments. This change does not claim market superiority or completion of those release gates.

Repository workflow: [project scan skill](../.agents/skills/pqcsuite-project-scan/SKILL.md).


## Persistent remediation workspace

The console now saves registrations inside the currently approved parent, full latest assessments, up to 30 summary/comparison records per project, owners, due dates and expiring exceptions. Default: `.pqcsuite/projects.json`; override with `--project-state`. `--sample-project` creates a local intentionally classical example without overwriting edits. Setup remains checkout-based until Wolf Pack 1.3.0 is published.

Finding IDs include algorithm/variant, source file set and test/declaration status; line shifts retain assignments. Renames or changed file sets can create a new identity. Rescans retain previously observed findings and distinguish new/persisting/no-longer-observed evidence. Missing findings do not prove a secure deployment or a verified migration; investigate deletion, parser coverage, renames and runtime use. Exception rationale and expiry are mandatory; expired exceptions and overdue dates stay visible without changing scanner risk.

State uses the existing private atomic-write/cross-process-lock implementation. Its read/write limit is 16 MB, with 200 registered repositories per approved parent and 5,000 current/historical findings per project. A failed save preserves prior disk state and leaves the completed scan visible with a warning. Persisted registration never authorizes a new parent or a replaced symlink. Ownership labels are workflow metadata, not authenticated user identities or RBAC.

Unified scans have a 50,000-file/512 MB discovery budget and a five-minute cooperative deadline. Cancel checks run during discovery, between scout files, and before publishing results. A single parser/relationship operation may finish before cancellation is observed; this is not a hard process CPU/memory limit. Existing completed results survive cancellation or quota failure. Standalone Wolf Pack keeps its existing defaults; the shared Scope implementation supplies the optional controls without a duplicate scanner.

Current next work: incremental analysis and broader language relationships; evidence-backed migration verification; simpler setup and diagnostics; real laptop/cloud/long-duration validation and independent security review. The owner removed team access (SSO/roles) and native installer code signing from this roadmap on 1 October 2026. The console remains a single-administrator workspace; ownership labels do not grant access.

Validation of this milestone: **367 Python tests passed, 12 prerequisite skips, 4,473 subtests passed; 36 browser journeys passed**. Both wheels built and the clean installed-wheel sample → scan → assign → restart → edit → rescan journey passed. Ruff, basic mypy (60 files), production CBOM baseline, whole-repository scan, official schema (zero errors), repeated site publishing and seven pinned public static scans passed. No new dependencies were introduced.

Development-corpus regression before/after the shared discovery budget change (163 labeled pairs, tuned fixture only; not real-world accuracy):

| Configuration | Before P / R / F1; FP / FN | After P / R / F1; FP / FN |
|---|---|---|
| full pack | 1.000 / 1.000 / 1.000; 0 / 0 | 1.000 / 1.000 / 1.000; 0 / 0 |
| without den | 0.845 / 1.000 / 0.916; 30 / 0 | 0.845 / 1.000 / 0.916; 30 / 0 |
| without corroboration | 1.000 / 0.994 / 0.997; 0 / 1 | 1.000 / 0.994 / 0.997; 0 / 1 |
| without second look | 1.000 / 0.914 / 0.955; 0 / 14 | 1.000 / 0.914 / 0.955; 0 / 14 |
| without flow | 1.000 / 0.933 / 0.965; 0 / 11 | 1.000 / 0.933 / 0.965; 0 / 11 |
| without registries | 1.000 / 0.988 / 0.994; 0 / 2 | 1.000 / 0.988 / 0.994; 0 / 2 |
| without siblings | 1.000 / 0.994 / 0.997; 0 / 1 | 1.000 / 0.994 / 0.997; 0 / 1 |
| without recognition | 0.982 / 1.000 / 0.991; 3 / 0 | 0.982 / 1.000 / 0.991; 3 / 0 |
| without propagation | 1.000 / 0.988 / 0.994; 0 / 2 | 1.000 / 0.988 / 0.994; 0 / 2 |
| without cross-file | 1.000 / 0.988 / 0.994; 0 / 2 | 1.000 / 0.988 / 0.994; 0 / 2 |
| without source scouts | 1.000 / 0.356 / 0.525; 0 / 105 | 1.000 / 0.356 / 0.525; 0 / 105 |
| without names | 1.000 / 0.963 / 0.981; 0 / 6 | 1.000 / 0.963 / 0.981; 0 / 6 |
| without concat | 1.000 / 0.994 / 0.997; 0 / 1 | 1.000 / 0.994 / 0.997; 0 / 1 |
| without symbols | 1.000 / 0.957 / 0.978; 0 / 7 | 1.000 / 0.957 / 0.978; 0 / 7 |
| without parameters | 1.000 / 0.994 / 0.997; 0 / 1 | 1.000 / 0.994 / 0.997; 0 / 1 |
| without implementation scouts | 1.000 / 0.982 / 0.991; 0 / 3 | 1.000 / 0.982 / 0.991; 0 / 3 |
| without config scouts | 1.000 / 0.748 / 0.856; 0 / 41 | 1.000 / 0.748 / 0.856; 0 / 41 |
| without lists | 1.000 / 0.969 / 0.984; 0 / 5 | 1.000 / 0.969 / 0.984; 0 / 5 |
| without artifact scouts | 1.000 / 0.933 / 0.965; 0 / 11 | 1.000 / 0.933 / 0.965; 0 / 11 |
| without binary scouts | 1.000 / 0.988 / 0.994; 0 / 2 | 1.000 / 0.988 / 0.994; 0 / 2 |
