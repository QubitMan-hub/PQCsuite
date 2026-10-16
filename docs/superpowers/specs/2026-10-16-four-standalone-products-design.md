# Four standalone products: design

Date: 16 October 2026. Base commit: `5f8c349`. Status: for owner review.

## Goal

Turn the PQC Suite monolith and the separate Wolf Pack scanner into four products a customer can install, configure, test, deploy and understand on their own: Acxelin TLS, Acxelin VPN, Acxelin Readiness and Acxelin Q-Vault.

Success means all of the following hold:

1. Each product installs from its own folder with one `pip install`, and that install pulls in no other product.
2. No product imports another product. A test reads the import graph and fails if one does.
3. Each product has its own README, example config, tests, docs, deploy path and website section.
4. Behaviour customers rely on keeps working, and every Vault archive, invitation, CA folder and CBOM baseline written by the current release still opens.
5. The Wolf Pack name and its pack vocabulary are gone from code, output and site.

## Decisions from the design interview

| # | Decision |
|---|---|
| D1 | One small shared library, `acxelin-core`, with no command of its own and no product features. |
| D2 | Acxelin VPN keeps everything it has today: IPsec site-to-site, WireGuard remote access, and the desktop app. |
| D3 | Wolf Pack's name and concept go. The role switchboard, the per-heuristic ablation benchmark and the evaluation kits leave the main line at git tag `research-archive-2026-10`. The dev corpus and `bench/truth.json` stay as a CI precision and recall gate. |
| D4 | One website: a shared home page with one short entry per product, each opening that product's own section. |
| D5 | Cryptographic and wire formats are frozen. Every other old name is renamed, and the old name is still read for one release with a one-line deprecation warning. |
| D6 | Commands and packages are `acxelin-tls`, `acxelin-vpn`, `acxelin-readiness`, `acxelin-vault` and `acxelin-core`. Display names are Acxelin TLS, Acxelin VPN, Acxelin Readiness and Acxelin Q-Vault. |
| D7 | All six architecture candidates are in scope (see "Architecture changes"). The keyring and HTTP candidates start with a test-first spike, and either is dropped if the spike shows no real simplification. |
| D8 | The suite-wide console is removed. Each product gets the interface its customer needs (see "What the console removal costs"). |
| D9 | Readiness reads other products' assets through CycloneDX CBOM files, not through their code. Acxelin VPN and Acxelin Q-Vault each gain an `inventory --cbom` command for this. This is the only new feature in the restructure. |
| D10 | The GitHub release-check (`latest_release`) is removed. Products do not phone home. |

## Target layout

```
core/                      acxelin-core
products/
  tls/                     acxelin-tls
  vpn/                     acxelin-vpn
  readiness/               acxelin-readiness   (no dependency on core)
  vault/                   acxelin-vault
site/                      the website: shared home + one section per product
tools/                     release gate, release notes, manual renderer (repo tooling, not shipped)
.github/workflows/         one workflow per product, plus pages, codeql, upstream
```

Every product folder has the same shape:

```
products/<name>/
  pyproject.toml           own version; depends on acxelin-core or nothing
  README.md                install in three commands, quickstart, config reference
  src/acxelin_<name>/
  config/example.toml
  tests/                   behaviour tests; security tests show the attack refused
  docs/                    manual.md, threat-model.md
  deploy/                  that product's own path (see each product)
  CHANGELOG.md
```

## Shared core

`acxelin-core` holds only code that at least two products use. It has no command, no config file and no product feature of its own. It is about 1,900 lines.

| Module | From | Used by |
|---|---|---|
| `config` | `build`, `read_text`, `read_toml`, `env_passphrase` in `pqcsuite/__init__.py` | TLS, VPN, Vault |
| `files` | `pqcsuite/storage.py` (atomic private writes, locks) | TLS, VPN, Vault |
| `http` | `serve_http`, `content_length`, `HTTP_IDLE`, `explain`, `ConfigWatch`, `file_stamp`, `restart` | TLS, VPN |
| `openssl` | `pqcsuite/tls/openssl.py`, contexts, policies and `hostport` from `tls/__init__.py`, `tls/server.py` | TLS, VPN |
| `pki` | `pki/__init__.py` (CA, CRL), `pki/signers.py`, `pki/est.py`, and `pki.commands`: the `ca` and `est` argument definitions both TLS and VPN mount (from `cli/certificates.py`) | TLS, VPN, Vault (Vault uses signer verification only) |

Rules:

1. Products import `acxelin_core` and never each other. `core/tests/test_boundaries.py` parses every product's imports and fails on a cross-product import.
2. Importing `acxelin_core` does not load OpenSSL. Only `acxelin_core.openssl` does, so Acxelin Q-Vault runs on any `cryptography>=49` without OpenSSL 3.5.
3. Each product pins a compatible core range (`acxelin-core>=1,<2`). Each product's Docker image and installer bundles its core, so customers still run one command.

## Products

### Acxelin TLS

For platform and security teams putting post-quantum TLS 1.3 and mTLS in front of existing services.

- **Owns:** the edge proxy (`tls/edge.py`, `bundles.py`, `http.py`), ACME (`pki/acme.py`), the CA, EST and signer commands (`cli/certificates.py`, `cli/edge.py`), the one-minute `try` tour (from `cli/suite.py`), and its own `doctor` (the TLS part of `checks.py`).
- **Commands:** `acxelin-tls try`, `edge`, `ca ...`, `est ...` (both from core `pki.commands`), `acme ...` and `doctor`.
- **Deploy:** Docker, Helm (CA + edge, from `deploy/helm`), Kubernetes sidecar, and systemd units `acxelin-tls-edge.service` and `acxelin-tls-maintain.timer`.
- **Tools:** `scripts/soak.py` and `scripts/benchmark.py` move here.
- **Needs:** OpenSSL 3.5+.

### Acxelin VPN

For network teams connecting sites (IPsec) and staff (WireGuard plus the desktop app).

- **Owns:** `vpn/*` (charon, controller, wireguard, platforms, desktop, app, join) and `cli/vpn.py`.
- **Takes over from the console:** `Handler`, `Backoff`, `policy` and `with_tour`, because the VPN app is their last user.
- **Commands:** `acxelin-vpn up`, `gateway`, `invite`, `join`, `app`, `desktop`, `status`, `disconnect`, `uninstall`, `doctor`, plus its own `ca ...` and `est serve` from core `pki.commands`. With its own CA and enrollment service, `invite` and `join` no longer need Acxelin TLS.
- **New:** `inventory --cbom` (D9).
- **Deploy:**
  - systemd units `acxelin-vpn-ipsec`, `acxelin-vpn-wireguard`, `strongswan-pqc` and `acxelin-vpn-ca-maintain.timer`
  - the gateway Docker image (`docker/vpn-gateway.*`)
  - the Packer gateway image (`deploy/packer`, which already builds strongSwan)
  - desktop installers (`packaging/`, `.github/actions/installer`)
- **Needs:** OpenSSL 3.5+, plus strongSwan 6.0.2+ for IPsec and WireGuard tools for remote access.

### Acxelin Readiness

For security and compliance teams finding where quantum-vulnerable cryptography lives and what to migrate first. This merges the Wolf Pack scanner with the suite's readiness assessment.

- **Owns:** the scanner engine (from `wolf-pack/wolfpack`), endpoint grading, compliance evidence, the HTML report, CBOM and SARIF, and the GitHub Action.
- **Deleted while folding in:** `pqcsuite/project.py` (its limits, cancellation and history features move into the pipeline), the OpenSSL-based prober in `pqcsuite/readiness/scan.py` (replaced by the engine's pure-Python prober, once tests show equal grading), and the second compliance rule set.
- **Commands:** `acxelin-readiness scan PATH [--tls HOST:PORT] [--ssh HOST] [--open] [--history FILE]`, `probe`, `report` (inputs: `--certs DIR`, `--targets`, `--cbom FILE`, repeatable) and `merge`.
- **Deploy:** pip, the Docker image, and the GitHub Action at `products/readiness/action.yml`.
- **Needs:** `cryptography>=43` only, plus the optional `crawler` extra (tree-sitter). No OpenSSL and no core.

Engine renames (concept removal):

| Old | New |
|---|---|
| `wolfpack` package | `acxelin_readiness` |
| `pack.py` (`run`, `hunt`) | `pipeline.py` (`run`, `detect`) |
| `scouts/` | `detectors/` |
| `den.py` | `verify.py` |
| `alpha.py` | `rank.py` |
| `elders.py` | `catalog.py` |
| `Sighting` | `Detection` |
| `pack.Roles`, `bench.CONFIGS` ablations, `hunt --without` | removed (D3) |

Verdict names (accepted, quarantined, rejected, suppressed) and the evidence types stay, because they are domain terms, not branding.

### Acxelin Q-Vault

For data owners protecting archives and backups that must stay secret past the arrival of quantum computers.

- **Owns:** `vault.py` and `cli/vault.py` (`keygen`, `encrypt`, `decrypt`, `share`, `inspect`, and the backup commands).
- **Recipients:** ML-KEM-768 + X25519 key pairs from `acxelin-vault keygen` (CNSA 2.0 option). An optional signer certificate and CRL can come from any CA and are checked with core `pki`. Vault never issues certificates.
- **New:** `inventory --cbom` (D9).
- **Deploy:** pip, plus a Docker image for scheduled backup jobs.
- **Needs:** `cryptography>=49` only.

## Compatibility (D5)

| Item | New | Old name still read for one release |
|---|---|---|
| Vault format: magic `PQV1`, `SIG1`, KDF label `pqcsuite-vault-v1` | unchanged forever | n/a |
| CA folder layout, EST and wire protocols | unchanged | n/a |
| Source suppression comment | `acxelin:ignore` | `wolfpack:ignore` |
| CBOM property namespace | `acxelin:*` | `wolfpack:*` in baselines and `merge` inputs |
| Scanner settings file | `.acxelin-readiness.toml` | `.wolfpack.toml` |
| Output names | `readiness-out/`, `readiness.sarif`, `migration.csv` | none |
| GitHub Action | `products/readiness/action.yml` | `wolf-pack/action.yml` shim with a deprecation warning |
| Invitation key and extension | `acxelin_invite`, `.acxinvite` | `pqcsuite_invite`, `.pqcinvite` |
| Environment variables | `ACXELIN_OPENSSL`, `ACXELIN_WIREGUARD_GO` | `PQCSUITE_OPENSSL`, `PQCSUITE_WIREGUARD_GO` |
| Kill-switch firewall rule | `ACXELIN-KILLSWITCH` | `PQCSUITE-KILLSWITCH`, removed on upgrade |
| Desktop user folder | `~/.acxelin-vpn` | `~/.pqcsuite`, read when the new one is absent |
| Server paths and systemd unit names | `/etc/acxelin-<product>` etc. | documented in upgrade notes; never moved automatically |

Key material and CA folders are never moved automatically. Moving private keys silently is a security risk, so the upgrade notes give the exact commands instead.

## Architecture changes

1. **Dissolve the suite hub.** `cli/`, `console/`, `checks.py`, `cli/common.py` and the `pqcsuite/__init__.py` helpers go. Each product owns its command and its `doctor`, and the helpers move to core.
2. **One assessment pipeline for Readiness.**
   - One prober, one NIST IR 8547 and CNSA 2.0 rule set, one report, and `project.py` deleted.
   - Fixes a correctness bug: the engine's CNSA 2.0 check counts AES of unknown key size as compliant (`size in (None, 256)` in `wolfpack/compliance.py`). The merged rule set marks it unverified instead.
3. **Delete the role switchboard** (D3).
4. **One keyring module for both VPN tunnels.** `controller.py` and `wireguard.py` each build the same mTLS server, CRL follower, reload watcher, status and metrics. One `keyring` module owns those, and strongSwan (PSK + RFC 8784 PPK) and WireGuard (peer PSK) become two adapters. Starts with a spike.
5. **One HTTP server helper.** Four request handlers (`serve_http`, ACME, console, VPN app) re-implement idle timeouts and size limits. Core `http` keeps one, and ACME's HTTP-01 and the VPN app become routes. Starts with a spike.
6. **One brand module.** `pqcsuite/brand.py` and `wolfpack/brand.py` merge into Readiness, the only product that writes branded reports. The site keeps its own copy of the fonts and tokens.

## What the console removal costs (D8)

| Console page | Replacement |
|---|---|
| Project findings and priorities | The Readiness HTML report, which is already a filterable dashboard |
| VPN status | The VPN app and `acxelin-vpn status` |
| Vault protection and recovery warnings | `acxelin-vault inspect` and `acxelin-vault doctor` |
| TLS edge and CA health | `acxelin-tls doctor`, `acxelin-tls status`, and the edge metrics endpoint |
| One token-protected web view of everything | none: no product ships a web dashboard except the VPN app |

If the owner wants a web view back, it becomes a per-product feature after the restructure, not part of it.

## Testing strategy

The existing tests were written after the code, so they are evidence, not the contract. Each stage writes its tests first, shows them failing, then changes code.

1. **Golden fixtures first.** Before any code moves, today's code writes:
   - a signed and an unsigned Vault archive
   - a WireGuard invitation
   - a CA folder with a CRL
   - a CBOM baseline
   - a source file with `wolfpack:ignore`
   - each example config

   New code must read every one.
2. **Behaviour tests from intended behaviour.** These are derived from the manual, threat model, security review and CLI help, not from the implementation. Every security behaviour has a test that shows the attack refused.
3. **Independence tests.**
   - the boundary test (core rule 1)
   - for each product, a clean-install test: fresh venv, install only that product, run its smoke command, and assert no other product's package is installed
4. **Existing tests are triaged** as keep, rewrite or delete, with the reason in the stage report.
5. **Readiness quality gate.** CI fails if precision or recall on `bench/corpus` drops below the values measured at stage 0. `truth.json` is never edited to pass.
6. **Coverage.** Each product keeps a line-coverage floor at its stage 0 measurement or higher.

## Website (D4)

- `/` is a shared home in Acxelin's format. It shows one entry per product: the customer challenge as the headline, the product name, one line, and a link. No feature lists.
- `/tls/`, `/vpn/`, `/readiness/` and `/vault/` each have up to five pages: overview, how it works, set up, sample or demo, and security. Each section's navigation shows only its own pages.
- Each product's manual renders from `products/<name>/docs/manual.md` into its section.
- Old public URLs (`wolf-pack.html`, `product-manual.html`, `how-it-works.html`, `security.html`, `console-demo.html`) become redirect pages for one release.
- Style follows the existing Acxelin tokens in `site/style.css`, with fonts self-hosted and never loaded from Google. Design work uses frontend-design and Impeccable.
- Playwright journeys, one per product:
  - home, then choose the challenge, the overview, set up, and copy the install command
  - the sample or demo opens
  - a product page shows no other product's description
  - axe accessibility checks and a mobile viewport

## Repository cleanup

| Item | Action | Reason |
|---|---|---|
| `wolf-pack/eval/`, ablation bench, `pack.Roles` | archive at tag | D3 |
| `.claude/skills/archify` (108 files), `docs/architecture/`, `docs/how-it-works/`, `site/architecture/` | remove | diagram tooling and outputs for the suite; superseded by per-product docs |
| `.claude/skills/wolf-pack-tidy`, `.agents/skills/pqcsuite-project-scan` | remove | procedures for the removed concept and the removed bridge |
| `docs/AGENT-HANDOFF.md`, `docs/PRODUCT-REVIEW.md`, `wolf-pack/docs/HANDOFF.md` | remove | dated progress and review notes; git history keeps them |
| `docs/PRODUCT-MANUAL.md`, `docs/THREAT-MODEL.md` | split per product | customers receive one product |
| `docs/SECURITY-REVIEW.md`, `docs/PILOT.md` | split per product | the outside-review brief and hardware pilots stay essential |
| `docs/CODE-CRAWLER.md` | move to Readiness docs | it documents that engine |
| `docs/RELEASE-READINESS.md`, `scripts/release_readiness.py`, `scripts/release_notes.py`, `scripts/manual.py` | move to `tools/`, per product | repo tooling |
| `scripts/console_demo.py`, `site/console-demo.html`, `pqcsuite/console/` | remove | D8 |
| `scripts/pilot.py` | move to each product's tests | per-product pilot measurements |
| `examples/` | split per product | `bank_demo.py`, `clinic_demo.py` and `explain_demo.py` tell the whole-suite story and are removed; each product keeps one quickstart demo |
| root `CLAUDE.md`, `wolf-pack/CLAUDE.md`, `CONTRIBUTING.md` | rewrite as one short root `CLAUDE.md` and `CONTRIBUTING.md` | they encode rules this restructure replaces |
| root and `wolf-pack` `CHANGELOG.md` | freeze as history; each product starts its own | separate releases |

Nothing is removed in the cleanup stage without first showing that no file outside the removal set references it.

## CI and releases

- One workflow per product runs on changes under `products/<name>/**`. The three core users also run on `core/**`.
- Each workflow runs ruff, the tests, coverage, the clean-install test and that product's deploy smoke test. The VPN workflow keeps the Debian 13 network-namespace tests. Readiness runs its quality gate and the CycloneDX 1.6 schema check.
- `pages.yml` builds the site and runs the Playwright journeys.
- `codeql.yml`, `dependabot.yml` and `upstream.yml` (the OpenSSL and strongSwan release watch) stay.
- `downloads.yml` (release-link checks) stays and checks every product's links.
- `soak.yml` moves to Acxelin TLS.
- Releases are tagged per product (`tls-v1.0.0`, `vpn-v1.0.0`, `readiness-v1.0.0`, `vault-v1.0.0`, `core-v1.0.0`) through the existing release gate.

## Stages

Each stage ends with a report of changes, test results (failing first, then passing) and remaining gaps, and waits for the owner's go-ahead.

| Stage | Work | Exit criteria |
|---|---|---|
| 0 | Build OpenSSL 3.5 here, install `cryptography>=49`, run the existing suite, write golden fixtures, record precision, recall and coverage | baseline numbers recorded; fixtures committed |
| 1 | Acxelin Readiness: renames, pipeline merge, compliance fix, switchboard removal, CBOM inputs | its tests and quality gate pass; clean install passes |
| 2 | `acxelin-core` extraction and Acxelin Q-Vault | boundary test passes for Vault; golden archives open |
| 3 | Acxelin TLS, plus the HTTP helper spike | TLS tests pass on OpenSSL 3.5; clean install passes |
| 4 | Acxelin VPN, plus the keyring spike | unit tests pass; namespace and desktop tests written for CI |
| 5 | Website and Playwright journeys | site checks pass; journeys written |
| 6 | Cleanup, CI, docs and final report | full boundary test passes; final gap list |

## Verification limits in this environment

| Area | Can verify here | Cannot verify here |
|---|---|---|
| Acxelin Readiness and Q-Vault | everything | none |
| Acxelin TLS | tests against OpenSSL 3.5 built from source | Helm on a real cluster, KMS and HSM signers against real accounts |
| Acxelin VPN | unit tests with stand-ins | strongSwan tunnels, network namespaces, privileged WireGuard, the desktop app's administrator prompt; owner CI and laptops must run these |
| Website | static checks, link checks, accessibility rules in source | Playwright runs, because its browser download is blocked here (allowlisting `cdn.playwright.dev` fixes this) |
| Publishing | a branch-ready tree and patch | pushing to GitHub; no credentials here |

## Owner decisions still needed

1. **License.** The repository has no LICENSE file, so no one has permission to use it. Default if undecided: each package states "All rights reserved, Acxelin Quantum" and the gap stays on the production-readiness list. This is a legal choice for the owner.
2. **Site hosting.** Default: GitHub Pages from this repository, with the product sections as sub-paths of the current address.

## Out of scope

Team access (SSO, RBAC) and installer code signing (owner decision, 1 October 2026). New features beyond `inventory --cbom`. An independent security review. Real-hardware, cloud and long-duration validation, which stay on each product's pilot list.
