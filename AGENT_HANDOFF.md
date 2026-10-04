# Agent handoff

Current state for the next contributor (any agent or person). Superseded progress notes live in Git history; validation evidence lives in each commit's CI run and in `docs/PRODUCT-REVIEW.md`.

## Rules that always apply

- Work on `main` (owner-authorised). No pull requests, force pushes, protection bypass, secrets or unrelated changes. Fetch, read `git log` and recent diffs before editing; another agent may be working concurrently.
- Read `CLAUDE.md` and `wolf-pack/CLAUDE.md` first. Keep the Acxelin styling, and keep Wolf Pack on its own page (never a product card on `site/index.html`).
- Out of scope by owner decision (1 October 2026): team access (SSO/RBAC) and native installer code signing. Do not add them or ask for identity-provider or signing credentials. The console stays a single-administrator token console.
- Do not claim what was not run: customer laptops, cloud accounts, long-duration soak, independent security review and privileged kernel tunnels need their real environments. Source evidence is not a verified deployment; a missing finding is not a verified fix.
- Never delete supported detectors, labelled evaluation truth or test fixtures as "duplicates".

## Layout

| Path | What it is |
|---|---|
| `pqcsuite/` | the suite: `tls/` (edge, OpenSSL binding), `pki/` (CA, EST, ACME, signers), `vpn/` (strongSwan site-to-site, WireGuard remote access, platforms), `vault.py`, `readiness/` (endpoint scans, compliance report), `console/`, `project.py` (repository scans through Wolf Pack), `storage.py` (atomic private writes, locks) |
| `wolf-pack/` | the separate Wolf Pack CBOM scanner, including the Code Crawler (`wolfpack/crawler.py`, `crawler_web.py`, `scouts/pyflow.py`) and security patterns (`scouts/patterns.py`) |
| `tests/`, `wolf-pack/tests/`, `tests/browser/` | pytest suites and Playwright journeys |
| `docs/` | manual (single source for `site/product-manual.html`, built by `scripts/manual.py`), threat model, Code Crawler, pilot protocol, reviews, and the reviewed self-scan inventory `docs/cbom.json` |
| `site/` | the public website; `site/publish.py` prepares it for Pages |
| `deploy/`, `docker/`, `examples/` | Helm, Kubernetes, Packer, systemd units (installed by `deploy/packer/provision.sh`), images, example configs and demos |

## Latest changes (October 2026)

- **Code Crawler accuracy:** Python values are followed across files and through function parameters; look-alike names and unreachable code are handled by new roles `lookalikes` and `reachability`; security patterns WPC001–WPC005 (role `patterns`) reach SARIF with CWE tags, the report, `findings.json` and console assessments. Gitignored files are scanned again (keys and `.env` files live there). Measurements: `docs/CODE-CRAWLER.md`.
- **VPN:** `vpn invite` / `vpn join` replace four hand-copied values and two commands with one file and one command; the client reports Protected / Connecting / Not protected, and `vpn status` reads the same state.
- **Readiness:** `readiness report --wolfpack FOLDER` adds code rows; the HTML report is a dashboard (do these first, per-area summary, filterable table). Code rows distinguish "action needed", "quantum-vulnerable: plan its migration", "not used for security" and "quantum-safe".
- **Console:** project findings come first, with priority counts that filter; the Vault page explains protection and flags archives without a recovery recipient; the VPN page no longer says "Disconnected" when nothing is configured.

## Open work

- A native desktop VPN client or signed installer (customer laptops currently use the terminal; installer signing is out of scope).
- Relationship adapters for C#, C and Kotlin (Java and Go landed in October 2026); hard resource isolation for repository scans.
- Independent cryptographic and security review; real laptop, cloud and long-duration validation.

## Releases

Published: suite v0.3.1 (v0.3.0 is kept as published) and Wolf Pack 1.3.0. Unreleased work is listed under "Unreleased" in both changelogs. Publish only through the release workflow after the exact commit's CI passes; never rewrite tags; confirm publication on GitHub rather than from this note.
