# Agent handoff

## Latest pass — Code Crawler and minimal workflow

- Added shared discovery and Python AST relationships, connected to accepted Wolf Pack findings, CBOM and offline reports. Existing detector results/tiers remain unchanged on all development-corpus ablations.
- Added optional `pqcsuite scan`, registered console project jobs, real stage messages, priority/search/evidence/JSON controls, private exports and bounded local summary history. Endpoint scans and imported CBOM review remain available.
- Customer workflow, evidence limits, performance, before/after size audit and remaining work: `docs/CODE-CRAWLER.md`. Added `.agents/skills/pqcsuite-project-scan/SKILL.md`; cloud setup draft now includes the scan extra. No third-party skill code was installed.
- Verification: 339 Python tests passed, 12 prerequisite skips, 4,431 subtests passed; 33 browser tests passed. Ruff/basic mypy, both wheels plus clean-environment install/scan, CycloneDX schema (0 errors), all 20 corpus configurations before/after, CBOM baseline, doctor, pip check, repeatable site publishing passed. Four pinned public projects scanned statically with no code/dependency execution.
- Wolf Pack checkout version is 1.3.0, unreleased. Root scan extra requires it; install both packages from this checkout until release publication. Graphs are Python-only; dynamic dispatch is unresolved. Optional history has one writer, bounded summaries, and no fleet storage/RBAC.
- Direct main integration follows the user authorization. No force push, no PR, no unrelated concurrent changes observed.

## Earlier work
- Codex: product improvements and earlier hardening verified and pushed directly to `main`. Implementation complete; no PR created.
- Claude Code: current work unknown. Repeated checks found no overlapping local edits or remote-main changes beyond base `ed4b260`. Existing customer-experience work was preserved.

## Completed — do not duplicate
- Earlier hardening: unpredictable exclusive temporary writes/private Vault restores, renewal/revocation locking, bounded input, reliable console mutations/navigation, safe repeatable site publishing, and unverified backup metadata labels.
- Readiness: observed posture metrics, priority/search filters, evidence/next actions (legacy protocols, trust failures, expiring certificates), JSON/CSV downloads, and retained targets for rescan.
- Wolf Pack: offline report search/priority filtering/sorting, linked evidence/remediation and CSV export. JavaScript-free reading remains usable; site samples regenerated.
- Integration: bounded local CycloneDX CBOM review beside endpoint assessment. Files never upload, content is escaped, and imported inventory clears on sign out. No invented combined score or code-to-endpoint mapping.
- VPN/Vault: truthful gateway observations and CLI diagnostic output, concise setup/verify/recover guidance. Overview excludes expired certificates from valid counts, surfaces unreachable VPN sources, and chooses the newest archive across folders.
- Market map/design decisions/final gaps: `docs/PRODUCT-REVIEW.md` (public references; no authenticated competitor-product access). Acxelin primitives retained, no new runtime dependencies/crypto primitives.

## Verification
- Final Python suite: 327 passed, 12 skipped, 4,407 subtests passed. Skips require missing external services or privileged VPN/OpenSSH/platform prerequisites.
- Final browser suite: 32 passed on installed Chromium (local config outside checkout), including real issue/revoke, local scan/rescan targets, CBOM escaping/local-only import, exports, offline reports, mobile/dark layouts, and accessibility.
- Ruff, basic mypy (56 source files), compileall, both wheels, site publishing twice, doctor, pip check, CBOM baseline, TLS tour and clinic workflow passed. Desktop/mobile/dark screenshots inspected using actual local unreachable-endpoint data.
- Earlier pass also verified dependency audits, bank workflow and a one-minute TLS/revocation soak; those do not establish days-long reliability.

## Boundaries and remaining work
- No consumer one-download VPN installer or browser connect/disconnect API. Existing native services/adapters require administrator credentials and OS tools. Separate referenced PQCvpn source was not found; public documentation was reviewed.
- Signed desktop packaging/enrollment, multi-user ownership/RBAC and durable fleet history remain product gaps. See product review and release-readiness docs.
- Real laptop/privileged tunnel tests, independent security review, real cloud/Kubernetes and days-long validation remain release limitations. Docker registry/build and pinned Playwright downloads were blocked in the earlier pass; browser validation uses system Chromium.
- Remote research was partially reachable on retries; Acxelin/PQCrypto/Tailscale/Vault and other public pages were read. Some specialized sources remained 403/404; remote hydrated visuals were unreliable. Do not claim all competitor functionality was verified.
- Preserve current Git identity, concurrent work and shared history. No force pushes or branch-protection bypasses.
