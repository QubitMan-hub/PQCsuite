# Agent handoff

Current instructions for the next contributor; superseded progress notes remain in Git history.

## Current priority — verify the five existing products

- Latest recheck from `2ae48bb`: 374 Python tests passed (13 host prerequisite skips), 37 browser tests, and 73 real-service/container tests including strongSwan responder restart recovery. Both wheels and the installed-package restart/remediation workflow passed; no new dependencies or modules. Fixed VICI reconnection/status retry/responder reload, invalid CA preflight, and misleading Vault header assurance. One-minute soak: 5,583 connections, zero failures, 3/3 revocations enforced. Kernel/platform limitations below remain unchanged.

- The owner explicitly put broader roadmap work aside. Do not resume SSO/installers/language expansion during verification.
- Verification from `1d42417`: 369 Python tests and 37 browser journeys passed; 12 host prerequisites skipped. Additional current-code container service/TLS/Vault/VPN checks: 78 passed, 3 VPN prerequisites skipped. Real strongSwan control-plane checks: 10 passed. Real userspace WireGuard split-tunnel traffic/rotation/revocation passed; full-tunnel test remains blocked by the kernel's missing IPv6 `addrtype` matcher. IPsec dataplane fails kernel SA installation (“Requested type not found”). Do not claim complete VPN validation.
- Fixed a real VPN status/recovery defect: IKE establishment alone no longer counts as protected. Require an installed encrypted child plus ML-KEM/PPK for health/metrics/overview, show IKE-only state in the UI, and retry missing children. Regression tests and stricter real dataplane assertions added.
- TLS/clinic/bank workflows, Vault scenarios, all scanner corpus/ablations, seven public static projects, dependency audit, wheels, lint/basic types and CBOM schema/baseline passed. Soak: 5,907 connections, zero failures, 3/3 revocations enforced. Full evidence and precise boundaries: `docs/PRODUCT-REVIEW.md`.

## Latest product milestone — persistent remediation

- Console now persists approved-parent registrations, latest full assessments, 30 recent comparisons per project, owners/deadlines and expiring exceptions in `.pqcsuite/projects.json` (`--project-state` overrides). Scope is rechecked on restart/use; private atomic storage and cross-process locks are reused. It remains a single-administrator token console, not SSO/RBAC.
- Finding IDs survive line shifts; rescans retain previous observations and assignments. “Not observed” is never labeled a verified deployed fix. Exceptions require rationale/expiry, stay in risk results, and show expired/overdue labels.
- `console --sample-project` creates an intentionally classical local example and preserves edits. Website has a sample assessment entry point and explicit language coverage matrix; Acxelin styling/product placement preserved.
- Unified scans have 50,000-file/512 MB discovery and five-minute cooperative time budgets plus Cancel. Prior completed evidence survives cancellation/quota failures. One parser/graph operation may finish before a checkpoint; this is not hard process isolation. No new production module or dependency.
- Validation: 367 Python tests passed, 12 prerequisite skips and 4,473 subtests; 36 browser journeys passed. Installed-wheel restart/remediation/rescan smoke passed. Both wheels, lint/basic types, CBOM baseline/schema, repeated publishing and seven real public static scans passed. All 20 corpus/ablation rows unchanged; before/after table in `docs/CODE-CRAWLER.md`.
- Remaining independent work: Java/Go relationship adapters, incremental scans, SSO/RBAC, signed native installers, independent security review and real laptop/cloud/long-duration validation. Identity-provider and signing-service details were requested asynchronously; no answer received at the time of this record. Do not substitute owner labels for access controls.

## Preserve

- Work on `main` is authorized by the owner. No PR, force push, protection bypass, secrets or unrelated changes. Check status/diffs and fetch before integrating; Claude Code's active work is unknown. Audit began at clean `3366c37`; no concurrent changes were observed.
- Read `CLAUDE.md` and `wolf-pack/CLAUDE.md`. Keep Acxelin styling and Wolf Pack's separate product placement. Do not delete supported config/binary/unsupported-language detectors or labeled evaluation truth as duplicates.
- Shared Code Crawler supports Python and optional JavaScript/TypeScript AST relationships, package aliases and bounded static caller/module impact. Dynamic dispatch and unsupported languages remain explicit coverage gaps. See [Code Crawler](docs/CODE-CRAWLER.md).
- Unified project scans feed Wolf Pack reports and Readiness. Approved-parent onboarding rejects traversal/outside paths/symlinks; exports omit source snippets/literals; private summary history uses shared cross-process storage locks. Default results exclude tests/declarations; advanced views retain them. Manual CBOM import and endpoint assessment remain separate supported evidence paths.
- Existing hardening, certificate/Vault recovery, truthful VPN telemetry, endpoint prioritization, offline exports, mobile and accessibility flows remain intact.

## Final audit changes

- Release evidence now uses pytest, including function-style tests, and refuses empty/failing runs. Release reports refuse failed/missing local evidence despite green remote CI; regressions demonstrate these failures.
- Linux integration/macOS CI use the same runner and parser extras. Wolf Pack runtime changes trigger suite CI; optional dependency audit derives requirements from manifests. Targeted privileged VPN checks remain unchanged.
- Consolidated stale developer/handoff guidance; repository map in [Contributing](CONTRIBUTING.md), generated default scan outputs ignored. Exact duplicate and unused-symbol checks found no safely removable production implementation. Required independent package assets and fixtures remain.
- Before/after, final validation and public competitor gaps: [Product review](docs/PRODUCT-REVIEW.md). Do not claim market superiority, a net source reduction or production readiness.

## Final validation — 1 October 2026

- Shared release evidence: 361 passed, 12 prerequisite skips, 4,446 passed subtests; 35 browser journeys passed. The JUnit total includes subtests. Additional Debian 13 real-service tests: 17 passed with no skips (nginx/PostgreSQL/Redis/MQTT/OpenSSH and related scenarios).
- Both wheels built/installed in a clean environment; optional web and base scans, seven pinned public repositories, corpus ablations, CBOM baseline/schema, lint/basic types, runtime/optional dependency audit, website publishing and demos passed. Production container built and ran with trusted proxy CA supplied through a temporary build secret, without changing the shipped Dockerfile or disabling verification.
- One-minute soak: 6,094 successful connections, no failures, 3/3 revocations enforced. Full release benchmark passed. These do not establish long-duration/production reliability; remote CI on the final commit is not claimed.

## Release boundaries

- Wolf Pack 1.3.0 remains unpublished. Install both packages from this checkout with their documented extras. Base container does not include optional repository scanning.
- Signed VPN installers/enrollment, fleet RBAC/history, hard resource isolation/incremental scans, broader AST languages and runtime deployment mapping remain open. Independent security review and real cloud/laptop/privileged tunnel/long-run validation require their actual environments.
- Cloud onboarding instructions already saved in the environment draft; no new environment configuration is needed for these source/CI/doc changes. No publication of that draft is implied.
