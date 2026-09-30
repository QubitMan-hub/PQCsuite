# Agent handoff

## Active Work

### Codex
- Audit customer workflows and security boundaries; fix verified problems in small commits.
- Console group complete; now auditing malformed inputs, report metadata, and website publishing safety.
- Run final full suite, build, dependency/CBOM scans, and customer workflows before push.

### Claude Code
- Current work unknown. Checkout was clean at `ed4b260` when this pass began.
- Recent history already improves key overwrite protection, error messages, doctor checks, and documentation; preserve those changes.

## Completed
- Final pass reproduced a renewal/revocation race: renewal read status outside the CA lock. The read/check/issue now share the reentrant lock; deterministic regression passes (44 focused tests passed).
- Vault CLI inspection and compliance evidence identify unverified headers; signature verification without `--ca` explicitly says the issuer is unchecked. Trust-message regression and CLI/compliance/docs tests: 20 passed.
- Input hardening: controlled HTTP errors for oversized/ambiguous body lengths; finite numeric configuration and integer/boolean distinction; bounded Vault signature lengths. 80 focused tests and 4,051 subtests passed.
- Website publishing refuses source/ancestor/symlink/unrelated output paths and preserves extra files on repeated builds; URLs are escaped. Wolf Pack reports and published samples have embedded favicons. Full browser suite: 26 passed. Site/docs/Wolf Pack tests: 95 passed, 7 subtests passed.
- Console: four browser regressions reproduced before fixes; all 13 console tests passed on system Chromium, including mobile/dark mode, accessibility, and real certificate issue/revoke. Python console/secret/docs tests: 15 passed, 6 subtests passed.
- Exclusive unpredictable CA/Vault temporary writes, owner-only plaintext restore staging/output, and preservation of dangling destination symlinks. Four regression tests; 46 focused tests and 3,571 subtests passed; crash tests also passed.
- Development environment validated: 312 tests and 4,237 subtests passed; 12 optional tests skipped. Lint, wheel, clinic demo, TLS smoke, and CBOM baseline passed before code changes.

## Important Decisions
- Preserve library formats and cryptographic primitives; focus on verified boundary and workflow defects. Restored folder roots are private (0700 on POSIX), with original interior archive permissions retained.
- Keep temporary artifacts outside tracked source. No destructive Git operations or force pushes.
- Backup headers only claim a suite and signer: console labels them unverified and directs users to `vault verify`. Display CA algorithms from API data (including SLH-DSA), not a hardcoded label.

## Needs Attention
- Docker image build is blocked by network policy at `registry-1.docker.io`; GitHub API at `api.github.com` also returns Forbidden. Native Git reads still work. Browser checks use installed `/usr/bin/chromium` because Playwright download hosts are denied.
- Independent cryptographic review, real cloud/managed Kubernetes deployments, days-long soak, and VPN checks on real laptops remain release limitations (see `docs/RELEASE-READINESS.md`).

## Do Not Duplicate
- Existing overwrite protections and documentation improvements in recent commits.
