# Agent handoff

## Active Work

### Codex
- Implementation and local validation complete on `codex/security-and-console-hardening`; changes are prepared for review.

### Claude Code
- Current work unknown. No overlapping local changes or new remote-main commits were observed during this pass (base `ed4b260`).
- Preserved recent key overwrite protections, error messages, doctor checks, and documentation improvements.

## Completed
- Exclusive, unpredictable CA/Vault temporary writes; private plaintext staging and restore outputs; preservation of dangling destination symlinks.
- Renewal status check and issuance share the CA lock; a deterministic test reproduces and prevents renewal after a competing revocation.
- Console action progress/errors/confirmed results, duplicate-submit protection, stale-response guards, and scan polling after navigation. Actual CA algorithm and unverified backup metadata labels.
- Safe repeatable site builds preserve unrelated files and reject dangerous destinations. Reports embed favicons; backup CLI/compliance output distinguishes metadata and signer trust.
- Bounded HTTP/signature lengths, explicit HTTP framing errors, finite numeric settings, and basic type annotations.

## Verification
- Full Python suite: 325 passed, 12 skipped, 4,385 subtests passed (final run). Skips: missing nginx/PostgreSQL/Redis/MQTT, root/OpenSSH, and privileged VPN/WireGuard prerequisites.
- Browser suite: 26 passed on installed Chromium, including mobile/dark mode, accessibility, and real certificate issuance/revocation. Desktop/mobile visuals inspected.
- Ruff and basic mypy (`--ignore-missing-imports`, 56 source files) passed; both wheels built; site published twice locally; pip check, pip-audit, npm audit and CBOM baseline passed.
- TLS smoke, clinic and bank demos passed. Short soak: 3,056 successful connections, 0 failed, 3/3 revocations enforced, stable final thread/file counts. This does not validate days-long behavior.

## Important Decisions
- No changes to cryptographic primitives or archive format. Restored folder roots are 0700 on POSIX; internal archive modes are retained.
- Archive headers are not proof of integrity or signer identity. Use `vault verify` with a recipient key and `--ca` for issuer trust.
- No destructive Git operations, force pushes, or speculative feature/dependency removals.

## Needs Attention
- Docker build blocked by network policy at `registry-1.docker.io`; GitHub API at `api.github.com` returns Forbidden. Native Git reads work. Playwright download hosts are denied; browser checks used `/usr/bin/chromium` with a local config outside the checkout.
- Independent security/cryptographic review, real cloud/managed Kubernetes deployments, days-long soak, and VPN checks on real laptops remain release limitations (`docs/RELEASE-READINESS.md`).

## Do Not Duplicate
- Reviewed improvements above and the pre-existing customer-experience work. Re-read current Git state before editing overlapping files.
