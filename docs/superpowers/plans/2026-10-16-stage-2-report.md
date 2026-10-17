# Stage 2 report: Acxelin TLS/mTLS + CA

## Evidence (executed here: Linux, Python 3.12, OpenSSL 3.5.9)
- Core + TLS (wheel install test and 12 console browser journeys included): 232 passed, 2 skipped (no IPv6 in the sandbox; the Windows-only ACL test).
- Readiness + website: 204 passed (wheel install test, 10 console journeys, 13 site checks: journeys, axe in light, dark and 390 px, links, images, no browser errors).
- Old suite (until Stage 6): 196 passed, 28 skipped (privileged and service tests).
- End-to-end smoke of the installed commands: `try`, `ca init/issue`, `edge`, `status`, `connect`, Readiness `scan`, `report`, `grade`. No tracebacks.
- `pip-audit --strict`: no known vulnerabilities in either product's dependencies. Bandit: no high findings; medium findings reviewed (intentional binds; one unchecked URL scheme fixed).
- `ruff check .` clean.

## Delivered
- Core: CA, CRL, signers, EST, TLS contexts with caller-supplied policy, `Server`, HTTPS client, console shell and access contract, file downloads, owner-only secret files (POSIX modes; Windows ACLs via icacls).
- Hardening merged from the PQC repo: CRL numbering and rollback rejection, CRL check caching, revoked connections closed, fallback preference, per-client limits, IPv6, no-delay, Windows localhost dial, ACME rechecks, OpenSSL lifecycle fixes, with its regression and lifecycle tests.
- `acxelin-tls`: commands, console (CA, certificates with renew, audited download, revoke, maintenance, activity; edges with quantum-safe share; connection test with client certificates and explained refusals; health), docs, Docker, Helm, sidecar, systemd, website section with real demo output.
- CI: core, TLS, Readiness and website on Linux, Windows and macOS (Python 3.11 and 3.14), Debian 13 job for the full TLS suite, dependency audit.

## Not verified here
- Windows and macOS: code paths audited and guarded, CI written, but not run. Needs a push.
- Docker images not built, Helm templates not rendered (neither tool in the sandbox).
- The PQC repo's interop tests (Node, curl, Go) not ported; KMS/HSM signers not run against real services.

## Remaining production gaps
- No LICENSE file (owner decision).
- Per-product release workflow and wheelhouse publishing not written.
- Readiness deployment verification (`verify_endpoint`) not yet moved.
- Old `pqcsuite` package, its site and `pages.yml` remain until Stage 6.
