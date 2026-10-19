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

## Completed after the first report
- Interop (from the PQC repo): Node and curl pass against the edge here (mutual TLS with ML-DSA, 20 MB byte-identical, refused without a certificate and after revocation); Go 1.24 runs in CI. Benchmark: 244 new post-quantum handshakes/s, 9,546 kept-alive requests/s on 1 CPU.
- External CA keys: a real boto3 KMS client (requests validated against AWS's KMS API model) and an external signing tool each sign a CA whose certificates and CRLs verify with standard ML-DSA. Live KMS/HSM tests and a manual `signers-live` workflow run against your key or device.
- CI: Docker build, run, console-in-container and Trivy scan for both images; kind + `helm lint`/`helm template`/install with a post-quantum request through the edge; interop.
- Release: `release-products.yml` per tag (core first), gated by `tools/release_check.py` (tested), with a tested wheelhouse, SHA-256 checksums, provenance attestation, a GitHub release and GHCR images.
- Licence: proprietary, © 2026 Acxelin Quantum, in the repository, core and both products; wheels carry it (install tests check), and PyPI uploads are blocked by classifier.

## Still needs your environment
- Windows and macOS runs, Docker, Trivy and kind/Helm: in CI after a push (no Docker, Helm or registry access in this sandbox).
- Live AWS KMS (`signers-live`, your key and credentials) and a real HSM (your device).
- A lawyer's review of the licence text.

## Takeover check (2026-10-19, fresh machine: Linux, Python 3.11, OpenSSL 3.5.9)
- Core + TLS + tools: 259 passed, 4 skipped (Windows ACLs; live KMS and HSM; no IPv6 in this kernel). Readiness + website: 207 passed. Old suite: 214 passed, 0 skipped, 2 failed: the strongSwan site-to-site tests, because this kernel has no XFRM interfaces ("Unknown device type"); CI runs them on a full kernel.
- First runs here: both Docker images through their CI steps; Trivy 0 HIGH/CRITICAL on both; Go 1.24, Node and curl interop 6/6 in Debian 13 (649 new handshakes/s, 5,492 kept-alive requests/s); `helm lint --strict` and `helm template`; boto3 KMS signer; installers from a checkout; desktop extra under Xvfb; a real WireGuard tunnel (wireguard-go); WireGuard and PostgreSQL scenarios as root.
- Fixed on the way: golden fixtures that .gitignore had kept out of Stage 0 (regenerated from 5f8c349); a Readiness grading test still calling the removed `pqcsuite tls`; an unpinned, unpatched Readiness image (4 fixable HIGH); boto3 missing from CI; contradictory OpenSSL advice in `doctor` and the installers; Dependabot watching removed paths.
- Not run: Windows, macOS, kind cluster install, live KMS/HSM.
