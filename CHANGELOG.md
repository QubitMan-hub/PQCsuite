# Changelog

Versions of Acxelin PQC Suite (`pqcsuite`). Wolf Pack CBOM has its own, in `wolf-pack/CHANGELOG.md`. A release is a tag `vX.Y.Z`; its GitHub release carries the wheel, the suite's own CBOM (Wolf Pack's inventory of `pqcsuite/`) and build provenance.

## Unreleased

Changes on the customer's side now reach running services by themselves.

- **The CA key is encrypted by default:** `ca init` takes the passphrase from `PQCSUITE_CA_PASSPHRASE` or a prompt, and without either refuses rather than writing an unencrypted key; `--no-encrypt` keeps the old behaviour. `--encrypt` is still accepted. The Helm chart passes `--no-encrypt` when `ca.passphraseSecret` is empty.
- **Revocations reach every machine:** `pqcsuite ca publish` serves the CA's CRL, and `crl_url` makes edges, VPN controllers and WireGuard gateways fetch it every `crl_every` seconds (60 by default). Only a CRL that the CA signed, that has not expired and that is not older than the kept copy replaces it. The Helm chart runs the publisher in the CA pod and points edges with `requireClientCert` at it.
- **Configuration files are followed:** the edge applies a changed `edge.toml` route by route (unchanged routes keep their connections); the VPN controller restarts in place with its tunnels up; the WireGuard gateway applies users, routes, DNS and sites while running. A file that does not load is logged and ignored. The systemd units support `systemctl reload`.
- **Readiness on a schedule:** the console re-scans its endpoints every `scan_every_hours` (`--scan-every`) and lists the endpoints whose grade changed since the scan before; a failed scan shows its error.
- **Preflight checks:** `pqcsuite doctor --ca DIR --config FILE` reports an unencrypted or world-readable CA key, a missing or expiring CRL, certificates expiring within 30 days, missing files, mutual TLS without a CRL, CRLs copied by hand instead of `crl_url`, `transition` routes, and a console listening beyond localhost; it exits 1 on any problem.
- **Found by fuzzing:** the console answered some malformed requests with an internal error, and an empty or very short serial could pick the CA's only certificate for revocation. Serials must now be at least 8 hex characters; kinds, names, validity and scan targets are checked. `tests/test_fuzz.py` feeds malformed input to Vault, ACME, EST, the console and the configuration loaders on every run.
- **Hostile-condition tests:** `test_downgrade` (every server and client policy pairing, classical-only and TLS 1.2 attackers, ML-DSA-65 under `cnsa2`, certificates used in the wrong role), `test_races` (processes issuing and revoking at once, renewal against revocation, two console administrators, revocation during handshakes), `test_crash` (the CA and Vault killed at random moments), `test_recovery` (back up the CA, lose it, restore it, carry on) and `test_secrets` (no passphrase, token or key in output, logs, audit trails or files at rest). CI scans the container image with Trivy and fails on fixable HIGH or CRITICAL vulnerabilities not triaged in `.trivyignore.yaml`.
- **Found by those tests:** a CA killed between writing a certificate's files and recording it left a valid certificate the CA could not revoke; certificates are now recorded first, files are flushed to disk before being renamed into place, and `doctor` reports revocations missing from the CRL. A wrong passphrase was, about one time in 256, reported as a parse error instead. The CRL is re-read when its size or identity changes too, not only its timestamp. A configuration file read while an editor was still writing it could stop the watcher for good (or, in principle, apply a truncated file); the watcher now waits until the file stops changing and survives any error.
- **Deployment gate:** `pqcsuite doctor --strict`; exit codes 0 safe, 1 warnings (with `--strict`), 2 unsafe, 3 broken installation. The Helm chart runs it before the edge starts (`edge.preflight`).
- **Enrollment tokens** can come from `PQCSUITE_ENROLL_TOKEN` instead of `--token`, which other users can read in the process list.
- **Threat model:** `docs/THREAT-MODEL.md`: which attackers the suite stops and which it does not, revocation when things fail, the key lifecycle, and runbooks for compromised keys.
- **Code scanning:** CodeQL on Python, JavaScript and the workflows, on every push and weekly.
- **New releases:** `pqcsuite doctor --check-updates`, and an opt-in notice in the console (`check_updates`, `--check-updates`). `PQCSUITE_RELEASES_URL` points both at a mirror inside your network.

## 0.1.0 (28 September 2026)

The first release.

Four products sharing one ML-DSA certificate authority.

- **TLS 1.3 + mTLS:** a post-quantum edge in front of any TCP service (X25519MLKEM768, ML-DSA certificates; `strict`, `transition` for browsers, and `cnsa2` policies), several workers per port, per-host limits on unfinished handshakes, and certificates reloaded without a restart. A CA with ML-DSA and SLH-DSA roots, intermediates, keys in a file, AWS KMS or an HSM, EST (RFC 7030) and ACME (RFC 8555) enrollment, renewals that keep their algorithm, and CRLs checked fail-closed.
- **IPsec VPN:** strongSwan sites with hybrid ML-KEM key exchange, a PSK and an RFC 8784 PPK derived over ML-DSA mutual TLS and rotated; WireGuard remote access with a pre-shared key replaced every two minutes; revoked sites and users cut off.
- **Vault:** files, folders and scheduled backups encrypted to ML-KEM-768 + X25519 recipients (ML-KEM-1024 + P-384 for CNSA 2.0), AES-256-GCM, optional ML-DSA signature, tampering caught before restore.
- **Readiness assessment:** TLS and SSH endpoint grades, and compliance evidence mapped to NIST IR 8547 and CNSA 2.0.
- **Console:** one dashboard for all four, in light and dark, on localhost with a bearer token.
- **Deployment:** Docker image, Helm chart, systemd units, Packer images for AWS, Azure and Google Cloud.
