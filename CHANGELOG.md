# Changelog

Versions of Acxelin PQC Suite (`pqcsuite`). Wolf Pack CBOM has its own, in `wolf-pack/CHANGELOG.md`. A release is a tag `vX.Y.Z`; its GitHub release carries the wheel, the suite's own CBOM (Wolf Pack's inventory of `pqcsuite/`) and build provenance.

## Unreleased

Changes on the customer's side now reach running services by themselves.

- **Revocations reach every machine:** `pqcsuite ca publish` serves the CA's CRL, and `crl_url` makes edges, VPN controllers and WireGuard gateways fetch it every `crl_every` seconds (60 by default). Only a CRL that the CA signed, that has not expired and that is not older than the kept copy replaces it. The Helm chart runs the publisher in the CA pod and points edges with `requireClientCert` at it.
- **Configuration files are followed:** the edge applies a changed `edge.toml` route by route (unchanged routes keep their connections); the VPN controller restarts in place with its tunnels up; the WireGuard gateway applies users, routes, DNS and sites while running. A file that does not load is logged and ignored. The systemd units support `systemctl reload`.
- **Readiness on a schedule:** the console re-scans its endpoints every `scan_every_hours` (`--scan-every`) and lists the endpoints whose grade changed since the scan before; a failed scan shows its error.
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
