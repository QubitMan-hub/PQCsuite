# Changelog

Versions of Acxelin PQC Suite (`pqcsuite`). Wolf Pack CBOM has its own, in `wolf-pack/CHANGELOG.md`. A release is a tag `vX.Y.Z`; its GitHub release carries the wheel, the suite's own CBOM (Wolf Pack's inventory of `pqcsuite/`) and build provenance.

## 0.1.0 (28 September 2026)

The first release.

Four products sharing one ML-DSA certificate authority.

- **TLS 1.3 + mTLS:** a post-quantum edge in front of any TCP service (X25519MLKEM768, ML-DSA certificates; `strict`, `transition` for browsers, and `cnsa2` policies), several workers per port, per-host limits on unfinished handshakes, and certificates reloaded without a restart. A CA with ML-DSA and SLH-DSA roots, intermediates, keys in a file, AWS KMS or an HSM, EST (RFC 7030) and ACME (RFC 8555) enrollment, renewals that keep their algorithm, and CRLs checked fail-closed.
- **IPsec VPN:** strongSwan sites with hybrid ML-KEM key exchange, a PSK and an RFC 8784 PPK derived over ML-DSA mutual TLS and rotated; WireGuard remote access with a pre-shared key replaced every two minutes; revoked sites and users cut off.
- **Vault:** files, folders and scheduled backups encrypted to ML-KEM-768 + X25519 recipients (ML-KEM-1024 + P-384 for CNSA 2.0), AES-256-GCM, optional ML-DSA signature, tampering caught before restore.
- **Readiness assessment:** TLS and SSH endpoint grades, and compliance evidence mapped to NIST IR 8547 and CNSA 2.0.
- **Console:** one dashboard for all four, in light and dark, on localhost with a bearer token.
- **Deployment:** Docker image, Helm chart, systemd units, Packer images for AWS, Azure and Google Cloud.
