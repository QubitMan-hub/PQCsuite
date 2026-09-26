# Roadmap and competitive notes (September 2026)

## Who else sells this, and what they offer

| Vendor | Product | What it does | What pqcsuite has |
|---|---|---|---|
| PQCrypto | PQCLens, PQCvpn, Q-Vault, Edge, PQCready AMIs | AI discovery, PQC VPN tunnels, backup encryption, TLS termination, prebuilt images | Discovery comes from Wolf Pack (to be integrated); VPN, vault, edge and bundles are built |
| QuSecure | QuProtect | Endpoint agents plus an orchestration layer that upgrades TLS and IPsec sessions to hybrid; issuance, revocation, audit logs | Edge, VPN, CA and audit log; no central fleet management yet |
| SandboxAQ | AQtive Guard | Network-wide inventory of certificates, libraries and devices; policy engine | `scan` for TLS endpoints; Wolf Pack for code, configs and binaries |
| Keyfactor, AppViewX | PQC PKI, crypto-agility | Certificate lifecycle automation, ACME/EST enrollment, HSM and KMS integration, policy and evidence | CA hierarchy, `ca maintain`, CRLs, EST enrollment, AWS KMS and command-line HSM signing |
| Thales, Fortanix | HSMs, KMS | PQC keys in hardware, crypto-agility | CA keys in AWS KMS or any HSM with a signing command; SLH-DSA roots |
| QAegis, QSphere (AWS Marketplace) | PQC VPNs | WireGuard with PQC; remote access with zero-trust controls | Site-to-site IPsec, plus WireGuard remote access with a PSK from ML-DSA mutual TLS |
| PQC Gateway (Pipy) | Edge gateway | PQC TLS termination and API management | Edge, without HTTP routing |

## What pqcsuite already does that most of them don't

- **VPN authentication:** it is rooted in ML-DSA today (PSK + RFC 8784 PPK from ML-DSA mutual TLS), not only an ML-KEM key exchange.
- **Revocation:** revoking a gateway cuts its tunnel within 15 seconds.
- **Open and tested:** every security behaviour has a test that shows the attack being refused, and CI runs real X25519MLKEM768 handshakes and real ESP traffic.
- **Windows:** it runs there (the CA, the vault and the TLS client/server).

## Next features, in the order I would build them

1. **Certificate enrollment (ACME and EST).** Servers request and renew ML-DSA certificates from the pqcsuite CA automatically. EST fits PQC best because it is algorithm-agnostic. ACME makes it a drop-in for cert-manager and certbot-style clients. This is the biggest gap against Keyfactor and AppViewX.
2. **Fleet management.** Edges and VPN gateways enrol with the console over mutual TLS, report status and receive policy and certificates centrally. This is QuSecure's core pitch.
3. **Remote-access VPN.** Done on Linux: WireGuard with address pools, per-user certificates, PSK rotation and revocation. Still to do: Windows/macOS clients and full-tunnel routing.
4. **Hardware-backed CA keys.** Done: AWS KMS (ML-DSA, external mu) and any HSM with a signing command. Native PKCS#11 is still to do.
5. **Compliance evidence.** Reports that map each endpoint, tunnel and backup to CNSA 2.0 and NIST IR 8547 dates (deprecated in 2030, disallowed in 2035), exportable for auditors. The `cnsa2` policy and the scan's CNSA 2.0 verdict are the start.
6. **Kubernetes.** A Helm chart for the edge as a sidecar, and a cert-manager external issuer backed by the pqcsuite CA.
7. **Cloud images.** Packer templates for AWS, Azure and GCP images of the edge, the VPN gateway and the bundles (PQCready AMI parity).
8. **SSH.** Check and harden OpenSSH (`mlkem768x25519-sha256`, `sntrup761x25519-sha512`) across a fleet, alongside the TLS scan.
9. **SLH-DSA (FIPS 205)** roots. Done, through OpenSSL 3.5, with intermediate CAs.
10. **Discovery.** Wolf Pack CBOM inside the console, when the owner decides.

Sources: pqcrypto.ai, AWS Marketplace listings (PQC Gateway, QSphere VPN, QAegis VPN), vendor overviews of QuSecure, SandboxAQ, PQShield and Keyfactor (thequantuminsider.com, cybersecuritynews.com), AppViewX and Thales on crypto-agility, and NSA CNSA 2.0 guides (postquantum.com, safelogic.com).
