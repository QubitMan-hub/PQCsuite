# Security

## Reporting a vulnerability

Email info@acxelinquantum.com with "security" in the subject. Please do not open a public issue.

For an independent review of the suite, start with [docs/SECURITY-REVIEW.md](docs/SECURITY-REVIEW.md): assets, trust boundaries, what to test and how to build a test setup.

## Cryptography used by this repository

CI scans `pqcsuite/` with Wolf Pack CBOM on every change and fails if cryptography ranked high or worse appears that is not in [docs/cbom.json](docs/cbom.json), the reviewed inventory (regenerate it with `wolfpack scan pqcsuite -o out` and copy `out/cbom.json` when a change is intended). Every algorithm that is not post-quantum is there on purpose:

| Where | What | Why |
|---|---|---|
| `vault.py` | X25519, P-384 (ECDH) | The classical half of the hybrid key wrap with ML-KEM-768 or ML-KEM-1024. Breaking it alone does not open a file. |
| `vpn/wireguard.py` | X25519 | WireGuard's own handshake. Quantum safety comes from the pre-shared key, derived over ML-DSA mutual TLS with X25519MLKEM768 and replaced every 2 minutes. |
| `pki/acme.py` | RSA, ECDSA, Ed25519 | Verifying ACME clients' account keys (RFC 8555). Certificates it issues are ML-DSA only. |
| `pki/signers.py` | SHA-1 | The RFC 5280 subject key identifier, a lookup label, not a security function (marked `wolfpack:ignore`). |
| `readiness/scan.py` | TLS 1.2, X25519, Ed25519 | Names the scanner looks for in other servers. |
| `tls` policy `transition` | X25519, ECDSA/RSA fallback certificate | Only when a customer enables it for browsers; `strict` (the default) and `cnsa2` refuse classical key exchange. |
| `tests/` | RSA, ECDSA, P-256 | Classical peers the tests expect to be refused or graded C. |

Vault encrypts data and wraps keys with AES-256-GCM. TLS 1.3 prefers AES-256-GCM and also allows ChaCha20-Poly1305 and AES-128-GCM, except under `cnsa2`, which allows only AES-256-GCM.

## How the repository is protected

- CI runs with a read-only token (`permissions: contents: read`) and every third-party action is pinned to a commit, updated through Dependabot.
- No secrets in the repository or its history. The suite's test keys are generated at test time; the one committed private key, `wolf-pack/bench/corpus/certs/signing.key`, is a deliberate Wolf Pack test fixture that protects nothing.
- Command-line tools never overwrite a private key, a CA or an encrypted archive by accident; a certificate key is replaced only by `ca renew` or `ca maintain`.

## Limits outside this repository

- Git names objects with SHA-1 (with collision detection). GitHub does not host SHA-256 repositories yet.
- Pushing over HTTPS or SSH uses GitHub's key exchange. To check yours: `ssh -v git@github.com 2>&1 | grep "kex: algorithm"`; `mlkem768x25519-sha256` or `sntrup761x25519-sha512` means post-quantum. OpenSSH 10 prefers `mlkem768x25519-sha256` by default.
- Commit signatures, if used, are classical (GPG or SSH keys).

## Assumptions about the host

- On Windows, pqcsuite loads OpenSSL from `PQCSUITE_OPENSSL`, then from the folders on `PATH` (newest `libssl-*.dll` first). Anyone who can write to one of those folders can make pqcsuite load their library, so set `PQCSUITE_OPENSSL` and keep `PATH` to folders only administrators can write. On Linux and macOS the system loader decides (`LD_LIBRARY_PATH` / `DYLD_LIBRARY_PATH` when set).
- Private keys are files with owner-only permissions, or live in AWS KMS or an HSM. Python cannot wipe keys from memory, so the host running the CA or an edge must be trusted like any server that holds keys.
