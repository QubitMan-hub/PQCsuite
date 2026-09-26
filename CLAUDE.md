# CLAUDE.md

Acxelin PQC Suite (working name `pqcsuite`, `NAME` in `pqcsuite/__init__.py`) is company work: four post-quantum products in Python. The owner develops on Windows with PowerShell and prefers minimal code with few comments. Tell him the limits honestly; don't overclaim.

## Products and layout

- **TLS 1.3 + mTLS:** `pqcsuite/tls/` (`openssl.py` ctypes bridge to OpenSSL 3.5+, policies in `__init__.py`, `server.py`, `edge.py`, `bundles.py`, `http.py`) and `pqcsuite/pki/` (CA in `__init__.py`, `signers.py` for SLH-DSA/KMS/HSM, `est.py`, `acme.py`).
- **IPsec VPN:** `pqcsuite/vpn/` (`charon.py` drives strongSwan through VICI, `controller.py` does the ML-DSA mTLS key agreement for PSK + RFC 8784 PPK, `wireguard.py` is remote access).
- **Vault:** `pqcsuite/vault.py`.
- **Readiness assessment:** `pqcsuite/readiness/` (`scan.py` for TLS/SSH grades, `compliance.py` for NIST IR 8547 and CNSA 2.0 evidence).
- `pqcsuite/console/` is the one dashboard; `pqcsuite/cli.py` groups commands by product. `site/` is the website, styled after acxelinquantum.com. `deploy/` holds Helm, Packer and systemd.

## Rules

1. Python only, with few dependencies: `cryptography`, and `vici` for IPsec. Never shell out to the `openssl` command.
2. Must work on Windows: pathlib, nothing POSIX-only outside the VPN and signal handling.
3. Every security behaviour has a test that shows the attack being refused, not just the happy path.
4. On Linux, run the tests with `LD_LIBRARY_PATH` set to an OpenSSL 3.5+ lib folder. CI uses Debian 13 and runs the VPN tests in network namespaces.
5. The mentor's AcxelinPQC repo is a feature reference only. It is proprietary, so never copy its code.
6. Wolf Pack CBOM integration is on hold until the owner says otherwise.

## Commands

```
pip install -e ".[test]"
python -m unittest discover -s tests -v
pqcsuite doctor
```
