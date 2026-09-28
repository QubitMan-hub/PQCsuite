# Scope for an independent security review

This is the brief for an outside reviewer. It says what the suite protects, where the trust boundaries are, what we most want tested, and how to build a test setup. Nothing here replaces the review; our own tests show the behaviour we intended, not that it is secure.

## What the suite protects

| Asset | Where it lives | Who must never get it |
|---|---|---|
| CA and issuing CA private keys (ML-DSA, SLH-DSA) | Encrypted file, AWS KMS, or an HSM through a signer command (`pki/signers.py`) | Anyone but the CA operator |
| Server and client private keys | Owner-only files written by `ca issue` / `ca enroll` | Other local users |
| TLS 1.3 session traffic through the edge | In memory (`tls/openssl.py`, OpenSSL 3.5 through ctypes) | Network attackers, now and after a quantum computer exists |
| IKE PSK and RFC 8784 PPK; WireGuard pre-shared keys | Derived with the TLS exporter over ML-DSA mutual TLS (`vpn/controller.py`, `vpn/wireguard.py`), handed to strongSwan or `wg` | Network attackers; revoked sites and users |
| Vault archives and their keys | Files; per-recipient ML-KEM-768 + X25519 (or ML-KEM-1024 + P-384) wrap, AES-256-GCM data, optional ML-DSA signature (`vault.py`) | Anyone not a recipient; anyone trying to alter an archive unnoticed |
| Console access token | Printed at start-up or set by `PQCSUITE_CONSOLE_TOKEN` | Anyone but the operator |

## Trust boundaries

1. **Network to TLS edge.** Untrusted clients reach `tls edge` and `tls server`. Policies: `strict` (default) and `cnsa2` refuse classical key exchange; `transition` also serves browsers with a classical certificate.
2. **Network to enrollment.** EST (`pki/est.py`) takes one-time tokens bound to one name; ACME (`pki/acme.py`) verifies account keys and http-01 challenges, fetching without following redirects.
3. **Gateway to gateway.** VPN controllers authenticate each other with ML-DSA certificates and check revocation before deriving keys. A revoked peer must get no new keys.
4. **Operator to console.** `console/` serves one page and a JSON API on localhost by default; every API call needs the bearer token; repeated wrong tokens are slowed down; the page runs under a CSP that allows only its own script by hash.
5. **Host.** The suite trusts the host it runs on: its OpenSSL library, file permissions, and the signer command it is configured with. Python cannot wipe keys from memory.

## What we most want tested

- **Certificate issuance:** name and SAN validation, key usage and basic constraints, path length for intermediates, CSR proof of possession, what EST and ACME let a client ask for.
- **Revocation:** fail-closed when a CRL is missing, damaged or expired; a revoked client refused at the edge, over EST renewal, and by the VPN controllers.
- **TLS edge:** downgrade to classical key exchange under `strict` and `cnsa2`; certificate selection in `transition`; slow and half-open connections (per-host caps, idle timeouts); certificate reload without restart.
- **Key derivation for VPNs:** exporter labels and context binding (both certificates, both public keys), rotation, what happens to the old PPK, replay across sessions.
- **Vault:** nonce uniqueness, recipient handling and removal, truncation and reordering, tampering detected before any plaintext is written, signature checks tied to the expected signer.
- **Console:** token handling, CSRF (the API takes a bearer header, not cookies), request size and time limits, what an unauthenticated caller learns.
- **Signers:** the external-command and KMS signers: a signer that returns a wrong or malformed signature must be caught (`signers._valid` checks every signature).

## Out of scope

- The published algorithms themselves (FIPS 203, 204, 205) and OpenSSL's implementation of them.
- FIPS 140-3 validation: the suite has not been through it and does not claim it.
- Wolf Pack CBOM (`wolf-pack/`), a separate inventory tool that holds no keys. Its `bench/corpus/certs/signing.key` is a deliberate test key.

## Building a test setup

CI (`.github/workflows/ci.yml`) is the reference: it builds OpenSSL 3.5 and strongSwan 6.1, runs the unit tests, puts nginx, PostgreSQL, Redis and MQTT behind the edge, runs two IPsec sites and a WireGuard gateway in network namespaces, and installs the Helm chart in a kind cluster. The demos in `examples/` (`clinic_demo.py`, `bank_demo.py`, `vpn_demo.py`) walk through the main flows end to end.

Findings: email info@acxelinquantum.com with "security" in the subject (see SECURITY.md).
