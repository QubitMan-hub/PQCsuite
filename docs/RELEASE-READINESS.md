# Release readiness

Every suite release (`vX.Y.Z`) carries a `RELEASE_READINESS.md` written by the release workflow
(`scripts/release_readiness.py`). A release is published only when every check below passed on the tagged commit; the
report records which jobs ran, the evidence from that commit, and, copied from this page, what has not been validated.
So a release can say "passed the defined gates", and nothing more than that.

## The gates

| Gate | What must pass on the commit |
|---|---|
| Correct | Unit tests on Linux and Windows (Python 3.11, 3.13), including the fuzz, crash, race, downgrade, recovery and secret-leak tests; the full suite against real nginx, PostgreSQL, Redis, MQTT and SSH on Debian 13 with OpenSSL 3.5; the clinic and bank demos; the website and console in Chromium with accessibility checks; lint |
| Secure | pip-audit on runtime and optional dependencies; Trivy on the container image (fixable HIGH/CRITICAL fail unless triaged in `.trivyignore.yaml`); Wolf Pack finds no new high-risk cryptography against `docs/cbom.json`; CodeQL on Python, JavaScript and the workflows |
| Operational | Helm install in a kind cluster with a post-quantum request through the edge and a CRL fetched from the CA; IPsec and WireGuard with real traffic in network namespaces, including revocation; the Packer template and provisioning on Debian 13 |

Each release also records its test counts, OpenSSL version, a CycloneDX SBOM of the installed dependencies, the Wolf Pack
CBOM of the suite, build provenance, and a small benchmark on the GitHub runner (`scripts/benchmark.py`: TLS handshakes
with and without ML-KEM, certificate issuance, Vault throughput). Runner numbers are indicative; measure on your own
hardware before sizing.

## Not yet validated

Update this list when one of these is done; every release report copies it as it stands.

| Area | Status |
|---|---|
| Independent security and cryptographic review | Not done. The suite uses OpenSSL 3.5 and pyca/cryptography for every primitive and implements none itself, but its own protocol code (the VPN key agreement, Vault's format, the TLS bridge) has had no outside review |
| Real cloud deployments (AWS, Azure, GCP images) | Templates are validated in CI; no image has been built and run in a cloud account |
| Managed Kubernetes (EKS, AKS, GKE) | Tested in kind only |
| Long-running soak tests (days, memory and handle growth, certificate and key rotation over time) | Not done |
| Property-based testing | Not done; fuzzing is seeded random input |
| Replay testing | Covered for ACME nonces and one-time EST tokens only; nothing broader |
| Performance on production hardware, and under load | Only the runner benchmark above |
| macOS | Not tested; Windows and macOS VPN clients are not available |
| Security snapshot comparison between releases (SBOM and CBOM diffs) | The files are published per release; nothing compares them yet |
