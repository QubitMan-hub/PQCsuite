# Release readiness

Every suite release (`vX.Y.Z`) carries a `RELEASE_READINESS.md` written by the release workflow
(`scripts/release_readiness.py`). A release is published only when every check below passed on the tagged commit; the
report records which jobs ran, the evidence from that commit, and, copied from this page, what has not been validated.
So a release can say "passed the defined gates", and nothing more than that.

## The gates

| Gate | What must pass on the commit |
|---|---|
| Correct | Unit tests on Linux and Windows (Python 3.11, 3.13) and macOS, including the fuzz, property, replay, crash, race, downgrade, recovery and secret-leak tests; the full suite against real nginx, PostgreSQL, Redis, MQTT and SSH on Debian 13 with OpenSSL 3.5; the clinic and bank demos; the website and console in Chromium with accessibility checks; lint |
| Secure | pip-audit on runtime and optional dependencies; Trivy on the container image (fixable HIGH/CRITICAL fail unless triaged in `.trivyignore.yaml`); Wolf Pack finds no new high-risk cryptography against `docs/cbom.json`; CodeQL on Python, JavaScript and the workflows |
| Operational | Helm install in a kind cluster with a post-quantum request through the edge and a CRL fetched from the CA; IPsec and WireGuard with real traffic in network namespaces, including revocation, full tunnel, the kill switch and recovery; a real VPN client tunnel on Windows and macOS; the Packer template and provisioning on Debian 13 |

Evidence uses the shared pytest runner, including function-style Code Crawler and project tests. A failing, empty or missing test result blocks release even when remote CI is green. Wolf Pack runtime changes also trigger suite integration CI; optional parser dependencies are included in the dependency audit.

Each release also records its test counts, OpenSSL version, a CycloneDX SBOM of the installed dependencies, the Wolf Pack
CBOM of the suite, build provenance, and a small benchmark on the GitHub runner (`scripts/benchmark.py`: TLS handshakes
with and without ML-KEM, certificate issuance, Vault throughput, and sustained connections from many clients). Runner numbers are indicative; measure on your own
hardware before sizing.

## Not yet validated

Update this list when one of these is done; every release report copies it as it stands.

| Area | Status |
|---|---|
| Independent security and cryptographic review | Not done. The suite uses OpenSSL 3.5 and pyca/cryptography for every primitive and implements none itself, but its own protocol code (the VPN key agreement, Vault's format, the TLS bridge) has had no outside review. What to give a reviewer: [PILOT.md](PILOT.md) part 4 |
| Real cloud deployments (AWS, Azure, GCP images) | Templates are validated in CI; no image has been built and run in a cloud account. Script: [PILOT.md](PILOT.md) part 1 |
| Managed Kubernetes (EKS, AKS, GKE) | Tested in kind only. Script: [PILOT.md](PILOT.md) part 2 |
| Long-running soak tests | `scripts/soak.py` (a mutual-TLS edge following a live CRL; a client issued and revoked every 20 s, the edge certificate renewed every 2 minutes; fails if memory, open files or threads grow, a valid client fails, or a revoked one gets in) runs for 2 hours every week in CI (`soak.yml`). Longest run so far: 2 hours in CI on 29 September 2026 (645,824 connections, 0 failed, 288 of 288 revoked certificates refused, 48 edge certificate renewals; memory 46.9 to 48.3 MB after warm-up, open files 15 to 17, threads 13 to 14; no problems reported). Days-long runs: [PILOT.md](PILOT.md) part 3 |
| Property-based testing | `tests/test_properties.py` (Hypothesis): Vault round trips and bit flips, HTTP parsing under any network split, DER, base64url, addresses, serial lookup, SAN and JWK parsing |
| Replay testing | ACME nonces, one-time EST tokens and older CRLs, plus `tests/test_replay.py`: a recorded mutual-TLS session sent again never reaches the application, and TLS 1.3 early data (0-RTT) is never enabled |
| Performance on production hardware, and under load | Every release measures sustained load on the runner (the "Load" row above); production hardware: [PILOT.md](PILOT.md) part 3 |
| macOS | The unit and TLS tests pass in CI on macOS with Homebrew OpenSSL, a release gate |
| VPN clients on Windows and macOS | CI brings a real tunnel up, rotates its key and removes it with WireGuard for Windows and with Homebrew's WireGuard on macOS. Full tunnel, the kill switch and recovery after the gateway forgets a laptop are tested with real traffic on Linux only; on Windows and macOS they have not been run on real laptops. Phones are not supported |
| Security snapshot comparison between releases (SBOM and CBOM diffs) | Done: each release report lists dependency and cryptographic-asset changes since the previous release |
