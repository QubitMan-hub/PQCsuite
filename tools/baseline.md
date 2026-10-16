# Stage 0 baseline

Base commit: `5f8c349a102e566560708ee12b9b1574e4a6e6cc` (still the upstream `HEAD` on 16 October 2026, checked with `git ls-remote`).
Environment: Ubuntu 24.04 sandbox, 1 CPU, root, Python 3.12.3, system OpenSSL 3.0.13.

## Environment findings

Each finding comes from a command run in this environment. The output is summarised here.

**F1. OpenSSL 3.5.9: established.**
- Built from the release tarball that `ci.yml` uses, with `./Configure --prefix=/opt/pqc --libdir=lib shared no-tests`, into `/opt/pqc`.
- `openssl version` reports `OpenSSL 3.5.9 29 Sep 2026`.
- It lists ML-KEM-512/768/1024, ML-DSA-44/65/87, and the TLS groups MLKEM512, MLKEM768, MLKEM1024, X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024.
- So the TLS and readiness full-handshake tests can run here.

**F2. `cryptography>=49`: established.**
- `pip install "cryptography>=49"` installs 50.0.2, which bundles OpenSSL 4.0.3 (29 Sep 2026).
- With `LD_LIBRARY_PATH` unset, ML-KEM-768 encapsulates and decapsulates, and ML-DSA-65 signs and verifies.
- The classes present are `MLKEM768PrivateKey`, `MLKEM1024PrivateKey`, `MLDSA44PrivateKey`, `MLDSA65PrivateKey` and `MLDSA87PrivateKey`.
- So Acxelin Q-Vault needs no system OpenSSL. The suite's floor `cryptography>=49` holds.

**F3. Network namespaces and tunnel tools: partly established.**
- `unshare -n` works. `iproute2`, `iptables`, `nftables` and `wireguard-tools` install from Ubuntu's archive.
- Veth pairs can be created between namespaces, and `iptables` chains can be created inside a namespace.
- The kernel has no WireGuard module (`ip link add wg0 type wireguard` fails with "Unknown device type"). Real WireGuard tunnels here would need userspace `wireguard-go`, which the code supports through `PQCSUITE_WIREGUARD_GO`.
- The strongSwan 6.1.0 source is reachable through GitHub's archive (`download.strongswan.org` is not). The build is not attempted in Stage 0; see the ruling in the ledger.

**F4. Playwright browser: established.**
- Chromium 141.0.7390.37 is preinstalled at `/opt/pw-browsers` (`PLAYWRIGHT_BROWSERS_PATH`) and launches headless.
- `tests/browser` pins `@playwright/test` 1.56.1, which uses this browser build (1194).
- This corrects the spec's earlier statement that the browser download was blocked. That check only looked in `~/.cache/ms-playwright`. Browser journeys can run here.

**F5. Publishing: established.** `git ls-remote` works. `git push --dry-run` fails with "could not read Username": no credentials are present. CI evidence needs the owner to push the branch.

**F6. TLS tests on Windows and macOS CI: static finding; confirm in a CI log.**
- `tests/helpers.py` sets `REASON` when OpenSSL 3.5 is unavailable, and `tests/test_tls.py` skips with `@unittest.skipIf(REASON, REASON)`.
- The `ubuntu-latest`/`windows-latest` matrix in `ci.yml` never sets `PQCSUITE_OPENSSL`, so on Windows the TLS tests skip.
- The macOS job sets `PQCSUITE_OPENSSL` from Homebrew's `openssl@3`, so they run there.
- Linux runs them in the Debian 13 container job.
- The spec therefore cannot list Windows as a supported TLS platform until a Windows job provides OpenSSL 3.5.

Also found: `PQCSUITE_REAL_WIREGUARD` (`ci.yml`, the macOS job) belongs in the spec's compatibility table with the other environment variables.
