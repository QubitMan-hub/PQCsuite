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

## Baseline run

**Commands**, from the repository root at the base commit (the tree differs only by the spec and plan documents):
```
python -m venv /home/claude/venv-baseline && . /home/claude/venv-baseline/bin/activate
pip install -e "./wolf-pack[dev,crawler]" -e ".[test,integration,scan-web]"
PQCSUITE_OPENSSL=/opt/pqc/lib LD_LIBRARY_PATH=/opt/pqc/lib python -m coverage run -m pytest -q -rfEs -p no:cacheprovider
pip install ruff==0.14.0 && ruff check .
```

**Result:**
- 446 passed, 0 failed, 0 errors, 28 skipped, and 4,188 subtests passed, in 189 s.
- `ruff check .`: "All checks passed!"
- The TLS tests in `tests/test_tls.py` ran (none skipped) against OpenSSL 3.5.9.

**Skips (28), each with the reason the test prints:**

| Count | Test | Reason |
|---|---|---|
| 13 | `tests/test_vpn_desktop.py` | needs the desktop extra (pystray, PIL), not part of the install command above |
| 4 | `tests/test_scenarios.py` | needs nginx |
| 1 each | `tests/test_scenarios.py` | needs mosquitto; needs PostgreSQL; needs redis; needs PostgreSQL and root; needs an OpenSSL 3.5+ command line on `PATH` |
| 2 | `tests/test_vpn.py:528,543` | needs root, iproute2 and `PQCSUITE_STRONGSWAN` |
| 2 | `tests/test_wireguard.py:447,496` | needs root, iproute2, (iptables), wireguard-tools and WireGuard (kernel or `PQCSUITE_WIREGUARD_GO`) |
| 1 | `tests/test_vpn_platforms.py:398` | real tunnel: set `PQCSUITE_REAL_WIREGUARD=1` |
| 1 | `tests/test_scan.py:228` | needs root and OpenSSH |

These skipped areas are not covered by this baseline. Their evidence comes from CI's privileged jobs, or from Stage 4 here where F3 allows.

## Dependencies

Python 3.12.3 (GCC 13.3.0). System OpenSSL 3.0.13. OpenSSL 3.5.9 in `/opt/pqc`. `pip freeze`:
```
acme==5.8.0
attrs==26.1.0
certbot==5.8.0
certifi==2026.7.22
cffi==2.1.1
charset-normalizer==3.5.2
ConfigArgParse==1.8.0
configobj==5.0.9
coverage==7.16.2
cryptography==50.0.2
distro==1.9.0
hypothesis==6.170.0
idna==3.20
iniconfig==2.3.1
josepy==2.2.0
jsonschema==4.26.0
jsonschema-specifications==2025.9.1
packaging==26.3
parsedatetime==2.6
pluggy==1.7.0
pycparser==3.11
Pygments==2.21.0
pyOpenSSL==26.4.0
pyRFC3339==2.1.1
pytest==9.1.1
referencing==0.37.0
requests==2.34.2
rpds-py==2026.9.1
sortedcontainers==2.4.0
tree-sitter==0.26.0
tree-sitter-go==0.25.0
tree-sitter-java==0.23.5
tree-sitter-javascript==0.25.0
tree-sitter-typescript==0.23.2
typing_extensions==4.16.0
urllib3==2.8.0
-e ./wolf-pack (wolfpack-cbom 1.4.1) and -e . (pqcsuite 0.4.3), both editable from this checkout
```

## Known flaky test

`tests/test_replay.py::ReplayTest::test_a_recorded_session_sent_again_is_refused_and_does_nothing` fails intermittently:
- 7 of 15 plain runs failed, and 4 of 10 under coverage. The first full run above happened to pass it; the coverage run below failed it.
- The failure is `OSError: [Errno 107] Transport endpoint is not connected` at `tests/test_replay.py:74`, `raw.shutdown(socket.SHUT_WR)`.
- It happens when the server has already closed the connection on the replayed session, which is the refusal under test happening first.
- The product behaviour is correct; the harness doesn't allow for the server closing first.
- Stage 0 changes no tests outside `tests/golden`, so the fix (treat a closed connection at `shutdown` as refused, then assert no request was executed) is scheduled for the TLS stage.

## Coverage by product

Line coverage per destination, over the current files mapped to it in `tools/coverage_map.toml`. Files under `deleted` are excluded. HTML and JavaScript have no line coverage.

**Command:** `python -m coverage run --source=pqcsuite,wolf-pack/wolfpack -m pytest -q`, then `python tools/coverage_by_product.py`. The source list is wider than `pyproject.toml`'s, which measures `pqcsuite` only.

**Run result:** 446 passed, 1 failed (the flaky test above), 28 skipped.

| Destination | Line coverage |
|---|---|
| core | 90.8% |
| readiness | 88.3% |
| tls | 79.3% |
| vault | 93.8% |
| vpn | 74.6% |

**Files mapped to one destination whose code splits** (later stages compare these at function level where it matters):
- `pqcsuite/__init__.py` (core; `latest_release` is removed, D10)
- `pqcsuite/tls/__init__.py` (core; TLS's named policies move to Acxelin TLS)
- `pqcsuite/console/__init__.py` (core shell; each product's routes move to that product)
- `pqcsuite/project.py` (readiness; folds into the pipeline)

**Low numbers:** VPN and TLS are low partly because the privileged and real-service tests listed under "Skips" don't run here.

## Readiness quality

**Command:** `cd wolf-pack && python -m wolfpack bench bench/corpus --json /tmp/bench.json`. The "full pack" row is the configuration with no roles switched off.

**Result:**
- 174 labelled (file, algorithm family) pairs. The repository notes say 166; the current `truth.json` has 174.
- Precision 1.000, recall 1.000, F1 1.000; 0 false positives, 0 false negatives.
- `tools/quality_baseline.json` pins these values with the SHA-256 of `bench/truth.json`.

This is a regression floor, not a quality claim. The dev corpus is tuned on by construction (`wolf-pack/CLAUDE.md`, rule 3), so a perfect score here says nothing about unseen code. The Stage 1 gate fails if either value drops below 1.000.
