# CLAUDE.md

pqcsuite is a company product for post-quantum secure communication, written in Python. "pqcsuite" is a working name (`NAME` in `pqcsuite/__init__.py`). The owner develops on Windows with PowerShell and prefers minimal code with few comments. Tell him the limits honestly; don't overclaim.

## Layout

- `pqcsuite/ca.py`: ML-DSA certificate authority (pyca/cryptography >= 49, pure Python).
- `pqcsuite/tls/openssl.py`: ctypes bridge to OpenSSL 3.5+ libssl. It is non-blocking with deadlines, and every call checks the OpenSSL error queue.
- `pqcsuite/tls/__init__.py`: policies (`strict`, `transition`), contexts, `connect`.
- `pqcsuite/tls/server.py`: threaded server with limits, CRL checks, certificate hot-reload and stats.
- `pqcsuite/edge.py`: terminate and originate proxy, TOML config, metrics.
- `pqcsuite/cli.py`: the `pqcsuite` command.

## Rules

1. Python only, with few dependencies: `cryptography`, and later strongSwan's `vici` for IPsec. Never shell out to the `openssl` command.
2. Must work on Windows. Use pathlib and `os.fsencode` for paths passed to OpenSSL, and nothing POSIX-only outside `edge`/`tls serve` signal handling.
3. Every security behaviour has a test that shows the attack being refused, not just the happy path.
4. Real handshakes: on Linux, run the tests with `LD_LIBRARY_PATH` set to an OpenSSL 3.5+ lib folder. CI uses Debian 13.
5. The mentor's AcxelinPQC repo is a feature reference only. It is proprietary, so never copy its code.

## Commands

```
pip install -e .
python -m unittest discover -s tests -v
pqcsuite doctor
```

## Roadmap

Stage 3 is IPsec via VICI with ML-DSA certificate auth. Stage 4 is the vault (X25519 + ML-KEM-768 hybrid encryption and ML-DSA signatures). Stage 5 is the web console, integrating Wolf Pack CBOM discovery. Propose a plan to the owner before starting each stage.
