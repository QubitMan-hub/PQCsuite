# Changelog

Versions of Wolf Pack CBOM. A release is a tag `wolf-pack-vX.Y.Z` on the PQC Suite repository; its GitHub release carries the wheel and build provenance.

## 1.1.0 (28 September 2026)

- **Trust stores:** a file of five or more self-signed certificates and nothing else (such as certifi's `cacert.pem`) is one line, "Trust store of 121 root certificates", ranked low, instead of one alert per root. Switch: `--without trust-store`.
- **Declared non-security hashes:** Python `hashlib` calls with `usedforsecurity=False` rank low and are SARIF notes. Switch: `--without purpose`.
- **Nothing skipped silently:** Python files the running interpreter cannot parse, and source files over 2 MB, are named in the report. The Docker image and GitHub Action run Python 3.14.
- RIPEMD-160 recognised; `itest/` and bare `unit/` folders count as tests; the deliberate TLS 1.0/1.1 probes no longer raise deprecation warnings.
- Moved into the PQC Suite repository, under `wolf-pack/`. The GitHub Action is now `QubitMan-hub/PQCsuite/wolf-pack@main`.

## 1.0.0

First production release: CycloneDX 1.6 CBOM, SARIF, HTML report; source, configuration, key and certificate, binary, dependency and live TLS/SSH scouts; Docker image, GitHub Action, `.wolfpack.toml`, `--exclude`.
