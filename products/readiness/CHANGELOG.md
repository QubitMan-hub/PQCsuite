# Changelog

## 1.0.0

First release of Acxelin Readiness, from Wolf Pack CBOM 1.4.1 and the PQC Suite's readiness assessment (their history is in
`CHANGELOG-history.md`). See `docs/upgrade.md`.

- One product: `scan`, `grade`, `report`, `merge`, `doctor` and a console for projects and endpoints.
- CBOM merges keep each system's observations; certificates match by fingerprint; secrets never merge.
- CNSA 2.0 reports AES of unknown key size as unverified instead of compliant.
