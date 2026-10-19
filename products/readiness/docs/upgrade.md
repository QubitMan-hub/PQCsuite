# Upgrading to Acxelin Readiness 1.0

Acxelin Readiness replaces Wolf Pack CBOM 1.x and the PQC Suite's `readiness` and `scan` commands.

## Commands

| Before | Now |
|---|---|
| `wolfpack scan PATH` | `acxelin-readiness scan PATH` |
| `wolfpack merge ...` | `acxelin-readiness merge ...` |
| `wolfpack bench` | removed; the quality gate runs in the product's tests |
| `wolfpack scan --without ROLE` | removed; every detector always runs |
| `pqcsuite scan PATH` | `acxelin-readiness scan PATH` |
| `pqcsuite readiness scan HOSTS` | `acxelin-readiness grade HOSTS` |
| `pqcsuite readiness probe HOST` | `acxelin-readiness grade HOST` |
| `pqcsuite readiness report --ca DIR` | `acxelin-readiness report --certs DIR` (a folder of PEM files) |
| `pqcsuite readiness report --targets ...` | `acxelin-readiness report --targets ...` |
| `pqcsuite readiness report --wolfpack OUT` | `acxelin-readiness report --cbom OUT` |
| `pqcsuite readiness report --vici` and `--backups` | export each system's inventory as a CBOM, then `acxelin-readiness report --cbom FILE`; the exports ship with those products |

## Names read through every 1.x release

Each old name still works and prints a one-line warning naming the new one. Old names are removed no earlier than 2.0.0.

| Old | New | When both exist |
|---|---|---|
| `wolfpack:ignore` comments | `acxelin:ignore` | both are honoured (each applies to its own line) |
| `.wolfpack.toml` | `.acxelin-readiness.toml` | the new file is used and the old one is ignored, with a warning |
| `wolfpack:*` properties in CBOMs given to `merge` | `acxelin:*` | the new property wins |
| `PQCSUITE_OPENSSL` | `ACXELIN_OPENSSL` | the new variable wins |

## Changed results

- **CNSA 2.0:** AES whose key size wasn't observed is now reported as "unverified" and fails `--fail-on-policy`. Before, it passed. This is a deliberate fix, because compliance that wasn't observed isn't proven.
- **`merge`:** assets are now matched by what they are. Algorithms match by name and parameters, certificates and public keys by fingerprint. Secret material and protocol instances are never merged across systems.
  - When systems disagree about a field, every system's value is kept in `acxelin:observations`, and the field is named in `acxelin:conflict`.
  - `bom-ref` values are now `<asset type>/<hash>`.
- **GitHub Action path:** the old path `QubitMan-hub/PQCsuite/wolf-pack` is removed. Change `uses:` to `QubitMan-hub/PQCsuite/products/readiness`; the inputs are the same. Workflows pinned to an older tag or commit keep working.
- **Output names:** the folder is `readiness-out/` (was `wolfpack-out/`), the SARIF file `readiness.sarif` (was `wolfpack.sarif`), and the report's CSV download `migration.csv` (was `wolfpack-migration.csv`). In `findings.json`, `sightings` is now `detections`.

## Rolling back

Reinstall the previous release. Scan outputs are files you keep; Acxelin Readiness has no state to restore. Baselines written by 1.0 still name every asset and its locations, so Wolf Pack 1.x can read them.
