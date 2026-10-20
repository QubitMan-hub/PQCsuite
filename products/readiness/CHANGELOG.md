# Changelog

## 1.0.2

- Console: the Endpoints tab works before you choose a folder. **Add and scan** adds a repository and scans it in one step.
  Choose an asset to see each file and line it was found on; choose a priority to show only those. Track a finding as
  accepted risk with a reason and an end date. Due dates use a date picker, and errors scroll into view.

## 1.0.1

- Windows: `install.ps1` no longer stops at Python's `>>>` prompt on computers with the `py` launcher (Python from
  python.org or the Microsoft Store). It passed `py` its `-3` one character at a time.

## 1.0.0

First release of Acxelin Readiness, from Wolf Pack CBOM 1.4.1 (its history is in `CHANGELOG-history.md`). See
`docs/upgrade.md`.

- One product: `scan`, `grade`, `report`, `merge`, `doctor` and a console for projects and endpoints.
- CBOM merges keep each system's observations; certificates match by fingerprint; secrets never merge.
- CNSA 2.0 reports AES of unknown key size as unverified instead of compliant.
- The GitHub Action lives at `products/readiness`; the old `wolf-pack` path is removed.
- A full manual (`docs/manual.md`), shipped in the release folder with the README, licence and example settings.
