# Acxelin Readiness

Find every piece of cryptography your organisation depends on, see which of it a quantum computer breaks, and know what to migrate first.

Acxelin Readiness reads source code, configuration, keys and certificates, binaries, container images, dependency manifests, packet captures and live TLS and SSH endpoints. It writes:
- a CycloneDX 1.6 cryptographic bill of materials (CBOM)
- SARIF for code scanning
- a self-contained HTML report that ranks every asset from critical to ok, with the fix for each

## Install

Python 3.11 to 3.14, on Linux, Windows or macOS. One command installs it for your user and puts `acxelin-readiness` on your PATH:

| Where | Command |
|---|---|
| Linux, macOS | `sh install.sh` |
| Windows | `Unblock-File .\install.ps1`, then `powershell -ExecutionPolicy RemoteSigned -File .\install.ps1` |

Run it in an unpacked release wheelhouse (it installs offline from the wheels next to it) or in `products/readiness` of a checkout. It checks your Python, finds OpenSSL 3.5, runs `acxelin-readiness doctor` and says what to do next. `sh install.sh --uninstall` (or `-Uninstall`) removes it.

For a virtual environment of your own: `pip install ./core ./products/readiness`.

## Use

| Task | Command |
|---|---|
| Scan a repository | `acxelin-readiness scan PATH` (then open `readiness-out/report.html`) |
| Include live endpoints | `acxelin-readiness scan PATH --tls api.example.com:443 --ssh bastion.example.com` |
| Grade endpoints A to F | `acxelin-readiness grade hosts.txt --html grades.html` |
| Evidence for an audit | `acxelin-readiness report --certs certs/ --targets hosts.txt --cbom readiness-out` |
| Check against standards | `acxelin-readiness scan PATH --policy nist-ir-8547 --policy cnsa-2.0 --fail-on-policy` |
| Fail CI only on new cryptography | `acxelin-readiness scan . --baseline cbom.json --fail-on high` |
| One view of many systems | `acxelin-readiness merge out-a out-b other-tool.cbom.json --name "Example Bank"` |
| See what this machine can scan | `acxelin-readiness doctor` |

Outputs land in `readiness-out/`: `cbom.json`, `readiness.sarif`, `findings.json` (every detection and its verdict), `relationships.json` (call relationships) and `report.html`. The report has a button that downloads the migration plan as `migration.csv`.

To mark a line that uses cryptography for something other than security (a cache key, a checksum), add `acxelin:ignore` with the reason in a comment on that line or the line above.

## Configure

Put settings in `.acxelin-readiness.toml` at the root of the scanned folder. The keys are the long option names with underscores. `config/example.toml` lists them all.

## Full TLS handshakes

Grades, accepted groups and SSH algorithms need nothing extra. To read the certificate of a server that offers only post-quantum key exchange, Acxelin Readiness completes a real TLS 1.3 handshake through OpenSSL 3.5 or newer. Point `ACXELIN_OPENSSL` at the folder that holds it; `doctor` says whether it is found. Without it, the report says those certificates were not observed. It never marks them as passing.

## Deploy

- **GitHub Action:** `uses: QubitMan-hub/PQCsuite/products/readiness@<tag>` with inputs `path`, `fail-on`, `baseline`, `args`, `output` and `upload-sarif`.
- **Docker:** `docker build -f products/readiness/deploy/Dockerfile -t acxelin-readiness .`, then `docker run --rm -v "$PWD:/scan" acxelin-readiness` (on Linux add `--user "$(id -u):$(id -g)"`, so the scan can write `readiness-out` into your folder).

## Limits

- A missing finding is not proof that cryptography is absent. Code that builds algorithm names at run time, or loads them from outside the scanned files, can be missed.
- The quality gate's precision and recall come from a labelled corpus that was tuned on, so they guard against regressions. They are not a claim about unseen code.

More: `docs/manual.md`, `docs/upgrade.md` (coming from Wolf Pack or the PQC Suite) and `docs/threat-model.md`.

## Licence

Proprietary: © 2026 Acxelin Quantum, all rights reserved. See `LICENSE`.
