# Contributing

How to work on the suite itself: a development install, the tests, the website and releases. Using the products is in the [README](README.md).

## Development install

Python 3.11+, from a clone:

```
pip install -e "./wolf-pack[dev,crawler]" -e ".[test,integration,scan-web]"   # [test]: hypothesis; [integration]: certbot and acme, for the ACME tests (leave it out for a lighter setup)
pqcsuite doctor
```

## Tests

```
python -m pytest -q
```

The shared pytest runner at the repository root runs these and Wolf Pack's tests together, including project onboarding and optional JavaScript/TypeScript AST fixtures. The base runtime remains independent of the test and web-parser extras. The suite needs `cryptography` 49 or newer (for ML-KEM and ML-DSA); an older one stops every test at import with a message saying so.

CI also lints with `ruff check .`, runs the website and console in Chromium with axe accessibility checks (`tests/browser`: `npm install`, `npx playwright install chromium`, `npx playwright test`), and scans `pqcsuite/` with Wolf Pack against the reviewed inventory in `docs/cbom.json`.

`tests/test_docs.py` keeps the documentation honest: a command or option quoted in the README, `docs/`, the examples or the website that the CLI does not have, or a link that leads nowhere, fails the build. Fix the documentation, or the product, in the same change.

The TLS tests run when OpenSSL 3.5+ is available. `tests/test_scenarios.py` puts real applications behind the products and checks them with independent clients: nginx (OpenSSL 3.5 command line and curl), PostgreSQL, Redis and MQTT through edge tunnels, EST enrollment, a vault backup with tampering, and readiness grades; each is skipped when the application is missing. CI also runs two IPsec sites and a WireGuard gateway in network namespaces with real traffic, installs the Helm chart in a kind cluster, and runs the image's provisioning script on Debian 13.

`pip wheel . -w dist` builds the wheel; setuptools works in `dist/.build`, so no `build/` folder is left in the source tree.

## Website

The website is in `site/` and is published to https://qubitman-hub.github.io/PQCsuite/ by `.github/workflows/pages.yml` on every change to it. `python site/publish.py https://YOUR-ADDRESS/ dist/site` copies it into `dist/site` with the absolute addresses that link previews and search engines need (canonical links, preview images, `sitemap.xml`, `robots.txt`). Choose a fresh output folder: the publisher refuses the source tree and unrelated nonempty folders. Rebuilding its own output preserves extra files instead of deleting the whole folder.

## Releases

A tag `vX.Y.Z` releases the suite and `wolf-pack-vX.Y.Z` releases Wolf Pack: push the tag, or open Actions → release → Run workflow and type it, and the workflow creates the tag on the branch's latest commit. Before tagging, set the version in the package's `pyproject.toml` (for the suite also `__version__`, the Helm chart's `version` and `appVersion`, and the Packer template's `version`) and rename its changelog's "Unreleased" section to `## X.Y.Z`; the release workflow refuses a tag that does not match. A suite release is published only when every CI and CodeQL job passed on its commit ([docs/RELEASE-READINESS.md](docs/RELEASE-READINESS.md)). Each GitHub release carries the wheel and signed build provenance (`gh attestation verify FILE --repo QubitMan-hub/PQCsuite`); a suite release also carries `RELEASE_READINESS.md`, the CBOM, a CycloneDX SBOM and the tested dependency versions, and publishes the image `ghcr.io/qubitman-hub/pqcsuite:X.Y.Z`.

`pqcsuite` is a working name: `NAME` in `pqcsuite/__init__.py`.
