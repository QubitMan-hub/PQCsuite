# Changelog

## 1.0.0

First release of Acxelin TLS as its own product, from the PQC Suite's TLS and certificate authority. See `docs/upgrade.md`.

- A console for the CA, edges and health.
- Commands are `acxelin-tls ...`; edge, bundle, serve and connect no longer sit under `tls`.
- Metrics are named `acxelin_tls_*`.
- No outbound contact with GitHub.
- Deploys with Docker, systemd or the installers. The Helm chart and Kubernetes examples are gone.
- A full manual (`docs/manual.md`), shipped in the release folder with the README, licence, example settings and systemd units.
