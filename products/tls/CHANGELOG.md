# Changelog

## 1.0.0

First release of Acxelin TLS.

- Post-quantum TLS 1.3 and mutual TLS in front of any TCP service (`acxelin-tls edge`), with an ML-DSA certificate authority
  (`acxelin-tls ca ...`), EST and ACME enrollment.
- A console for the CA, edges and health.
- Metrics are named `acxelin_tls_*`.
- No outbound contact with GitHub or Acxelin Quantum.
- Deploys with Docker, systemd or the installers.
- A full manual (`docs/manual.md`), shipped in the release folder with the README, licence, example settings and systemd units.
