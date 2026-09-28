# Security

## Reporting a vulnerability

Email info@acxelinquantum.com with "security" in the subject. Please do not open a public issue.

## Notes

- `bench/corpus` deliberately contains weak cryptography and a test private key (`bench/corpus/certs/signing.key`). They are fixtures, not secrets.
- CI runs with a read-only token and every third-party action is pinned to a commit, updated through Dependabot.
- Wolf Pack reads code and files locally. It opens network connections only to endpoints given with `--tls` or `--ssh`.
