# Upgrading from the PQC Suite to Acxelin TLS 1.0

Acxelin TLS replaces the suite's `tls` and `ca` commands, the TLS edge and the certificate console.

## Commands

| Before | Now |
|---|---|
| `pqcsuite tls edge\|bundle\|serve\|connect` | `acxelin-tls edge\|bundle\|serve\|connect` |
| `pqcsuite ca ...` | `acxelin-tls ca ...` |
| `pqcsuite try` | `acxelin-tls try` |
| `pqcsuite doctor --ca DIR --config FILE` | `acxelin-tls doctor --ca DIR --config FILE` (edge configurations only) |
| `pqcsuite console` (certificates and edges) | `acxelin-tls console` |

## Names read through every 1.x release

| Old | New | When both exist |
|---|---|---|
| `PQCSUITE_CA_PASSPHRASE` | `ACXELIN_TLS_CA_PASSPHRASE` | the new one wins |
| `PQCSUITE_PARENT_CA_PASSPHRASE` | `ACXELIN_TLS_PARENT_CA_PASSPHRASE` | the new one wins |
| `PQCSUITE_ENROLL_TOKEN` | `ACXELIN_TLS_ENROLL_TOKEN` | the new one wins |
| `PQCSUITE_OPENSSL` | `ACXELIN_OPENSSL` | the new one wins |

## Changes that break existing setups

- **Metrics are renamed:** `pqcsuite_connections_active`, `pqcsuite_events_total` and `pqcsuite_group_total` are now `acxelin_tls_*`. Update dashboards and alerts.
- **Paths:** units and examples now use `/etc/acxelin-tls`, `/var/lib/acxelin-tls` and `/opt/acxelin-tls`, and the service user `acxelin`. Nothing is moved automatically; copy your files and, above all, your CA folder yourself.
- **Container image:** `ghcr.io/qubitman-hub/acxelin-tls` replaces the suite image. Its entry point is `acxelin-tls`, so commands drop the leading `tls` (`edge --config ...`).
- **Helm chart:** the chart is `acxelin-tls`. The console is no longer exposed in the cluster, so `ca.console.tokenSecret` is gone. Use `kubectl port-forward` and `acxelin-tls console link` (see the chart's notes).
- **Console sign-in:** the long-lived `PQCSUITE_CONSOLE_TOKEN` is gone. The console opens with a one-time link.
- **Removed:** `--check-updates` and the GitHub release check; products no longer contact GitHub.

## The CA folder is unchanged

The folder format is the same, so a CA folder from the suite works as it is, and a folder created by Acxelin TLS 1.0 works in the suite release. That is checked against fixtures made by the suite's code.

## Rolling back

1. Before upgrading, stop the services and copy the CA folder.
2. To roll back, stop, restore the copy, and reinstall the previous release.

Anything done after the upgrade is lost on restore. **Revocations are the dangerous part:** a certificate you revoked after upgrading is valid again once the older folder is restored, so revoke it again before restarting the edges. Certificates issued after the upgrade, and enrollment tokens used after it, are also lost.
