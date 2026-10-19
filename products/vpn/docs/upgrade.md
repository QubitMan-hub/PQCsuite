# Upgrading from the PQC Suite to Acxelin VPN 1.0

Acxelin VPN replaces the suite's `vpn` commands, its gateway image, its desktop app and the VPN parts of its console.

## Gateways can move one at a time

The key agreement did not change: the same exporter labels, message format and PSK, PPK and WireGuard key derivation. A gateway
on Acxelin VPN 1.0 agrees the same keys as one still on PQC Suite 0.4.3, in both directions, so you can upgrade one site, check
its tunnels, then the next. A test runs both versions against each other over real post-quantum mutual TLS.

## Commands

| Before | Now |
|---|---|
| `pqcsuite vpn up\|gateway\|status\|check` | `acxelin-vpn up\|gateway\|status\|check` |
| `pqcsuite vpn invite\|join\|app\|desktop` | `acxelin-vpn invite\|join\|app\|desktop` |
| `pqcsuite vpn connect\|disconnect\|install\|uninstall` | `acxelin-vpn connect\|disconnect\|install\|uninstall` |
| `pqcsuite ca init\|issue\|revoke\|crl\|maintain\|list\|serve` for the VPN's CA | `acxelin-vpn ca ...` (the same CA folder works) |
| `pqcsuite doctor` (VPN checks) | `acxelin-vpn doctor` |
| `pqcsuite readiness report --vici` | `acxelin-vpn inventory --cbom FILE`, then hand the CBOM to Acxelin Readiness or any CBOM tool |
| `pqcsuite console` (VPN) | `acxelin-vpn console` |

## Names read through every 1.x release

| Old | New | When both exist |
|---|---|---|
| `.pqcinvite` invitations from `pqcsuite vpn invite` | `.acxinvite` | both join; the app lists both, newest first |
| `PQCSUITE_CA_PASSPHRASE` | `ACXELIN_VPN_CA_PASSPHRASE` | the new one wins |
| `PQCSUITE_WIREGUARD_GO` | `ACXELIN_WIREGUARD_GO` | the new one wins |
| `PQCSUITE_OPENSSL` | `ACXELIN_OPENSSL` | the new one wins |
| `~/.pqcsuite/vpn` (invitations, this computer's keys) | `~/.acxelin-vpn` | the old folder is used only while the new one does not exist |

Each old name logs a warning saying what to use instead. They are removed in 2.0.

## Replaced on upgrade, automatically

- **The kill switch.** The suite's `PQCSUITE-KILLSWITCH` chain (Linux) and `com.apple/pqcsuite` anchor (macOS) are removed only
  once Acxelin VPN's own (`ACXELIN-KILLSWITCH`, `com.apple/acxelin-vpn`) is in place, so a full-tunnel laptop never has a gap
  and never ends up with two. `acxelin-vpn disconnect` also lifts one the suite left behind.
- **The start-with-the-machine service.** `acxelin-vpn install` removes the suite's `pqcsuite-vpn` service before adding
  `acxelin-vpn`.
- **The desktop app.** The 1.0 installers replace the suite's Acxelin VPN app in place.

## Changes that break existing setups

- **Metrics are renamed:** `pqcsuite_vpn_*` are now `acxelin_vpn_*`, and `pqcsuite_wireguard_*` are now `acxelin_vpn_wireguard_*`.
  Update dashboards and alerts.
- **Paths and units:** units and examples use `/etc/acxelin-vpn`, `/var/lib/acxelin-vpn` and `/opt/acxelin-vpn`. The units are
  `acxelin-vpn-ipsec`, `acxelin-vpn-wireguard`, `acxelin-vpn-enroll` and `acxelin-vpn-ca-maintain.timer` (they were
  `pqcsuite-ipsec` and `pqcsuite-wireguard`); `strongswan-pqc` keeps its name. Nothing is moved automatically: copy your
  configurations, certificates and CA folder, then disable the old units.
- **Container image:** `ghcr.io/qubitman-hub/acxelin-vpn` replaces the suite's gateway image. Its entry point is `acxelin-vpn`;
  with no command it runs `up --config /etc/acxelin-vpn/site.toml` (the suite's took the configuration path as its only argument).
- **Packer cloud images removed:** Acxelin VPN ships as the gateway image, systemd units and the installers.
- **Console sign-in:** the long-lived `PQCSUITE_CONSOLE_TOKEN` is gone. The console opens with a one-time link.

## Rolling back

1. Before upgrading, stop the services and copy the CA folder, `/etc/pqcsuite` and, on each laptop, `~/.pqcsuite/vpn`.
2. To roll back, stop, restore the copies, reinstall the previous release and re-enable its units.

Anything done after the upgrade is lost on restore. **Revocations are the dangerous part:** a site or person you revoked after
upgrading is valid again once the older CA folder is restored, so revoke them again before restarting the gateways.
Invitations sent and certificates issued after the upgrade are also lost; send those invitations again.
