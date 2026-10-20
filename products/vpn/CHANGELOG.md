# Changelog

## 1.0.0

First release of Acxelin VPN as its own product, from the PQC Suite's VPN. See `docs/upgrade.md`.

- Commands are `acxelin-vpn ...` (they were `pqcsuite vpn ...`), with the certificate authority commands the VPN needs:
  `ca init`, `issue`, `revoke`, `crl`, `maintain`, `list` and `serve` (the enrollment service invitations use).
- An administrator console for sites, people and health: see each tunnel and its algorithms, invite a person and download their
  invitation, see who is connected, and revoke someone.
- `acxelin-vpn inventory --cbom` writes the VPN's cryptography as a CycloneDX 1.6 CBOM, without any key or secret in it.
- The VPN's policy is its own: TLS 1.3 only, hybrid ML-KEM key exchange (X25519MLKEM768, SecP384r1MLKEM1024 or
  SecP256r1MLKEM768) and ML-DSA certificates.
- The key agreement is unchanged, so a gateway on 1.0 and one still on PQC Suite 0.4.3 agree the same keys during an upgrade.
- Old names still work through 1.x, with a warning: `.pqcinvite` invitations, `PQCSUITE_*` variables, `~/.pqcsuite`. The old
  kill switch (`PQCSUITE-KILLSWITCH`, `com.apple/pqcsuite`) is removed when the new one is installed.
- Deploys with the gateway Docker image (strongSwan 6.1, OpenSSL 3.5), systemd units, or the installers. The desktop app ships as
  a Windows Setup, a macOS disk image and a Linux package. The Packer cloud images are gone.
- `doctor --json`, for scripts and the installer check.
- The app and `status` say when the key was last renewed, warn in words when renewals stop, and count failed renewals.
- A full manual (`docs/manual.md`), shipped in the release folder with the README, licence, example settings and systemd units.
