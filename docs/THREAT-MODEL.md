# Threat model and key management

What the suite defends against, what it does not, and what to do when something goes wrong. [SECURITY-REVIEW.md](SECURITY-REVIEW.md) lists the assets and trust boundaries for an outside reviewer; [SECURITY.md](../SECURITY.md) lists every classical algorithm in the code and why it is there. Nothing here has been checked by an independent reviewer yet.

## What the suite relies on

The suite writes no cryptographic primitive itself. ML-KEM, ML-DSA, SLH-DSA, X25519, AES-GCM and TLS 1.3 come from OpenSSL 3.5+ (the TLS edge, through ctypes) and pyca/cryptography 49+ (the CA and Vault). A flaw in either, or an OpenSSL build without the post-quantum groups, is a flaw in the suite; `pqcsuite doctor` shows which versions are loaded. The operating system, its random number generator and its file permissions are trusted. None of it is FIPS 140-3 validated.

## Attackers

| Attacker | Protected? | How, and the limit |
|---|---|---|
| Records traffic now, decrypts it with a future quantum computer | Yes | X25519MLKEM768 (or SecP384r1MLKEM1024 under `cnsa2`) on every TLS connection; ML-KEM on every IKE exchange and rekey; ML-KEM in every Vault recipient wrap. `transition` still lets old clients connect classically: their traffic is not protected. |
| Active man in the middle | Yes | TLS 1.3 with certificates from your CA; mutual TLS where `require_client_cert` is set. VPN keys come only from ML-DSA mutual TLS. |
| Forges signatures with a quantum computer | Yes, for what the CA issues | ML-DSA or SLH-DSA certificates and CRLs. Browsers get a classical certificate under `transition` because they cannot verify ML-DSA yet. |
| Downgrades a connection to classical key exchange | Yes under `strict` and `cnsa2` | The edge offers only hybrid groups, so a client without them is refused, not downgraded; TLS 1.2 is refused by every policy. Two peers that both support post-quantum always agree on it, whatever their policies (`tests/test_downgrade.py` tries every pairing). |
| Presents the wrong algorithm or role | Yes | A `cnsa2` server refuses ML-DSA-65 client certificates; a server certificate is refused as a client identity and a client certificate as a server's (`tests/test_downgrade.py`). |
| Holds a stolen client certificate and key | Until revoked | Revoke it; the edge refuses it at its next handshake once its CRL copy has the revocation (at most `crl_every`, 60 s by default, with `crl_url`). There is no OCSP. |
| Holds a revoked VPN site or user certificate | Yes, within about a minute | It gets no new keys; its tunnel is cut 15 s after the CRL reaches the gateway. |
| Serves an old, forged or expired CRL | Yes | A downloaded CRL replaces the copy only if the CA signed it, it has not expired and it is not older than the copy. An expired copy refuses every client (fail closed). |
| Blocks the CRL address | Partly | The last copy stays in use until it expires (7 days by default), then every mutual-TLS client is refused. Watch the `CRL ... keeping` errors in the logs. |
| Replays a key-agreement or ACME message | Yes | VPN keys come from the TLS exporter of that session, bound to both site names and a fresh tag (WireGuard also to both public keys); ACME uses one-time nonces. |
| Alters, truncates or reorders a Vault archive | Yes | Every chunk is authenticated and the chunk count is bound; nothing is written until everything verifies. Fuzzed in `tests/test_fuzz.py`. |
| Steals backup storage | Yes | Archives open only with a recipient's private key. |
| Steals the CA key | No | See "If the CA key is compromised". Keep it in AWS KMS or an HSM, or encrypted (the default for `ca init`). Issue from an intermediate and keep the root offline: a compromised EST, ACME or console service then holds only the issuing CA's key and passphrase, which the root can revoke and replace. The Helm chart mounts no root into those services, and with `ca.issuingSecret` keeps it out of the cluster. |
| Has root on a machine running the suite | No | Keys and session secrets are in its memory and files. Python cannot wipe keys from memory. |
| Holds the console token | No | The token is full administrator access: issue, revoke, scan. There are no roles. Keep the console on localhost, or behind the edge with mutual TLS. Ten wrong tokens a minute from one address are refused. |
| Floods the edge with connections | Partly | Per-host limits on unfinished handshakes, deadlines on every socket and a connection cap; a flood from many addresses can still fill it. Put a load balancer or firewall that limits per-source connections in front. |
| Watches traffic volume and timing | No | Nothing pads or hides traffic patterns. |
| Compromises a dependency or the build | Partly | CI pins every action to a commit, audits dependencies, and releases carry build provenance; a malicious upstream release of OpenSSL or cryptography would still be trusted. |

## Revocation, when things fail

| Situation | What happens | Test |
|---|---|---|
| CRL missing when a service starts | It refuses to start (mutual TLS without a CRL would accept revoked clients) | `test_tls` |
| CRL damaged or signed by another CA | Every client is refused and the log says why | `test_tls`, `test_changes` |
| CRL expired | Every client is refused until a fresh one arrives | `test_changes` |
| CRL address unreachable | The copy is kept and the error logged each minute; it recovers by itself | `test_changes` |
| Older CRL served after a newer one | Ignored | `test_changes` |
| CA offline longer than the CRL's validity | Mutual-TLS clients are refused when the copy expires: run `ca maintain` (or `ca crl --days N`) before then | |
| Gateway restarts | It fetches the CRL before accepting anyone; without a copy and without the address it does not start | `test_changes` |
| CA killed between recording a revocation and re-signing the CRL | `pqcsuite doctor --ca` reports the revocation missing from `crl.pem`; `ca crl` or the daily `ca maintain` fixes it | `test_crash` |

Clocks matter: a machine whose clock runs ahead treats a CRL as expired early. Run NTP.

## Key lifecycle

| Stage | How |
|---|---|
| Generate | `ca init` (ML-DSA-87 by default, or SLH-DSA); `ca issue` and `ca enroll` generate leaf keys where they will be used (EST keys never leave the machine). |
| Store | Owner-only files (`chmod 600`), CA keys encrypted unless `--no-encrypt`, leaf keys optionally (`--key-passphrase-env`); CA keys in AWS KMS (`--kms`) or behind an HSM command (`--signer-command`). |
| Rotate leaves | `ca maintain` daily renews what expires within 30 days in place with a new key; services reload the files without a restart. |
| Rotate an issuing CA | Create a new intermediate under the root (`ca init --parent ROOT`), issue from it, and let the old one's certificates expire. Clients trust the root, so nothing changes for them. |
| Rotate the root | Create a new root, add its `ca.crt` to every trust bundle next to the old one, reissue, then remove the old root once nothing chains to it. |
| Revoke | `ca revoke SERIAL` (console: Revoke). The CRL is re-signed at once; `ca publish` serves it. |
| Back up | The CA folder (`ca.key`, `ca.crt`, `index.json`, `crl.pem`). Encrypt it with Vault to an offline recipient: `pqcsuite vault backup pki --to backups -r offline.pub`. A KMS or HSM key is backed up by the provider, not by the suite. |
| Destroy | Delete the key file and its backups, or schedule deletion in KMS. Deleting a file does not scrub it from disks or snapshots; use full-disk encryption on machines that hold keys. |

## Crashes and recovery

Every file the CA writes is written to a temporary name, flushed to disk and renamed into place, so a crash leaves the old file or the new one, never half of one. A certificate is recorded in `index.json` before its files are written, so a crash can leave a record without files (still revocable; `ca maintain` renews it into place) but never a certificate the CA does not know about. Vault archives are written to a `.part` file and renamed into place when complete (they are not flushed to disk first, so after a power cut check the newest archive with `vault inspect`). `tests/test_crash.py` kills the CA and Vault at random moments and checks all of this; `tests/test_races.py` runs six processes issuing and revoking at once, renewals racing revocations, two console administrators, and revocations landing during handshakes.

**Recovery objectives.** The recovery point is how often you back the CA folder up: with a nightly `vault backup` from cron, up to a day of issuance can be missing after a restore (see "If the CA machine is lost"). Restoring itself is quick: in `tests/test_recovery.py`, decrypting the backup and bringing the CA back, with existing clients still accepted and a revoked one still refused, takes about two seconds. Plan the recovery time around getting a machine and the backup's offline key, not around the software.

## Runbooks

**If the CA key is compromised.** Anyone holding it can issue certificates your services trust, so revoking leaves is not enough.
1. Stop the CA (EST, ACME, console) so nothing more is issued from it.
2. Create a new root on a clean machine, preferably in KMS or an HSM: `pqcsuite ca init --dir pki-new --name "…" --kms KEY`, or with an encrypted key file (the default).
3. Put the new `ca.crt` in every trust bundle (edges, VPN gateways, clients) and remove the old one. Until it is removed, the old CA can still vouch for anyone.
4. Reissue every server, client and site certificate from the new CA (`ca enroll` with new tokens, or `ca issue`).
5. Re-encrypt Vault archives only if their recipients' keys were also exposed; the CA key does not open archives.

**If an issuing (intermediate) CA is compromised.** Revoke it in its parent (`ca revoke` on the root's folder), publish the root's CRL, create a new intermediate, reissue from it.

**If a server, client or VPN key is stolen.** `ca revoke SERIAL --reason keyCompromise`, then issue a replacement. With `crl_url`, every edge and gateway refuses it within a minute.

**If AWS KMS or the HSM is unavailable.** Nothing new can be issued or renewed and the CRL cannot be re-signed. Existing certificates keep working until they expire, and mutual-TLS clients keep working until the CRL copy expires (7 days by default). Restore signing before then, or re-sign earlier with a longer `--crl-days`.

**If the CA machine is lost.** Restore the CA folder from its Vault backup (`pqcsuite vault decrypt`) on a new machine; point `ca publish` and EST at it. Certificates issued since the last backup are missing from `index.json`: revoke them by serial once you have them, or reissue.

**If the console token leaks.** Restart the console with a new `PQCSUITE_CONSOLE_TOKEN`, then read `console-audit.jsonl` for anything issued or revoked with the old one.
