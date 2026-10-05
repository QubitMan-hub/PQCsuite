"""Vault: quantum-safe encryption for files, folders and backups."""
import sys
from pathlib import Path

from .. import env_passphrase
from ..pki import encrypted
from ..vault import VaultError
from .common import ask, show


def cmd_vault(a):
    from .. import vault
    def passphrase():
        if a.passphrase_env:
            return env_passphrase(a.passphrase_env)
        return ask("Key passphrase: ", "pass --passphrase-env VARIABLE") if encrypted(a.key) else None

    signer = lambda: vault.load_signer(a.sign_cert, a.sign_key, env_passphrase(a.sign_passphrase_env)) if a.sign_cert else None
    if a.vault_cmd == "keygen":
        taken = [f for f in (f"{a.out}.key", f"{a.out}.pub") if Path(f).exists()]
        if taken:
            raise VaultError(f"{taken[0]} already exists; pick another name (replacing a key makes everything encrypted to it unreadable)")
        ident = vault.Identity.generate(a.cnsa2)
        pw = env_passphrase(a.passphrase_env) if a.passphrase_env else None
        if not pw and not a.no_passphrase:
            instead = "pass --passphrase-env VARIABLE, or --no-passphrase"
            pw = ask("Passphrase for the new key: ", instead)
            if ask("Repeat: ", instead) != pw:
                raise VaultError("the passphrases do not match")
        ident.save(f"{a.out}.key", pw)
        Path(f"{a.out}.pub").write_bytes(ident.public.pem())
        print(f"{a.out}.key (keep secret) and {a.out}.pub (share with people who encrypt for you), id {ident.public.id}")
    elif a.vault_cmd in ("encrypt", "backup"):
        rec = [vault.Recipient.load(r) for r in a.recipient]
        if len({r.id for r in rec}) < 2:
            lone = (f"only one key can open this {'backup' if a.vault_cmd == 'backup' else 'file'}: lose it (or its passphrase) and the data is "
                    "gone for good. Add a recovery key kept offline, e.g. -r ops.pub -r recovery.pub")
            if a.vault_cmd == "backup" and not a.no_recovery_key:
                raise VaultError(f"{lone}; or pass --no-recovery-key to accept the risk")
            print(f"warning: {lone}", file=sys.stderr)
        if a.vault_cmd == "encrypt":
            if Path(a.out).exists():
                raise VaultError(f"{a.out} already exists; choose another -o")
            vault.encrypt(a.source, a.out, rec, signer())
            print(f"encrypted {a.source} -> {a.out} for {len(rec)} recipient(s)")
        else:
            target, pruned = vault.backup(a.source, a.to, rec, signer(), a.keep)
            print(f"backup {target}" + (f"; removed {len(pruned)} old" if pruned else ""))
    elif a.vault_cmd == "decrypt":
        target, who = vault.decrypt(a.file, a.out, vault.Identity.load(a.key, passphrase()), a.ca, a.crl, a.signer, a.require_signature)
        if not who:
            print(f"restored {target}; the file is not signed")
        elif a.ca:
            print(f"restored {target}, signed by {who} (certificate checked against {a.ca})")
        else:
            print(f"restored {target}; the signature is intact, but nobody checked who issued the signer's certificate "
                  f"({who}). Pass --ca to require one of your CA's certificates.")
    elif a.vault_cmd == "verify":
        r = vault.verify(a.file, vault.Identity.load(a.key, passphrase()), a.ca, a.crl, a.signer, a.require_signature)
        what = f"{r['files']} file(s), {r['bytes']} bytes" if r["kind"] == "dir" else f"{r['bytes']} bytes"
        print(f"{a.file}: restores {r['name']} ({what}); every chunk authenticated; opens for {r['recipients']} key(s); "
              + (f"signed by {r['signed_by']}" if r["signed_by"] else "not signed") + "; nothing was written")
        if r["signed_by"] and not a.ca:
            print("The signature is intact; the signer's certificate issuer was not checked. Pass --ca to require your CA.")
        if r["recipients"] < 2:
            print("warning: only one key opens it; `pqcsuite vault share` adds a recovery key without re-encrypting", file=sys.stderr)
    elif a.vault_cmd == "share":
        n = vault.add_recipients(a.file, vault.Identity.load(a.key, passphrase()), [vault.Recipient.load(r) for r in a.recipient])
        print(f"{a.file} now opens for {n} recipient(s); the encrypted data was not rewritten")
    elif a.vault_cmd == "inspect":
        show(vault.inspect(a.file), a.json)
        if not a.json:
            print("Header metadata only: integrity and the claimed signer are unverified. Use `vault verify` with a recipient key.")
    return 0

def add(sub):
    q = sub.add_parser("vault", help="Vault: quantum-safe encryption for files, folders and backups").add_subparsers(dest="vault_cmd", required=True)
    p = q.add_parser("keygen", help="a recipient key pair (ML-KEM-768 + X25519)")
    p.add_argument("out", help="writes OUT.key and OUT.pub")
    p.add_argument("--passphrase-env")
    p.add_argument("--no-passphrase", action="store_true")
    p.add_argument("--cnsa2", action="store_true", help="ML-KEM-1024 + P-384 (NSA CNSA 2.0) instead of ML-KEM-768 + X25519")
    for name in ("encrypt", "backup"):
        p = q.add_parser(name, help="encrypt a file or folder" if name == "encrypt" else "timestamped encrypted archive, with retention")
        p.add_argument("source")
        if name == "encrypt":
            p.add_argument("-o", "--out", required=True, help="the encrypted file to write, e.g. report.pdf.pqv")
        else:
            p.add_argument("--to", required=True, help="folder that holds the archives (sync it to any storage)")
            p.add_argument("--keep", type=int, help="keep only the newest N archives")
            p.add_argument("--no-recovery-key", action="store_true", help="allow a backup that a single key opens (losing it loses the data)")
        p.add_argument("-r", "--recipient", action="append", required=True, help="recipient .pub (repeatable)")
        p.add_argument("--sign-cert", help="sign with this CA-issued ML-DSA certificate")
        p.add_argument("--sign-key")
        p.add_argument("--sign-passphrase-env")
    for name, text in (("decrypt", "decrypt and verify"), ("verify", "restore drill: prove an archive opens with this key and is intact, writing nothing")):
        p = q.add_parser(name, help=text)
        p.add_argument("file")
        p.add_argument("-k", "--key", required=True, help="your .key file")
        if name == "decrypt":
            p.add_argument("-o", "--out", default=".", metavar="FOLDER",
                           help="folder to restore into (default: this one); the original file or folder name is kept inside it")
        p.add_argument("--passphrase-env", metavar="VAR", help="the key's passphrase is in this environment variable (otherwise you are asked)")
        p.add_argument("--ca", help="the signer's certificate must chain to this CA")
        p.add_argument("--crl", help="and must not be revoked")
        p.add_argument("--signer", help="and must have this common name")
        p.add_argument("--require-signature", action="store_true", help="refuse a file that is not signed")
    p = q.add_parser("share", help="let more recipients open a file, without re-encrypting it")
    p.add_argument("file")
    p.add_argument("-k", "--key", required=True, help="your .key file (you must be able to open the file)")
    p.add_argument("-r", "--recipient", action="append", required=True)
    p.add_argument("--passphrase-env")
    p = q.add_parser("inspect", help="who can open a file and who signed it")
    p.add_argument("file")
    p.add_argument("--json", action="store_true")
    for c in q.choices.values():
        c.set_defaults(func=cmd_vault)
