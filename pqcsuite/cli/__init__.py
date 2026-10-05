"""The `pqcsuite` command. Each product's commands live in their own module; this one builds the parser and runs a command."""
import argparse
import json
import logging
import os
import sys

from .. import NAME, __version__, explain, tls
from ..pki import CAError
from ..vault import VaultError
from ..vpn.charon import CharonError
from ..vpn.wireguard import WGError
from . import certificates, edge, readiness, suite, vault, vpn


class JSONFormatter(logging.Formatter):
    def format(self, r):
        out = {"time": self.formatTime(r), "level": r.levelname, "logger": r.name, "message": r.getMessage()}
        if r.exc_info:
            out["exception"] = self.formatException(r.exc_info)
        return json.dumps(out)


# Help for options many commands share, filled in wherever a command gives none of its own
HELP = {
    "key_passphrase_env": "the key's passphrase is in this environment variable",
    "passphrase_env": "the key's passphrase is in this environment variable (otherwise you are asked)",
    "sign_key": "the signing certificate's private key",
    "sign_passphrase_env": "the signing key's passphrase is in this environment variable",
    "json": "print JSON instead of text",
    "timeout": "seconds to wait for each connection",
    "workers": "endpoints scanned at once",
    "vici": "strongSwan's control socket (default: unix:///var/run/charon.vici)",
    "interface": "the WireGuard interface (default: wg0)",
    "san": "another DNS name or IP address the certificate covers (repeatable)",
    "days": "certificate lifetime in days",
    "algorithm": "the key's algorithm",
    "out": "folder to write to",
    "file": "the Vault file (.pqv)",
    "source": "the file or folder to encrypt",
    "serial": "from `ca list`; the first 8 or more hex characters are enough",
    "kind": "server, client, or site (a VPN gateway: both)",
    "common_name": "the name it certifies, e.g. web.corp.example",
    "csr": "the certificate signing request (PEM)",
    "recipient": "a recipient's .pub file (repeatable)",
    "no_passphrase": "leave the private key unencrypted",
    "names": "the DNS names the certificate is for",
    "server_name": "the name in the server's certificate, if not its host",
    "html": "also write the report as a web page here",
    "backups": "a folder of Vault backups to include",
    "note": "a note to remember whom the key is for",
    "service": "the service to put behind the edge",
    "tls_key": "the --tls-cert private key",
    "ca": "the CA certificate to trust",
    "key": "the private key",
    "verbose": "log debugging detail",
}


def explain_options(p):
    for a in p._actions:
        if isinstance(a, argparse._SubParsersAction):
            for c in a.choices.values():
                explain_options(c)
        elif a.help is None and a.dest in HELP:
            a.help = HELP[a.dest]


def parser():
    ap = argparse.ArgumentParser(prog=NAME, description="Post-quantum products: TLS 1.3 + mTLS, VPN, Vault and Readiness assessment.")
    ap.add_argument("--version", action="version", version=f"{NAME} {__version__}")
    ap.add_argument("--log-json", action="store_true", help="structured JSON logs")
    ap.add_argument("-v", "--verbose", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--dir", default="pki", help="CA folder (default: pki)")
    suite.add(sub)
    edge.add(sub)
    certificates.add(sub, common)
    vpn.add(sub, common)
    vault.add(sub)
    readiness.add(sub)
    suite.add_console(sub)
    explain_options(ap)
    return ap


def main(argv=None):
    ap = parser()
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        print(f"\nNew here? `{NAME} try` runs a one-minute tour; `{NAME} doctor` checks this machine.")
        sys.exit(0)
    h = logging.StreamHandler()
    h.setFormatter(JSONFormatter() if a.log_json else logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, handlers=[h])
    try:
        sys.exit(a.func(a))
    except BrokenPipeError:  # output piped into head, or a pager closed early
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)
    except (CAError, CharonError, WGError, VaultError, tls.TLSError, ValueError, OSError, ImportError) as e:
        print(f"error: {explain(e)}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
