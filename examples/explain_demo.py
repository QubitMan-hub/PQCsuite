"""The idea behind Acxelin PQC Suite, shown with real post-quantum cryptography: why it matters, readiness, TLS + mTLS and the VPN.

    pip install cryptography
    python explain_demo.py           # pauses between steps: press Enter to go on
    python explain_demo.py --auto    # runs straight through

Runs on Windows, macOS or Linux, needs no administrator rights, starts no servers and contacts nothing. It uses the
products' algorithms: X25519 + ML-KEM-768 to agree keys, ML-DSA-65 for identities, AES-256-GCM for data. The products do
this inside standard TLS 1.3 and IPsec; this script shows the idea in a few dozen lines and does not replace them.
At the end it writes explain-demo-results.html next to itself.
"""
import argparse
import html
import json
import os
import sys
import textwrap
from datetime import datetime
from pathlib import Path

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey, MLDSA65PublicKey
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError:
    raise SystemExit("This demo needs cryptography 49 or newer, which includes ML-KEM and ML-DSA:  pip install -U cryptography") from None

LOG = []
AUTO = False


def step(title, story):
    LOG.append([title, story, []])
    print(f"\n{'=' * 72}\n{len(LOG)}. {title}\n{'=' * 72}\n{textwrap.fill(story, 72, break_on_hyphens=False)}")
    if not AUTO:
        try:
            input("\n  [Enter] to continue ")
        except EOFError:
            pass


def say(text, mark=""):
    lead = f"{mark:8}" if mark else ""
    print(textwrap.indent(textwrap.fill(lead + text, 70, subsequent_indent=" " * len(lead), break_on_hyphens=False), "  "))
    LOG[-1][2].append((mark, text))


def raw(public_key):
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def kdf(*secrets):
    return HKDF(hashes.SHA256(), 32, None, b"demo session key").derive(b"".join(secrets))


class Authority:
    """Your own certificate authority: it signs ID cards with ML-DSA and keeps a list of cancelled ones."""

    def __init__(self):
        self.key, self.revoked, self.serial = MLDSA65PrivateKey.generate(), set(), 1000

    def issue(self, name):
        key = MLDSA65PrivateKey.generate()
        self.serial += 1
        body = json.dumps({"name": name, "serial": self.serial, "key": raw(key.public_key()).hex()}).encode()
        return {"name": name, "serial": self.serial, "body": body, "sig": self.key.sign(body)}, key

    def check(self, card):
        """None if the card is genuine and not cancelled, else the reason it is refused."""
        if card is None:
            return "no ID card"
        try:
            self.key.public_key().verify(card["sig"], card["body"])
        except InvalidSignature:
            return "ID card not signed by our authority"
        return "ID card cancelled" if card["serial"] in self.revoked else None


def handshake(authority, server, client, transcript_note=b""):
    """A post-quantum handshake in the shape of TLS 1.3 with mutual authentication. Each side is (card, ML-DSA key).
    Returns (session key, what was negotiated) or raises PermissionError with the reason it was refused."""
    c_x, c_kem = X25519PrivateKey.generate(), MLKEM768PrivateKey.generate()              # client: two key shares
    hello = raw(c_x.public_key()) + c_kem.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    s_x = X25519PrivateKey.generate()                                                       # server: answers both
    kem_secret, kem_ct = c_kem.public_key().encapsulate()
    x_secret = s_x.exchange(c_x.public_key())
    transcript = hello + raw(s_x.public_key()) + kem_ct + transcript_note
    for side, (card, key) in (("server", server), ("client", client)):                      # each side shows its card
        reason = authority.check(card)
        if reason:
            raise PermissionError(f"{side}: {reason}")
        proof = key.sign(transcript)                                                        # and proves it holds the key
        MLDSA65PublicKey.from_public_bytes(bytes.fromhex(json.loads(card["body"])["key"])).verify(proof, transcript)
    assert c_x.exchange(s_x.public_key()) == x_secret and c_kem.decapsulate(kem_ct) == kem_secret
    return kdf(x_secret, kem_secret), f"X25519 + ML-KEM-768 key exchange, ML-DSA-65 identities ({len(hello)}-byte hello)"


def seal(key, text):
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, text.encode(), None)


def unseal(key, blob):
    return AESGCM(key).decrypt(blob[:12], blob[12:], None).decode()


def why_it_matters():
    step("Why it matters: harvest now, decrypt later",
         "Someone records your encrypted traffic today and keeps it. Years later a quantum computer can work out the classical "
         "X25519 secret from that recording. We play that future attacker by simply giving them the X25519 secret.")
    message = "Account 4417: transfer 12,400.00 to supplier"
    a, b = X25519PrivateKey.generate(), X25519PrivateKey.generate()
    x_secret = a.exchange(b.public_key())
    recording = seal(kdf(x_secret), message)
    say(f"classical session recorded today: {recording[12:28].hex()}...")
    say(f"years later, with the X25519 secret, the attacker reads: \"{unseal(kdf(x_secret), recording)}\"", "EXPOSED")
    kem = MLKEM768PrivateKey.generate()
    kem_secret, _ = kem.public_key().encapsulate()
    recording = seal(kdf(x_secret, kem_secret), message)
    try:
        unseal(kdf(x_secret, b"\0" * 32), recording)
        say("the hybrid recording opened (this should not happen)", "FAILED")
    except InvalidTag:
        say("hybrid session (X25519 + ML-KEM-768): the same attacker learns nothing; they would also need the ML-KEM secret, "
            "and no quantum computer is known to break ML-KEM", "SAFE")


def readiness():
    step("Readiness: where do we stand?",
         "Readiness makes a polite test connection to each server you list and asks which key exchanges it offers. The three "
         "servers below are made-up examples; the grading rule is the product's.")
    servers = {"portal.example.com": (["X25519MLKEM768"], "ML-DSA-65"),
               "api.example.com": (["X25519MLKEM768", "X25519"], "ECDSA P-256"),
               "records.example.com": (["X25519", "secp256r1"], "RSA-2048")}
    order = []
    for name, (groups, cert) in servers.items():
        pq = any("MLKEM" in g for g in groups)
        grade = "A" if pq and all("MLKEM" in g for g in groups) else "B" if pq else "C"
        meaning = {"A": "post-quantum only", "B": "post-quantum, old visitors still accepted", "C": "classical only: recordings can be opened later"}[grade]
        say(f"{name:22} offers {', '.join(groups)}; certificate {cert}: {meaning}", f"grade {grade}")
        order.append((grade, name))
    say("fix first: " + ", then ".join(n for g, n in sorted(order, reverse=True) if g != "A"))


def tls():
    ca = Authority()
    api, api_key = ca.issue("api.bank.example")
    partner, partner_key = ca.issue("partner-bank")
    request = "GET /accounts/4417"
    step("TLS + mTLS: a quantum-safe front door",
         "Your own authority gives ID cards (signed with ML-DSA) to the service and to a partner. The edge in front of the service "
         "agrees keys with X25519 + ML-KEM-768 and lets in only clients that show a valid card. The service itself is unchanged.")
    attempts = [("the partner, with its card", (partner, partner_key)),
                ("a stranger, with no card", (None, None)),
                ("a stranger, with a card it made itself", Authority().issue("partner-bank"))]
    for who, client in attempts:
        try:
            key, how = handshake(ca, (api, api_key), client)
            say(f"{who}: {how}; the service answers \"{unseal(key, seal(key, 'balance 12,400.00'))}\" to {request}", "OK")
        except PermissionError as e:
            say(f"{who}: {e}", "REFUSED")
    step("The partner's key is stolen: revoke it", "One change at the authority. The edge refuses the card from the next connection.")
    ca.revoked.add(partner["serial"])
    say(f"authority: card {partner['serial']} (partner-bank) cancelled")
    try:
        handshake(ca, (api, api_key), (partner, partner_key))
        say("the revoked partner got in (this should not happen)", "FAILED")
    except PermissionError as e:
        say(f"the partner, with its revoked card: {e}", "REFUSED")


def vpn():
    ca = Authority()
    hq, branch = ca.issue("hq.bank.example"), ca.issue("branch-0417.bank.example")
    step("VPN: a quantum-safe link between two offices",
         "Each office gateway has an ID card from your authority. The gateways agree the tunnel key with X25519 + ML-KEM-768 and "
         "check each other's cards; every packet is then sealed with AES-256-GCM. The product does this with strongSwan IPsec.")
    key, how = handshake(ca, hq, branch, b"ipsec")
    packet = seal(key, "payroll-october.csv, 18 kB")
    say(f"tunnel up: {how}")
    say(f"what anyone on the internet sees: {packet[12:40].hex()}...")
    say(f"what headquarters receives: \"{unseal(key, packet)}\"", "OK")
    new_key, _ = handshake(ca, hq, branch, b"ipsec rekey")
    say(f"keys are renewed regularly: tunnel key {key[:4].hex()}... is replaced by {new_key[:4].hex()}..., so one stolen key "
        "opens only a short stretch of traffic", True)
    step("The branch is compromised: cut it off",
         "One change at the authority. At the next key renewal headquarters refuses the branch's card, and the tunnel is gone.")
    ca.revoked.add(branch[0]["serial"])
    try:
        handshake(ca, hq, branch, b"ipsec rekey")
        say("the revoked branch kept its tunnel (this should not happen)", "FAILED")
    except PermissionError as e:
        say(f"branch 0417 at the next key renewal: {e}; tunnel down", "REFUSED")


PAGE = """<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PQC Suite demo results</title><style>
body {{ margin: 0; background: #faf9f5; color: #3f4c59; font: 16px/1.6 Roboto, "Segoe UI", system-ui, sans-serif; }}
main {{ max-width: 860px; margin: 0 auto; padding: 48px 20px; }}
h1, h2 {{ font-family: "Host Grotesk", "Segoe UI", system-ui, sans-serif; color: #2e3c4e; font-weight: 500; }}
h1 {{ font-size: 38px; margin: 6px 0 24px; }} h2 {{ font-size: 21px; margin: 0 0 6px; }}
.kicker {{ font-size: 13px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; color: #8a6100; margin: 0; }}
section {{ background: #fff; border: 1px solid #e6e0d2; border-radius: 12px; padding: 20px 24px; margin-bottom: 14px; }}
ul {{ padding: 0; list-style: none; }} li {{ margin: 6px 0; padding-left: 12px; border-left: 4px solid #e6e0d2; font-size: 15px; }}
li.ok {{ border-color: #26734d; }} li.no {{ border-color: #b3431f; }}
b.ok {{ color: #26734d; }} b.no {{ color: #b3431f; }} footer {{ color: #636e78; font-size: 13px; }}
</style><main><p class="kicker">Acxelin PQC Suite · demo</p><h1>The idea, shown with real post-quantum cryptography</h1>
{sections}<footer>Run on {when}. Everything ran on this computer; nothing was sent anywhere.</footer></main></html>"""


def report():
    sections = []
    for i, (title, story, lines) in enumerate(LOG, 1):
        tone = {"OK": "ok", "SAFE": "ok", "REFUSED": "no", "EXPOSED": "no", "FAILED": "no"}
        items = "".join(f'<li class="{tone.get(m, "")}">' + (f'<b class="{tone.get(m, "")}">{m}</b> ' if m else "") + f"{html.escape(t)}</li>"
                        for m, t in lines)
        sections.append(f"<section><h2>{i}. {html.escape(title)}</h2><p>{html.escape(story)}</p><ul>{items}</ul></section>")
    out = Path(__file__).resolve().with_name("explain-demo-results.html")
    out.write_text(PAGE.format(sections="".join(sections), when=datetime.now().strftime("%d %B %Y, %H:%M")), encoding="utf-8")
    return out


def main():
    global AUTO
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--auto", action="store_true", help="run without pauses")
    AUTO = ap.parse_args().auto
    sys.stdout.reconfigure(errors="replace")
    print("Acxelin PQC Suite: the idea, shown with real post-quantum cryptography on this computer.")
    why_it_matters()
    readiness()
    tls()
    vpn()
    print(f"\n{'=' * 72}\nDone. A summary is in {report()}")
    if any(m == "FAILED" for _, _, lines in LOG for m, _ in lines):
        raise SystemExit("A step did not go as expected; see FAILED above.")


if __name__ == "__main__":
    main()
