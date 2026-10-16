"""Golden fixtures written by today's code (tools/make_fixtures.py), read by today's code.

Later stages point these same checks at the new products: legitimate data written before the restructure must stay readable.
"""
import datetime as dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography import x509

G = Path(__file__).resolve().parent
ROOT = G.parents[1]
PW = b"golden-test-only"
FAR = dt.datetime(2099, 1, 1, tzinfo=dt.timezone.utc)


def test_manifest_hashes_match():
    manifest = json.loads((G / "MANIFEST.json").read_text())
    assert manifest
    for rel, digest in manifest.items():
        assert hashlib.sha256((G / rel).read_bytes()).hexdigest() == digest, rel


def test_vault_archives_open_and_match_plaintext(tmp_path):
    from pqcsuite import vault
    plain = (G / "vault/plain.txt").read_bytes()
    for archive, key in (("unsigned.pqv", "recipient.key"), ("signed.pqv", "recipient.key"), ("cnsa2.pqv", "cnsa2.key")):
        out = tmp_path / archive
        target, _ = vault.decrypt(G / "vault" / archive, out, vault.Identity.load(G / "vault" / key, PW))
        assert Path(target).read_bytes() == plain, archive


def test_signed_archive_verifies_against_fixture_ca(tmp_path):
    from pqcsuite import vault
    _, who = vault.decrypt(G / "vault/signed.pqv", tmp_path, vault.Identity.load(G / "vault/recipient.key", PW),
                           ca=G / "pki/ca/ca.crt", crl=G / "pki/ca/crl.pem", expected_signer="signer.golden.invalid",
                           require_signature=True)
    assert "signer.golden.invalid" in who


def test_ca_folder_lists_revoked_certificate_in_crl():
    from pqcsuite.pki import CA
    ca = CA(G / "pki/ca", PW)
    revoked = [r for r in ca.records() if r.status == "revoked"]
    assert [r.common_name for r in revoked] == ["revoked.golden.invalid"]
    crl = x509.load_pem_x509_crl((G / "pki/ca/crl.pem").read_bytes())
    assert crl.get_revoked_certificate_by_serial_number(int(revoked[0].serial, 16)) is not None


def test_fixture_lifetimes_reach_past_2099():
    for pem in sorted((G / "pki").rglob("*.pem")) + sorted((G / "pki").rglob("*.crt")):
        if b"BEGIN CERTIFICATE" in pem.read_bytes():
            for cert in x509.load_pem_x509_certificates(pem.read_bytes()):
                assert cert.not_valid_after_utc > FAR, pem
    assert x509.load_pem_x509_crl((G / "pki/ca/crl.pem").read_bytes()).next_update_utc > FAR
    assert dt.datetime.fromisoformat(json.loads((G / "vpn/invite.pqcinvite").read_text())["expires"]) >= FAR


def test_invitation_parses_with_old_reader():
    from pqcsuite.vpn import join
    inv = join.parse((G / "vpn/invite.pqcinvite").read_text())
    assert inv["name"] == "laptop.golden.invalid"
    assert join.must_enroll(inv, G / "vpn/no-device-yet") is True


def test_cbom_baseline_validates_and_ignore_comment_suppresses():
    run = subprocess.run([sys.executable, str(ROOT / "products/readiness/tools/validate_cbom.py"), str(G / "readiness/baseline/cbom.json")],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    sightings = json.loads((G / "readiness/baseline/findings.json").read_text())["sightings"]
    md5_line = next(i for i, line in enumerate((G / "readiness/project/app.py").read_text().splitlines(), 1) if "md5" in line)
    on_line = [s for s in sightings if s["file"].endswith("app.py") and s["line"] == md5_line and s["algo"] == "MD5"]
    assert on_line and all(s["verdict"] == "suppressed" for s in on_line)


def test_example_configs_load_with_old_loaders():
    from pqcsuite.tls import edge
    from pqcsuite import vpn
    from pqcsuite.vpn import wireguard
    edge.load_config(G / "configs/edge.toml")
    vpn.load_config(G / "configs/vpn-hq.toml")
    vpn.load_config(G / "configs/vpn-branch.toml")
    wireguard.load_gateway(G / "configs/wireguard-gateway.toml")
