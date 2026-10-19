"""The VPN's CBOM is something Acxelin Readiness can take in: `acxelin-readiness merge` reads it like any other system's CBOM and
ranks what it finds. Neither product imports the other; only this repository-level test sees both."""
import json
import textwrap

from acxelin_core.pki import CA
from acxelin_readiness import inventory as readiness
from acxelin_vpn import inventory as vpn


def test_readiness_merges_the_vpn_cbom_and_sees_its_post_quantum_tunnels(tmp_path):
    ca = CA.init(tmp_path / "pki", "VPN Root")
    ca.issue("hq.acme", "site", ["203.0.113.10"], out=tmp_path / "hq")
    ca.crl()
    site = tmp_path / "hq.toml"
    site.write_text(textwrap.dedent(f"""
        [site]
        name = "hq.acme"
        address = "203.0.113.10"
        cert = "{(tmp_path / 'hq' / 'chain.pem').as_posix()}"
        key = "{(tmp_path / 'hq' / 'key.pem').as_posix()}"
        ca = "{(tmp_path / 'pki' / 'ca.crt').as_posix()}"
        crl = "{(tmp_path / 'pki' / 'crl.pem').as_posix()}"
        keyring_listen = "0.0.0.0:7443"
        [[peer]]
        name = "branch.acme"
        address = "198.51.100.7"
        local_subnets = ["10.1.0.0/16"]
        remote_subnets = ["10.2.0.0/16"]
        """))
    (tmp_path / "vpn").mkdir()
    (tmp_path / "vpn" / "cbom.json").write_text(vpn.cbom([site], "Acme VPN"))
    systems = readiness.run([tmp_path / "vpn"], "Acme", tmp_path / "merged")
    assert [s["name"] for s in systems] == ["Acme VPN"] and systems[0]["tool"].startswith("acxelin-vpn")
    tiers = {a["name"]: a["tier"] for a in systems[0]["assets"]}
    assert tiers["ML-KEM-768"] == tiers["X25519MLKEM768"] == tiers["ML-DSA-65"] == "ok"
    assert tiers["X25519"] not in ("ok", None), "the classical half of the hybrid is still ranked as quantum-exposed"
    assert systems[0]["readiness"]["hybrid"] is True
    others = {o["component"]["cryptoProperties"]["assetType"] for o in systems[0]["others"]}
    assert {"certificate", "related-crypto-material", "protocol"} <= others
    merged = json.loads((tmp_path / "merged" / "cbom.json").read_text())
    assert any(c.get("name") == "CN=hq.acme" for c in merged["components"])
