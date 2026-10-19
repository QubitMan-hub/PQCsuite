"""`acxelin-vpn inventory --cbom`: what the VPN protects traffic with, as a CycloneDX 1.6 CBOM. Every tunnel's algorithms, the
key agreement's groups and signatures, the certificates, and PSK/PPK/private-key presence (type and size, never a value). The
file validates, is the same bytes every time for the same configuration, and holds no secret in any common encoding."""
import base64
import contextlib
import io
import json
import textwrap
from pathlib import Path

import pytest
from acxelin_core.pki import CA
from acxelin_core.pki.est import create_token
from cryptography.hazmat.primitives import serialization

from acxelin_vpn import cli, inventory
from acxelin_vpn.wireguard import private_key
from support_vpn import REASON

SCHEMAS = Path(__file__).with_name("schemas")
CA_PASS, KEY_PASS = "ca-pass-90e2", "site-key-pass-4b17"


@pytest.fixture
def deployment(tmp_path, monkeypatch):
    """A headquarters site with two branches (one per profile), a WireGuard gateway, and every secret they hold."""
    d = tmp_path
    monkeypatch.setenv("TEST_SITE_KEY_PASS", KEY_PASS)
    ca = CA.init(d / "pki", "VPN Root", passphrase=CA_PASS.encode())
    for name, kind in (("hq.acme", "site"), ("vpn.acme", "server")):
        ca.issue(name, kind, ["203.0.113.10"], out=d / name, passphrase=KEY_PASS.encode())
    ca.crl()
    wg_private, _ = private_key(d / "wireguard.key")
    (d / "hq.toml").write_text(textwrap.dedent(f"""
        [site]
        name = "hq.acme"
        address = "203.0.113.10"
        cert = "{(d / 'hq.acme' / 'chain.pem').as_posix()}"
        key = "{(d / 'hq.acme' / 'key.pem').as_posix()}"
        ca = "{(d / 'pki' / 'ca.crt').as_posix()}"
        crl = "{(d / 'pki' / 'crl.pem').as_posix()}"
        key_passphrase_env = "TEST_SITE_KEY_PASS"
        keyring_listen = "0.0.0.0:7443"
        [[peer]]
        name = "branch1.acme"
        address = "198.51.100.7"
        local_subnets = ["10.1.0.0/16"]
        remote_subnets = ["10.2.0.0/16"]
        [[peer]]
        name = "branch2.acme"
        address = "198.51.100.8"
        local_subnets = ["10.1.0.0/16"]
        remote_subnets = ["10.3.0.0/16"]
        profile = "high"
        rotate_minutes = 30
        """))
    (d / "gateway.toml").write_text(textwrap.dedent(f"""
        [wireguard]
        name = "vpn.acme"
        endpoint = "vpn.acme:51820"
        keyring_listen = "0.0.0.0:7444"
        pool = "10.99.0.0/24"
        cert = "{(d / 'vpn.acme' / 'chain.pem').as_posix()}"
        key = "{(d / 'vpn.acme' / 'key.pem').as_posix()}"
        ca = "{(d / 'pki' / 'ca.crt').as_posix()}"
        crl = "{(d / 'pki' / 'crl.pem').as_posix()}"
        private_key = "{(d / 'wireguard.key').as_posix()}"
        rotate_minutes = 2
        """))
    secrets = [CA_PASS.encode(), KEY_PASS.encode(), base64.b64decode(wg_private), create_token(ca, "alice", "client").encode()]
    for key in (d / "pki" / "ca.key", d / "hq.acme" / "key.pem", d / "vpn.acme" / "key.pem"):
        pem = key.read_bytes()
        loaded = serialization.load_pem_private_key(pem, (CA_PASS if "pki" in str(key) else KEY_PASS).encode())
        secrets += [pem, loaded.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())]
    return d, [d / "hq.toml", d / "gateway.toml"], secrets


def export(configs, name="Acme VPN"):
    return inventory.cbom(configs, name)


def validate(bom):
    from jsonschema import Draft7Validator
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT7
    docs = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in SCHEMAS.glob("*.json")}
    reg = Registry()
    for n, doc in docs.items():
        r = Resource.from_contents(doc, default_specification=DRAFT7)
        reg = reg.with_resource(n, r).with_resource(doc.get("$id", n), r)
    return list(Draft7Validator(docs["bom-1.6.schema.json"], registry=reg).iter_errors(bom))


def test_the_cbom_validates_against_cyclonedx_1_6(deployment):
    _, configs, _ = deployment
    errors = validate(json.loads(export(configs)))
    assert errors == [], [(list(e.path), e.message[:160]) for e in errors[:5]]


def test_the_same_configuration_gives_the_same_bytes(deployment):
    _, configs, _ = deployment
    assert export(configs) == export(configs) == export(list(reversed(configs)))
    assert export(configs) != export(configs, "Another VPN")


def by_name(bom):
    out = {}
    for c in bom["components"]:
        out.setdefault(c["name"], []).append(c)
    return out


def test_every_tunnel_algorithm_group_signature_and_protocol_is_listed(deployment):
    bom = json.loads(export(deployment[1]))
    names = by_name(bom)
    for algo in ("ML-KEM-768", "ML-KEM-1024", "X25519", "ECDH-P-384", "AES-256-GCM", "HMAC-SHA384", "HMAC-SHA512",
                 "X25519MLKEM768", "SecP384r1MLKEM1024", "SecP256r1MLKEM768", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
                 "ChaCha20-Poly1305", "BLAKE2s"):
        assert names.get(algo) and names[algo][0]["cryptoProperties"]["assetType"] == "algorithm", algo
    assert names["ML-KEM-768"][0]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    protocols = {c["name"]: c["cryptoProperties"]["protocolProperties"] for c in bom["components"]
                 if c["cryptoProperties"]["assetType"] == "protocol"}
    assert {"TLS 1.3", "IKEv2", "IPsec ESP", "WireGuard"} <= set(protocols)
    assert protocols["TLS 1.3"]["version"] == "1.3" and {"TLS_AES_256_GCM_SHA384"} <= {s["name"] for s in protocols["TLS 1.3"]["cipherSuites"]}
    refs = {c["bom-ref"] for c in bom["components"]}
    assert len(refs) == len(bom["components"]), "every bom-ref is unique"
    used = json.dumps(bom)
    for p in protocols.values():
        for s in p.get("cipherSuites", []):
            assert set(s["algorithms"]) <= refs
    tunnels = [c for c in names.get("tunnel hq.acme to branch2.acme", [])]
    assert tunnels and "ML-KEM-1024" in json.dumps(tunnels[0]) and "ECDH-P-384" in json.dumps(tunnels[0])
    assert "pki" in used


def test_certificates_are_listed_with_their_ml_dsa_signature(deployment):
    bom = json.loads(export(deployment[1]))
    certs = {c["name"]: c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "certificate"}
    assert {"CN=hq.acme", "CN=vpn.acme", "CN=VPN Root"} <= set(certs)
    refs = {c["bom-ref"]: c["name"] for c in bom["components"]}
    hq = certs["CN=hq.acme"]["cryptoProperties"]["certificateProperties"]
    assert hq["issuerName"] == "CN=VPN Root" and hq["notValidAfter"] and refs[hq["signatureAlgorithmRef"]] == "ML-DSA-87"
    assert refs[certs["CN=VPN Root"]["cryptoProperties"]["certificateProperties"]["signatureAlgorithmRef"]] == "ML-DSA-87"


def test_keys_and_shared_secrets_are_listed_by_type_and_size_only(deployment):
    bom = json.loads(export(deployment[1]))
    material = [c for c in bom["components"] if c["cryptoProperties"]["assetType"] == "related-crypto-material"]
    kinds = {(c["name"], c["cryptoProperties"]["relatedCryptoMaterialProperties"]["type"]) for c in material}
    assert {("IKE PSK hq.acme to branch1.acme", "secret-key"), ("PPK hq.acme to branch1.acme", "secret-key"),
            ("IKE PSK hq.acme to branch2.acme", "secret-key"), ("PPK hq.acme to branch2.acme", "secret-key"),
            ("WireGuard PSK per person at vpn.acme", "secret-key"), ("WireGuard private key of vpn.acme", "private-key"),
            ("private key of hq.acme", "private-key"), ("private key of vpn.acme", "private-key")} <= kinds
    for c in material:
        rp = c["cryptoProperties"]["relatedCryptoMaterialProperties"]
        assert "value" not in rp and rp.get("size") in (256, None), c["name"]
    hq_key = next(c for c in material if c["name"] == "private key of hq.acme")
    assert {"name": "acxelin:encrypted", "value": "yes"} in hq_key["properties"]


def variants(secret):
    """The ways a secret could leak into a text file: as it is, as hex, as base64 (standard, URL-safe, unpadded) and as the
    base64 lines of a PEM body."""
    b64 = base64.b64encode(secret).decode()
    out = {secret.decode("latin-1"), secret.hex(), secret.hex().upper(), b64, base64.urlsafe_b64encode(secret).decode().rstrip("="), b64.rstrip("=")}
    out |= {line for line in secret.decode("latin-1").splitlines() if len(line) >= 16 and not line.startswith("-----")}
    out |= {b64[i:i + 64] for i in range(0, len(b64), 64) if len(b64[i:i + 64]) >= 16}
    return {v for v in out if len(v) >= 8}


def test_no_secret_reaches_the_cbom_in_any_encoding(deployment, tmp_path):
    _, configs, secrets = deployment
    secrets += agreed_keys(deployment)
    out = tmp_path / "cbom.json"
    with contextlib.redirect_stdout(io.StringIO()), pytest.raises(SystemExit) as e:
        cli.main(["inventory", "--config", str(configs[0]), "--config", str(configs[1]), "--cbom", str(out), "--name", "Acme VPN"])
    assert e.value.code == 0
    text = out.read_bytes().decode("latin-1")
    leaked = [(i, v[:12]) for i, s in enumerate(secrets) for v in variants(s) if v in text]
    assert leaked == []
    assert out.read_bytes() == export(configs).encode(), "the command writes what the library builds"


def agreed_keys(deployment):
    """The PSK and PPK a real key agreement over post-quantum mutual TLS gives hq and branch1 (none without OpenSSL 3.5)."""
    if REASON:
        return []
    from unittest.mock import Mock
    from acxelin_core import tls
    from acxelin_core.server import Server
    from acxelin_vpn import Peer, Site, controller
    from acxelin_vpn.policies import POLICY
    d = deployment[0]
    CA(d / "pki", CA_PASS.encode()).issue("branch1.acme", "site", ["203.0.113.11"], out=d / "branch1.acme")
    hq = Site("hq.acme", "127.0.0.1", str(d / "hq.acme/chain.pem"), str(d / "hq.acme/key.pem"), str(d / "pki/ca.crt"),
              key_passphrase_env="TEST_SITE_KEY_PASS", peers=[Peer("branch1.acme", "127.0.0.1", ["10.1.0.0/16"], ["10.2.0.0/16"])])
    r = controller.Controller(hq, charon=Mock())
    srv = Server(("127.0.0.1", 0), lambda: tls.server_context(POLICY, hq.cert, hq.key, hq.ca, True, KEY_PASS.encode()), r.respond)
    srv.start()
    try:
        br = Site("branch1.acme", "127.0.0.1", str(d / "branch1.acme/chain.pem"), str(d / "branch1.acme/key.pem"), str(d / "pki/ca.crt"),
                  peers=[Peer("hq.acme", "127.0.0.1", [], [], initiate=True, keyring=f"127.0.0.1:{srv.port}")])
        i = controller.Controller(br, charon=Mock())
        i.agree(br.peers[0])
    finally:
        srv.stop(1)
    _, _, psk, ppk, _, _ = i.charon.load_keys.call_args.args
    return [psk, ppk]


def test_a_missing_certificate_is_named_not_fatal(deployment):
    d, configs, _ = deployment
    (d / "vpn.acme" / "chain.pem").unlink()
    bom = json.loads(export(configs))
    assert any(p == {"name": "acxelin:missing", "value": (d / "vpn.acme" / "chain.pem").as_posix()}
               for c in bom["components"] for p in c.get("properties", []))
    assert validate(bom) == []


def test_a_file_that_is_not_a_vpn_configuration_is_refused_in_words(tmp_path):
    bad = tmp_path / "edge.toml"
    bad.write_text("[[edge]]\nname = 'x'\n")
    with pytest.raises(ValueError, match="no \\[site\\] or \\[wireguard\\]"):
        export([bad])
