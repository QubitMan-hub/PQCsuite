"""The CBOM merge contract (spec: "CBOM contract"): identity per asset type, every system's observations kept, deterministic content."""
import json

from acxelin_readiness import inventory


def algo(name, param=None, level=None, loc="a.py:1"):
    ap = {"primitive": "ae"} | ({"parameterSetIdentifier": param} if param else {}) | ({"nistQuantumSecurityLevel": level} if level is not None else {})
    return {"type": "cryptographic-asset", "name": name, "bom-ref": f"x/{name}/{param}", "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": ap},
            "evidence": {"occurrences": [{"location": loc}]}}


def cert(fp, loc):
    return {"type": "cryptographic-asset", "name": "CN=api.example.invalid", "bom-ref": f"c/{loc}", "cryptoProperties": {"assetType": "certificate"},
            "properties": [{"name": "acxelin:fingerprint", "value": fp}], "evidence": {"occurrences": [{"location": loc}]}}


def psk(loc):
    return {"type": "cryptographic-asset", "name": "IKE PSK", "bom-ref": f"k/{loc}", "cryptoProperties": {"assetType": "related-crypto-material",
            "relatedCryptoMaterialProperties": {"type": "secret-key", "size": 256}}, "evidence": {"occurrences": [{"location": loc}]}}


def system(tmp_path, name, components):
    p = tmp_path / name / "cbom.json"
    p.parent.mkdir()
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": name}}, "components": components}))
    return p


def merged(tmp_path):
    a = system(tmp_path, "alpha-sys", [cert("ab" * 32, "a:443"), algo("AES", "128", level=1), psk("tunnel-a"), algo("SHA-256", level=1)])
    b = system(tmp_path, "beta-sys", [cert("ab" * 32, "b:443"), algo("AES", "256", level=1), psk("tunnel-b"), algo("SHA-256", level=2)])
    taken = set()
    return inventory.build("org", [inventory.load(p, taken) for p in (a, b)])


def by(bom, name):
    return [c for c in bom["components"] if c.get("name") == name and c["type"] == "cryptographic-asset"]


def test_one_certificate_seen_twice_is_one_asset_with_both_occurrences(tmp_path):
    [c] = by(merged(tmp_path), "CN=api.example.invalid")
    assert sorted(o["location"] for o in c["evidence"]["occurrences"]) == ["alpha-sys: a:443", "beta-sys: b:443"]


def test_same_algorithm_name_with_different_parameters_stays_two_assets(tmp_path):
    assert len(by(merged(tmp_path), "AES")) == 2


def test_secret_material_is_never_merged_across_systems(tmp_path):
    assert len(by(merged(tmp_path), "IKE PSK")) == 2


def test_disagreement_keeps_both_observations_and_names_the_conflict(tmp_path):
    [c] = by(merged(tmp_path), "SHA-256")
    props = {p["name"]: p["value"] for p in c["properties"]}
    assert "nistQuantumSecurityLevel" in props["acxelin:conflict"]
    observed = {(o["system"], o["value"]) for o in json.loads(props["acxelin:observations"]) if o["field"] == "nistQuantumSecurityLevel"}
    assert observed == {("alpha-sys", 1), ("beta-sys", 2)}
    assert "nistQuantumSecurityLevel" not in c["cryptoProperties"]["algorithmProperties"]


def test_content_is_deterministic_apart_from_export_metadata(tmp_path):
    first, second = merged(tmp_path), None
    import shutil
    shutil.rmtree(tmp_path / "alpha-sys"), shutil.rmtree(tmp_path / "beta-sys")
    second = merged(tmp_path)
    for bom in (first, second):
        del bom["serialNumber"], bom["metadata"]["timestamp"], bom["metadata"]["tools"]
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    refs = [c["bom-ref"] for c in first["components"]]
    assert refs == sorted(refs)


def test_scanner_certificates_carry_the_fingerprint_the_merge_keys_on():
    from acxelin_readiness import cbom
    from pathlib import Path
    import tempfile
    from acxelin_core.pki import CA
    with tempfile.TemporaryDirectory() as d:
        CA.init(Path(d) / "ca", "Root").issue("edge.invalid", "server", out=Path(d) / "edge")
        from acxelin_readiness import pipeline
        r = pipeline.run(d, "p")
        bom = cbom.build("p", r.assets, r.artifacts, r.libraries, r.endpoints)
    certs = [c for c in bom["components"] if (c.get("cryptoProperties") or {}).get("assetType") == "certificate"]
    assert certs and all(inventory.identity(c, "p")[0:1] == ["certificate"] and len(inventory.identity(c, "p")) == 2 for c in certs)
