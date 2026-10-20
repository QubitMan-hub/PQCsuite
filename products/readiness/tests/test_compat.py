"""Old names keep working through acxelin-readiness 1.x, with a one-line warning; the new name always wins."""
import json

from acxelin_readiness import cli, compliance, inventory, pipeline


def test_old_settings_file_is_read_with_a_warning(tmp_path, capsys):
    (tmp_path / ".wolfpack.toml").write_text('exclude = ["old"]\n')
    assert cli.settings(None, tmp_path) == {"exclude": ["old"]}
    assert ".wolfpack.toml is the old name" in capsys.readouterr().err


def test_new_settings_file_wins_over_the_old_one(tmp_path, capsys):
    (tmp_path / ".wolfpack.toml").write_text('exclude = ["old"]\n')
    (tmp_path / ".acxelin-readiness.toml").write_text('exclude = ["new"]\n')
    assert cli.settings(None, tmp_path) == {"exclude": ["new"]}
    err = capsys.readouterr().err
    assert "ignored" in err and ".acxelin-readiness.toml" in err


def test_old_and_new_ignore_comments_both_suppress(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')  # wolfpack:ignore\nhashlib.sha1(b'x')  # acxelin:ignore\n")
    verdicts = {d.algo: d.verdict for d in pipeline.run(tmp_path, "t").detections if d.file == "a.py"}
    assert verdicts.get("MD5") == "suppressed" and verdicts.get("SHA-1") == "suppressed"


def test_old_cbom_properties_are_read_in_merges():
    component = {"properties": [{"name": "wolfpack:tier", "value": "critical"}]}
    assert inventory.prop(component, "acxelin:tier") == "critical"
    both = {"properties": [{"name": "wolfpack:tier", "value": "low"}, {"name": "acxelin:tier", "value": "high"}]}
    assert inventory.prop(both, "acxelin:tier") == "high"


def test_cnsa2_does_not_pass_aes_of_unknown_size(tmp_path):
    (tmp_path / "a.py").write_text("from cryptography.hazmat.primitives.ciphers import algorithms\nalgorithms.AES(key)\n")
    r = pipeline.run(tmp_path, "t")
    aes = [a for a in r.assets if a.algo == "AES" and not a.params.get("key_size")]
    assert aes, "the fixture must give an AES asset with no observed key size"
    result = compliance.evaluate(aes, [], {"profiles": ["cnsa-2.0"]})
    assert any(v["rule"] == "CNSA 2.0" and "unverified" in v["message"] for v in result["violations"]), json.dumps(result)
    assert not result["passed"]


def test_no_remedy_names_another_product(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nfrom Crypto.Cipher import AES\nfrom cryptography.hazmat.primitives.asymmetric import rsa\n"
                                   "rsa.generate_private_key(public_exponent=65537, key_size=2048)\nAES.new(k, AES.MODE_ECB)\nhashlib.md5(b'x').hexdigest()\n")
    (tmp_path / "nginx.conf").write_text("ssl_protocols TLSv1.1 TLSv1.2;\n")
    r = pipeline.run(tmp_path, "t")
    from acxelin_readiness import remedy
    texts = [f"{who} {fix}" for a in r.assets for who, fix in remedy.remedies(a)]
    assert texts, "the fixture must produce remedies"
    assert not [t for t in texts if "acxelin" in t.lower()], texts
