"""The CA's key outside this process: AWS KMS and any signing tool (HSM, smart card, signing service).

The KMS tests drive a real boto3 KMS client: botocore validates every request against AWS's published KMS API model, and a
hook answers each call with a signature OpenSSL 3.5 makes in ML-DSA's external-mu mode, the mode KMS uses for MessageType
EXTERNAL_MU. A certificate the CA signs that way must verify with standard (pure) ML-DSA, which proves the mu we compute is
the one FIPS 204 specifies. The live tests run the same flow against a real KMS key or HSM when their settings are given.
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization

from acxelin_core import openssl
from acxelin_core.pki import CA

pytestmark = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


def openssl_cli():
    folder = os.environ.get("ACXELIN_OPENSSL")
    for c in ([str(Path(folder).parent / "bin" / "openssl")] if folder else []) + [shutil.which("openssl") or ""]:
        if c and Path(c).exists() and "OpenSSL 3.5" <= subprocess.run([c, "version"], capture_output=True, text=True).stdout[:11]:
            return c
    pytest.skip("needs the openssl 3.5+ command line")


@pytest.fixture
def key(tmp_path):
    o = openssl_cli()
    subprocess.run([o, "genpkey", "-algorithm", "ML-DSA-87", "-out", tmp_path / "k.pem"], check=True)
    subprocess.run([o, "pkey", "-in", tmp_path / "k.pem", "-pubout", "-out", tmp_path / "pub.pem"], check=True)
    return o, tmp_path / "k.pem", tmp_path / "pub.pem"


TOOL = """import os, subprocess, sys, tempfile
data = sys.stdin.buffer.read()
fd, path = tempfile.mkstemp()
os.write(fd, data); os.close(fd)
try:
    sys.stdout.buffer.write(subprocess.run(sys.argv[1:] + ["-in", path], capture_output=True, check=True).stdout)
finally:
    os.unlink(path)
"""


def tool(*argv):
    """An external signing tool: reads the bytes on stdin and writes the signature (OpenSSL's one-shot ML-DSA needs a file)."""
    return [sys.executable, "-c", TOOL, *map(str, argv)]


def sign_file(o, k, data, *opts):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
    try:
        return subprocess.run([o, "pkeyutl", "-sign", "-inkey", str(k), *opts, "-in", f.name], capture_output=True, check=True).stdout
    finally:
        os.unlink(f.name)


def assert_signed_by(ca_root, pub_pem):
    """The CA certificate, an issued certificate and the CRL all verify under the external key with standard ML-DSA."""
    public = serialization.load_pem_public_key(pub_pem.read_bytes())
    ca = CA(ca_root)
    out, rec = ca.issue("web.example.invalid", "server", ["web.example.invalid"])
    crl = x509.load_pem_x509_crl(ca.crl(days=1))
    for thing in (ca.cert, x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())):
        public.verify(thing.signature, thing.tbs_certificate_bytes)
    public.verify(crl.signature, crl.tbs_certlist_bytes)
    return rec


def test_a_signing_tool_holds_the_ca_key(tmp_path, key):
    o, k, pub = key
    command = tool(o, "pkeyutl", "-sign", "-inkey", k, "-rawin")
    CA.init(tmp_path / "ca", "Tool Root", signer_config={"type": "command", "command": command, "public_key": str(pub)})
    assert not (tmp_path / "ca/ca.key").exists(), "the key stays with the tool"
    assert_signed_by(tmp_path / "ca", pub)


def test_a_failing_signing_tool_is_an_error_in_words(tmp_path, key):
    o, k, pub = key
    with pytest.raises(Exception, match="signing command failed"):
        CA.init(tmp_path / "ca", "Broken", signer_config={"type": "command", "command": [o, "pkeyutl", "-sign", "-inkey", "/nope.pem", "-rawin"],
                                                         "public_key": str(pub)})


def kms_client(o, k, pub, calls):
    boto3 = pytest.importorskip("boto3")
    client = boto3.client("kms", region_name="eu-west-1", aws_access_key_id="test", aws_secret_access_key="test")
    spki = serialization.load_pem_public_key(pub.read_bytes()).public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)

    class Http:
        status_code, headers, content = 200, {}, b""

    def answer(model, params, **_):
        body = json.loads(params["body"] or b"{}")
        calls.append((model.name, body))
        if model.name == "GetPublicKey":
            return Http(), {"KeyId": body["KeyId"], "PublicKey": spki, "KeySpec": "ML_DSA_87", "KeyUsage": "SIGN_VERIFY", "SigningAlgorithms": ["ML_DSA_SHAKE_256"]}
        if model.name == "Sign":
            mu = base64.b64decode(body["Message"])
            sig = sign_file(o, k, mu, "-pkeyopt", "mu:1")
            return Http(), {"KeyId": body["KeyId"], "Signature": sig, "SigningAlgorithm": body["SigningAlgorithm"]}
        raise AssertionError(f"unexpected KMS call {model.name}")
    client.meta.events.register("before-call.kms.*", answer)
    return client


def test_an_aws_kms_key_holds_the_ca_key(tmp_path, key):
    o, k, pub = key
    calls = []
    client = kms_client(o, k, pub, calls)
    with mock.patch("boto3.client", return_value=client):
        CA.init(tmp_path / "ca", "KMS Root", signer_config={"type": "aws-kms", "key_id": "alias/acxelin-root", "region": "eu-west-1"})
        assert_signed_by(tmp_path / "ca", pub)
    signs = [b for name, b in calls if name == "Sign"]
    assert signs and all(b["MessageType"] == "EXTERNAL_MU" and b["SigningAlgorithm"] == "ML_DSA_SHAKE_256" and len(base64.b64decode(b["Message"])) == 64
                         for b in signs), "only the 64-byte mu leaves this machine"


def test_a_kms_key_that_is_not_ml_dsa_is_refused(tmp_path, key):
    from acxelin_core.pki.signers import KMSSigner, SignerError
    client = mock.Mock()
    client.get_public_key.return_value = {"PublicKey": b"x", "KeySpec": "ECC_NIST_P256"}
    with pytest.raises(SignerError, match="not ML-DSA"):
        KMSSigner("alias/wrong", client=client)


@pytest.mark.skipif(not os.environ.get("ACXELIN_LIVE_KMS_KEY_ID"), reason="set ACXELIN_LIVE_KMS_KEY_ID (an ML_DSA_* key) and AWS credentials")
def test_live_aws_kms(tmp_path):
    from acxelin_core.pki.signers import KMSSigner
    key_id = os.environ["ACXELIN_LIVE_KMS_KEY_ID"]
    signer = KMSSigner(key_id, os.environ.get("AWS_REGION"))
    (tmp_path / "pub.pem").write_bytes(serialization.load_der_public_key(signer.spki).public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    CA.init(tmp_path / "ca", "Live KMS Root", algorithm=signer.algorithm, signer_config={"type": "aws-kms", "key_id": key_id, "region": os.environ.get("AWS_REGION")})
    assert_signed_by(tmp_path / "ca", tmp_path / "pub.pem")


@pytest.mark.skipif(not os.environ.get("ACXELIN_LIVE_HSM_COMMAND"), reason="set ACXELIN_LIVE_HSM_COMMAND (JSON list) and ACXELIN_LIVE_HSM_PUBLIC_KEY")
def test_live_hsm(tmp_path):
    command, pub = json.loads(os.environ["ACXELIN_LIVE_HSM_COMMAND"]), Path(os.environ["ACXELIN_LIVE_HSM_PUBLIC_KEY"])
    from acxelin_core.pki.signers import spki_algorithm, _pem_body
    CA.init(tmp_path / "ca", "Live HSM Root", algorithm=spki_algorithm(_pem_body(pub.read_bytes())), signer_config={"type": "command", "command": command, "public_key": str(pub)})
    assert_signed_by(tmp_path / "ca", pub)
