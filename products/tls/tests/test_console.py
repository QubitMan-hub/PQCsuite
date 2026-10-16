"""Acxelin TLS console journeys at the API (spec: "Where each console feature goes"), on the shared console mechanism."""
import json
import logging
import urllib.error
import urllib.request

import pytest
from acxelin_core import console as core
from acxelin_core import openssl

from acxelin_tls import console as tc

needs_openssl = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")
PASS = "ca-pass-7f3e91"


@pytest.fixture
def home(tmp_path):
    return tmp_path / "state"


@pytest.fixture
def app(home):
    return tc.build(home)


def call(app, method, path, body=None):
    return app.routes[(method, path)](body or {})


def make_ca(app, passphrase=None):
    return call(app, "POST", "/api/ca/create", {"name": "Example Root CA", "passphrase": passphrase})


def issue(app, kind="server", cn="web.example.invalid", names=None):
    return call(app, "POST", "/api/certificates/issue", {"kind": kind, "common_name": cn, "names": names or []})[1]


def test_first_run_has_no_ca_and_creating_one_needs_a_name(app):
    assert call(app, "GET", "/api/status")[1]["configured"] is False
    with pytest.raises(ValueError, match="name"):
        call(app, "POST", "/api/ca/create", {"name": "  "})
    assert make_ca(app)[0] == 200
    status = call(app, "GET", "/api/status")[1]
    assert status["configured"] and status["name"] == "Example Root CA" and status["algorithm"] == "ML-DSA-87" and status["encrypted"] is False
    with pytest.raises(ValueError, match="already"):
        make_ca(app)


def test_an_encrypted_ca_stays_locked_after_a_restart_until_the_right_passphrase(app, home):
    make_ca(app, PASS)
    assert b"ENCRYPTED" in (home / "ca/ca.key").read_bytes()
    assert call(app, "GET", "/api/status")[1]["unlocked"] is True
    again = tc.build(home)
    status = call(again, "GET", "/api/status")[1]
    assert status["encrypted"] and status["unlocked"] is False
    with pytest.raises(ValueError, match="unlock"):
        issue(again)
    with pytest.raises(ValueError, match="passphrase"):
        call(again, "POST", "/api/ca/unlock", {"passphrase": "wrong"})
    call(again, "POST", "/api/ca/unlock", {"passphrase": PASS})
    assert issue(again)["common_name"] == "web.example.invalid"


def test_issued_certificates_are_listed_and_their_keys_stay_on_disk(app, home):
    make_ca(app)
    out = issue(app, names=["127.0.0.1"])
    assert (home / out["folder"] / "chain.pem").exists() and (home / out["folder"] / "key.pem").exists()
    rows = call(app, "GET", "/api/certificates")[1]["certificates"]
    assert [(r["common_name"], r["kind"], r["status"]) for r in rows] == [("web.example.invalid", "server", "valid")]
    assert "PRIVATE KEY" not in json.dumps(out) + json.dumps(rows)


@pytest.mark.parametrize("cn", ["", "bad name!", "x" * 300])
def test_certificate_names_are_checked(app, cn):
    make_ca(app)
    with pytest.raises(ValueError):
        issue(app, cn=cn)


def test_issuing_needs_a_ca_first(app):
    with pytest.raises(ValueError, match="create"):
        issue(app)


def test_revoking_lists_the_certificate_as_revoked_and_refreshes_the_crl(app, home):
    make_ca(app)
    row = issue(app, kind="client", cn="alice.example.invalid")
    before = call(app, "GET", "/api/status")[1]["crl"]
    call(app, "POST", "/api/certificates/revoke", {"serial": row["serial"], "reason": "keyCompromise"})
    rows = call(app, "GET", "/api/certificates")[1]["certificates"]
    assert [r["status"] for r in rows] == ["revoked"]
    from cryptography import x509
    crl = x509.load_pem_x509_crl((home / "ca/crl.pem").read_bytes())
    assert crl.get_revoked_certificate_by_serial_number(int(row["serial"], 16)) is not None
    assert call(app, "GET", "/api/status")[1]["crl"]["days_left"] >= (before or {"days_left": 0})["days_left"] > -1
    with pytest.raises(ValueError, match="serial"):
        call(app, "POST", "/api/certificates/revoke", {"serial": "deadbeefdeadbeef"})


def test_the_crl_can_be_refreshed_on_demand(app):
    make_ca(app)
    out = call(app, "POST", "/api/crl/refresh")[1]
    assert out["days_left"] > 0


@needs_openssl
def test_edges_report_their_policy_and_a_connection_test_names_the_negotiated_group(app, home):
    from acxelin_tls.edge import Edge, Route, serve_metrics
    make_ca(app)
    cert = issue(app, cn="localhost", names=["127.0.0.1"])
    edge = Edge(Route("shop", "terminate", "127.0.0.1:0", "127.0.0.1:9", cert=str(home / cert["folder"] / "chain.pem"), key=str(home / cert["folder"] / "key.pem"))).start()
    metrics = serve_metrics("127.0.0.1:0", [edge], None)
    try:
        url = f"http://127.0.0.1:{metrics.server_address[1]}"
        call(app, "POST", "/api/edges/add", {"url": url})
        shown = call(app, "GET", "/api/edges")[1]["edges"]
        assert shown[0]["url"] == url and shown[0]["status"]["shop"]["policy"] == "strict" and shown[0]["error"] is None
        test = call(app, "POST", "/api/edges/test", {"target": f"127.0.0.1:{edge.port}", "server_name": "localhost"})[1]
        assert test["group"] in ("X25519MLKEM768", "SecP384r1MLKEM1024", "SecP256r1MLKEM768") and test["peer_key"].startswith("ML-DSA")
    finally:
        edge.stop(0)
        metrics.shutdown()


@needs_openssl
def test_an_unreachable_edge_and_a_refused_connection_are_explained_in_words(app):
    make_ca(app)
    call(app, "POST", "/api/edges/add", {"url": "http://127.0.0.1:1"})
    shown = call(app, "GET", "/api/edges")[1]["edges"][0]
    assert shown["error"] and "Traceback" not in shown["error"]
    with pytest.raises(ValueError, match="connection refused"):
        call(app, "POST", "/api/edges/test", {"target": "127.0.0.1:1"})


@pytest.mark.parametrize("url", ["ftp://x", "not a url", "http://", "javascript:alert(1)"])
def test_edge_addresses_must_be_http_urls(app, url):
    with pytest.raises(ValueError, match="http"):
        call(app, "POST", "/api/edges/add", {"url": url})


@needs_openssl
def test_health_lists_each_check_with_its_level_and_what_to_do(app):
    make_ca(app)
    rows = call(app, "GET", "/api/health")[1]["checks"]
    assert rows and all(set(r) >= {"level", "message"} and r["level"] in ("ok", "warn", "fail") for r in rows)
    assert any("OpenSSL" in r["message"] and r["level"] == "ok" for r in rows)


def test_secrets_never_reach_responses_logs_or_files(app, home, caplog):
    caplog.set_level(logging.DEBUG)
    responses = [make_ca(app, PASS)[1], call(app, "GET", "/api/status")[1], issue(app), call(app, "GET", "/api/certificates")[1]]
    with pytest.raises(ValueError):
        call(tc.build(home), "POST", "/api/ca/unlock", {"passphrase": "wrong-" + PASS})
    assert PASS not in json.dumps(responses) and PASS not in caplog.text
    assert PASS.encode() not in b"".join(p.read_bytes() for p in home.rglob("*") if p.is_file())


def test_the_console_signs_in_over_http_and_loads_no_other_product(app, home):
    server = core.start(app, home, port=0)
    port = server.server_address[1]
    try:
        page = urllib.request.urlopen(f"http://127.0.0.1:{port}/").read()
        assert b"Acxelin TLS" in page and page.count(b"<script>") == 1
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status")
        assert e.value.code == 401
    finally:
        server.shutdown()
    import subprocess
    import sys
    code = "import sys, acxelin_tls.console;" \
           "bad=[m for m in sys.modules if m.split('.')[0] in ('pqcsuite','acxelin_readiness','acxelin_vpn','acxelin_vault','wolfpack')]; assert not bad, bad"
    assert subprocess.run([sys.executable, "-c", code]).returncode == 0
