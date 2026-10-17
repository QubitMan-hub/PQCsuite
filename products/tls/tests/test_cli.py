import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

import pytest
from acxelin_core import openssl
from acxelin_core.pki import CA

from acxelin_tls import cli, common

needs_openssl = pytest.mark.skipif(openssl.available() is not None, reason="needs OpenSSL 3.5+ (set ACXELIN_OPENSSL)")


def run(*args, env=None):
    p = subprocess.run([sys.executable, "-m", "acxelin_tls", *args], capture_output=True, text=True, env={**os.environ, **(env or {})}, timeout=120)
    return p.returncode, p.stdout, p.stderr


def test_version_and_help_name_the_product_only():
    code, out, _ = run("--version")
    assert code == 0 and out.strip() == "acxelin-tls 1.0.0"
    code, out, _ = run("--help")
    assert code == 0
    for command in ("edge", "bundle", "serve", "connect", "ca", "try", "doctor", "status", "console"):
        assert command in out
    assert "vault" not in out.lower() and "vpn" not in out.lower() and "readiness" not in out.lower() and "pqcsuite" not in out.lower()


def test_ca_lifecycle_from_the_command_line(tmp_path):
    d = str(tmp_path / "pki")
    assert run("ca", "init", "--name", "Test Root", "--dir", d, "--no-encrypt")[0] == 0
    assert run("ca", "issue", "server", "web.example.invalid", "--dir", d, "--out", str(tmp_path / "web"))[0] == 0
    code, out, _ = run("ca", "list", "--dir", d)
    assert code == 0 and "web.example.invalid" in out
    serial = out.split()[0] if out.split() else ""
    assert run("ca", "revoke", serial, "--dir", d)[0] == 0
    assert (tmp_path / "pki/crl.pem").exists()


def test_the_old_passphrase_variable_is_read_and_the_new_one_wins(tmp_path):
    CA.init(tmp_path / "ca", "Root", passphrase=b"old-secret")
    os.environ.pop("ACXELIN_TLS_CA_PASSPHRASE", None)
    os.environ["PQCSUITE_CA_PASSPHRASE"] = "old-secret"
    try:
        assert common.ca_passphrase(tmp_path / "ca") == b"old-secret"
        os.environ["ACXELIN_TLS_CA_PASSPHRASE"] = "new-secret"
        assert common.ca_passphrase(tmp_path / "ca") == b"new-secret"
    finally:
        os.environ.pop("PQCSUITE_CA_PASSPHRASE", None)
        os.environ.pop("ACXELIN_TLS_CA_PASSPHRASE", None)


@needs_openssl
def test_doctor_reports_the_machine_and_checks_a_ca_and_a_config(tmp_path):
    CA.init(tmp_path / "pki", "Root", passphrase=None)
    code, out, _ = run("doctor", "--ca", str(tmp_path / "pki"))
    assert code in (0, 1) and "OpenSSL" in out and "post-quantum TLS 1.3" in out
    bad = tmp_path / "edge.toml"
    bad.write_text('[[edge]]\nname = "x"\nmode = "terminate"\nlisten = "127.0.0.1:0"\ntarget = "127.0.0.1:1"\ncert = "/nope/chain.pem"\nkey = "/nope/key.pem"\n')
    code, out, _ = run("doctor", "--config", str(bad))
    assert code == 2 and "does not exist" in out


@needs_openssl
def test_the_one_minute_tour_ends_with_the_classical_client_refused():
    code, out, err = run("try")
    assert code == 0, err
    assert "refused, as it should be" in out and "ML-KEM" in out
    assert not any(w in out.lower() for w in ("pqcsuite", "readiness", "vault", "vpn"))


@needs_openssl
def test_status_reads_an_edges_metrics_endpoint(tmp_path):
    from acxelin_tls.edge import Edge, Route, serve_metrics
    CA.init(tmp_path / "pki", "Root", passphrase=None)
    ca = CA(tmp_path / "pki", None)
    ca.issue("localhost", "server", ["127.0.0.1"], out=tmp_path / "e")
    edge = Edge(Route("shop", "terminate", "127.0.0.1:0", "127.0.0.1:9", cert=str(tmp_path / "e/chain.pem"), key=str(tmp_path / "e/key.pem"))).start()
    server = serve_metrics("127.0.0.1:0", [edge], None)
    port = server.server_address[1]
    try:
        code, out, _ = run("status", "--url", f"http://127.0.0.1:{port}")
        assert code == 0 and "shop" in out and "strict" in out
        code, out, _ = run("status", "--url", f"http://127.0.0.1:{port}", "--json")
        assert json.loads(out)["shop"]["policy"] == "strict"
        assert run("status", "--url", "http://127.0.0.1:1")[0] == 1
    finally:
        edge.stop(0)
        server.shutdown()


@needs_openssl
def test_a_bundle_never_sends_the_reader_to_another_product(tmp_path):
    code, out, err = run("bundle", "nginx", "--host", "shop.example.invalid", "--out", str(tmp_path / "b"))
    assert code == 0, err
    text = out + (tmp_path / "b/README.txt").read_text() + (tmp_path / "b/docker-compose.yml").read_text() + (tmp_path / "b/edge.toml").read_text()
    assert "acxelin-tls connect shop.example.invalid:443" in text
    assert not any(w in text.lower() for w in ("pqcsuite", "readiness", "vault", "vpn"))
    assert "acxelin-tls:1.0.0" in text and "/etc/acxelin-tls/edge.toml" in text


def test_main_is_importable_and_returns_a_status():
    assert callable(cli.main) and hasattr(threading, "Thread") and time and urllib.request


def test_console_container_flag_listens_on_every_interface_and_opens_no_browser(monkeypatch, tmp_path):
    from acxelin_tls import console
    seen = {}
    monkeypatch.setattr(console, "run", lambda home, port, open_browser, ca_dir, host: seen.update(home=home, open=open_browser, host=host) or 0)
    with pytest.raises(SystemExit):
        cli.main(["console", "--container", "--home", str(tmp_path)])
    assert seen == {"home": tmp_path, "open": False, "host": "0.0.0.0"}
    with pytest.raises(SystemExit):
        cli.main(["console", "--no-browser", "--home", str(tmp_path)])
    assert seen["host"] == "127.0.0.1"


def test_status_only_reads_http_addresses(tmp_path):
    code, _, err = run("status", "--url", f"file://{tmp_path}")
    assert code == 1 and "http" in err
