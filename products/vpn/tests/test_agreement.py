"""IPsec and WireGuard agree keys through one module: the same mutual TLS session, message framing and exporter, with only
the label, context and length differing. The labels and contexts are pinned to what deployed gateways use."""
import inspect

import pytest
from acxelin_core import tls
from acxelin_core.pki import CA

from acxelin_vpn import agreement, controller, wireguard


def test_labels_and_contexts_are_pinned():
    assert (agreement.IPSEC, agreement.WIREGUARD) == ("EXPORTER-pqcsuite-ipsec-v1", "EXPORTER-pqcsuite-wireguard-v1")
    assert agreement.ipsec_context("hq.acme", "branch.acme", "0123456789ab") == b"branch.acme|hq.acme|0123456789ab"
    assert agreement.wireguard_context("gw", "alice", "t", "C=", "G=") == b"gw|alice|t|C=|G="
    assert (controller.LABEL, controller.context, wireguard.LABEL, wireguard.context) == (
        agreement.IPSEC, agreement.ipsec_context, agreement.WIREGUARD, agreement.wireguard_context)
    assert agreement.TAG.match(agreement.new_tag()) and not agreement.TAG.match("../x")


def test_neither_data_plane_has_its_own_copy_of_the_agreement():
    for mod in (controller, wireguard):
        src = inspect.getsource(mod)
        for own in (".export(", "client_context(", "server_context(", "tls.connect(", "Server("):
            assert own not in src, f"{mod.__name__} does {own} itself"


def test_one_session_gives_both_sides_the_same_keys(tmp_path):
    try:
        tls.lib()
    except tls.OpenSSLUnavailable as e:
        pytest.skip(str(e))
    ca = CA.init(tmp_path / "ca", "VPN Root")
    for name in ("hq.acme", "branch.acme"):
        ca.issue(name, "site", ["127.0.0.1"], out=tmp_path / name)
    got = {}

    def respond(conn, addr):
        msg = agreement.read_line(conn)
        got["responder"] = agreement.ipsec_keys(conn, "hq.acme", agreement.common_name(conn.peer_certificate()), msg["tag"])
        agreement.send(conn, {"ok": True})
    d = lambda n: (tmp_path / n / "chain.pem", tmp_path / n / "key.pem")
    server = agreement.keyring("127.0.0.1:0", *d("hq.acme"), tmp_path / "ca/ca.crt", respond)
    try:
        with agreement.dial(("127.0.0.1", server.port), tmp_path / "ca/ca.crt", *d("branch.acme"), server_name="hq.acme") as conn:
            tag = agreement.new_tag()
            agreement.send(conn, {"v": 1, "site": "branch.acme", "tag": tag})
            mine = agreement.ipsec_keys(conn, "branch.acme", agreement.common_name(conn.peer_certificate()), tag)
            assert agreement.read_line(conn) == {"ok": True}
            assert "MLKEM" in conn.group.upper()
    finally:
        server.stop(1)
    assert len(mine) == 64 and mine == got["responder"]
