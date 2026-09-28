"""Post-quantum costs on this machine, as JSON: TLS handshakes over loopback (hybrid ML-KEM against classical X25519, both
with an ML-DSA-65 server certificate), certificate issuance, and Vault throughput. Needs OpenSSL 3.5+.

    python scripts/benchmark.py [--rounds 200]
"""
import argparse
import json
import os
import statistics
import tempfile
import time
from pathlib import Path

from pqcsuite import tls, vault
from pqcsuite.pki import CA
from pqcsuite.tls.openssl import Context
from pqcsuite.tls.server import Server


def timed(fn, rounds):
    out = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn()
        out.append((time.perf_counter() - start) * 1000)
    return {"median_ms": round(statistics.median(out), 3), "p95_ms": round(sorted(out)[int(len(out) * .95) - 1], 3), "rounds": rounds}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rounds", type=int, default=200)
    rounds = ap.parse_args().rounds
    d = Path(tempfile.mkdtemp())
    ca = CA.init(d / "pki", "Bench Root")
    srv, _ = ca.issue("localhost", "server", ["127.0.0.1"], out=d / "srv")
    cafile = str(d / "pki" / "ca.crt")
    s = Server(("127.0.0.1", 0), lambda: tls.server_context(srv / "chain.pem", srv / "key.pem", policy_name="transition"),
               lambda conn, addr: None, handshake_timeout=5)
    s.start()
    results = {"openssl": tls.lib().version}
    try:
        for name, groups in (("X25519MLKEM768", "X25519MLKEM768"), ("X25519", "X25519")):
            ctx = Context(False, groups, None, tls.CIPHERSUITES, None, None, None, cafile, True)

            def handshake():
                with tls.connect("127.0.0.1", s.port, ctx, "localhost", 5) as c:
                    assert c.info()["group"].lower() == name.lower()
            handshake()
            results[f"tls_handshake_{name}"] = timed(handshake, rounds)
    finally:
        s.stop(1)
    results["ca_issue_ML-DSA-65"] = timed(lambda: ca.issue("bench.test", "server"), max(10, rounds // 10))
    me, data = vault.Identity.generate(), d / "data"
    data.write_bytes(os.urandom(64 << 20))
    start = time.perf_counter()
    vault.encrypt(data, d / "data.pqv", [me.public])
    enc = time.perf_counter() - start
    start = time.perf_counter()
    vault.decrypt(d / "data.pqv", d / "out", me)
    dec = time.perf_counter() - start
    results["vault_64MiB"] = {"encrypt_MiB_s": round(64 / enc, 1), "decrypt_MiB_s": round(64 / dec, 1)}
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
