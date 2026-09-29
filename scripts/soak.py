"""Soak: run the edge for a long time under steady change and fail if it degrades. Linux (reads /proc).

    python scripts/soak.py --minutes 120 [--out soak.json]

A mutual-TLS edge follows the CA's published CRL (crl_url) in front of a plain service while clients connect without a
pause. Every 20 s a client certificate is issued and revoked (the revoked one must be refused once the CRL arrives, a valid
one must still get in); every few minutes the edge's own certificate is renewed (hot reload). Memory, open files and threads
are sampled; after a warm-up they must stay flat. Needs OpenSSL 3.5+.
"""
import argparse
import json
import logging
import os
import socket
import tempfile
import threading
import time
from pathlib import Path

from pqcsuite import PEM, serve_http, tls
from pqcsuite.pki import CA
from pqcsuite.tls.edge import Edge, Route


def usage():
    rss = next(int(line.split()[1]) for line in open("/proc/self/status") if line.startswith("VmRSS:"))
    return {"rss_mb": round(rss / 1024, 1), "fds": len(os.listdir("/proc/self/fd")), "threads": threading.active_count()}


def echo_server():
    s = socket.create_server(("127.0.0.1", 0))

    def serve():
        while True:
            conn, _ = s.accept()
            threading.Thread(target=lambda c=conn: (c.sendall(c.recv(64)), c.close()), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return s.getsockname()[1]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--minutes", type=float, default=120)
    ap.add_argument("--clients", type=int, default=4)
    ap.add_argument("--out")
    a = ap.parse_args()
    logging.basicConfig(level=logging.ERROR)  # a refused revoked client is the expected case, not news
    d = Path(tempfile.mkdtemp())
    ca = CA.init(d / "pki", "Soak Root")
    ca.crl()
    cafile = str(d / "pki" / "ca.crt")
    srv, srv_rec = ca.issue("localhost", "server", ["127.0.0.1"], out=d / "edge")
    who, _ = ca.issue("steady", "client", out=d / "steady")
    publish = serve_http("127.0.0.1:0", {"/crl.pem": (PEM, lambda: (d / "pki" / "crl.pem").read_text())})
    edge = Edge(Route("soak", "terminate", "127.0.0.1:0", f"127.0.0.1:{echo_server()}", cert=str(srv / "chain.pem"), key=str(srv / "key.pem"),
                      ca=cafile, require_client_cert=True, crl=str(d / "edge-crl.pem"),
                      crl_url=f"http://127.0.0.1:{publish.server_address[1]}/crl.pem", crl_every=5)).start()
    steady = tls.client_context(cafile, who / "chain.pem", who / "key.pem")
    counts = {"ok": 0, "failed": 0, "revocations": 0, "revocations_enforced": 0, "renewals": 0}
    lock, stop, deadline = threading.Lock(), threading.Event(), time.monotonic() + a.minutes * 60

    def ask(ctx):
        try:
            with tls.connect("127.0.0.1", edge.port, ctx, "localhost", 10) as c:
                c.sendall(b"ping")
                return c.recv(timeout=10) == b"ping"
        except (tls.TLSError, OSError):
            return False

    def client():
        while not stop.is_set():
            ok = ask(steady)
            with lock:
                counts["ok" if ok else "failed"] += 1
    threads = [threading.Thread(target=client, daemon=True) for _ in range(a.clients)]
    for t in threads:
        t.start()
    samples, n = [], 0
    while time.monotonic() < deadline:
        time.sleep(20)
        n += 1
        out, rec = ca.issue(f"leaver-{n}", "client", out=d / f"leaver-{n}")
        ctx = tls.client_context(cafile, out / "chain.pem", out / "key.pem")
        ca.revoke(rec.serial)
        counts["revocations"] += 1
        for _ in range(30):  # the edge fetches the CRL every 5 s
            if not ask(ctx):
                counts["revocations_enforced"] += 1
                break
            time.sleep(0.5)
        ctx.close()
        if n % 6 == 0:
            srv_rec = ca.renew(srv_rec.serial, out=srv)[1]
            counts["renewals"] += 1
        samples.append({"minute": round((a.minutes * 60 - (deadline - time.monotonic())) / 60, 1), **usage()})
        print(json.dumps({**samples[-1], **counts}), flush=True)
    stop.set()
    for t in threads:
        t.join()
    edge.stop(0)
    publish.shutdown()
    settled = samples[len(samples) // 5:] or samples
    first, last = settled[0], settled[-1]
    problems = []
    if last["rss_mb"] > first["rss_mb"] * 1.3 + 20:
        problems.append(f"memory grew from {first['rss_mb']} to {last['rss_mb']} MB")
    if last["fds"] > first["fds"] + 20:
        problems.append(f"open files grew from {first['fds']} to {last['fds']}")
    if last["threads"] > first["threads"] + 10:
        problems.append(f"threads grew from {first['threads']} to {last['threads']}")
    if counts["failed"] > counts["ok"] / 1000:
        problems.append(f"{counts['failed']} of {counts['ok'] + counts['failed']} valid connections failed")
    if counts["revocations_enforced"] != counts["revocations"]:
        problems.append(f"{counts['revocations'] - counts['revocations_enforced']} revoked certificates were still let in")
    result = {"minutes": a.minutes, **counts, "start": first, "end": last, "problems": problems}
    if a.out:
        Path(a.out).write_text(json.dumps({**result, "samples": samples}, indent=1))
    print(json.dumps(result, indent=1))
    raise SystemExit(1 if problems else 0)


if __name__ == "__main__":
    main()
