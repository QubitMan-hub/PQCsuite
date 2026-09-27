"""Demo Bank VPN: a branch office and a staff laptop joined to headquarters over post-quantum VPNs, on one Linux machine.

Headquarters, a branch and a laptop each get a network namespace (a small private network stack), joined by virtual
cables. The branch reaches headquarters over IPsec with a hybrid ML-KEM key exchange and a post-quantum PPK; the laptop
reaches it over WireGuard with a pre-shared key agreed over ML-DSA mutual TLS. Revoking a certificate cuts each off.

    sudo python examples/vpn_demo.py            # pauses before each step; press Enter to go on
    sudo python examples/vpn_demo.py --auto     # runs straight through and checks every result

Needs Linux, root, iproute2 and pqcsuite with OpenSSL 3.5+. The branch part needs strongSwan 6.0.2+ (set PQCSUITE_STRONGSWAN to
its install prefix if charon is not in /usr/lib/ipsec); the laptop part needs wireguard-tools and WireGuard (the kernel
module, or wireguard-go). A part whose software is missing is skipped with a message.
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from clinic_demo import Demo  # noqa: E402

HQ, BRANCH, LAPTOP = "dbk-hq", "dbk-branch", "dbk-laptop"
PLACES = {HQ: "headquarters", BRANCH: "branch 0417", LAPTOP: "laptop", None: "CA"}


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def charon_path():
    prefix = os.environ.get("PQCSUITE_STRONGSWAN")
    places = [Path(prefix) / "libexec/ipsec/charon"] if prefix else [Path("/usr/lib/ipsec/charon"), Path("/usr/libexec/ipsec/charon"),
                                                                     Path("/usr/libexec/strongswan/charon")]
    return next((p for p in places if p.exists()), None)


def wireguard_ready():
    kernel = Path("/sys/module/wireguard").exists() or shutil.which("modprobe") and sh("modprobe", "wireguard", check=False).returncode == 0
    return shutil.which("wg") and (kernel or shutil.which("wireguard-go") or os.environ.get("PQCSUITE_WIREGUARD_GO"))


class VPNDemo(Demo):
    def at(self, ns, *args, expect=0, contains=(), tool="pqcsuite"):
        """Run a command at one place, printed as the person there would type it."""
        cmd = [sys.executable, "-m", "pqcsuite", *map(str, args)] if tool == "pqcsuite" else [tool, *map(str, args)]
        shown = " ".join(f'"{a}"' if " " in str(a) else str(a) for a in args)
        print(f"\n[{PLACES[ns]}] $ {tool} {shown}")
        r = subprocess.run(["ip", "netns", "exec", ns, *cmd] if ns else cmd, cwd=self.work, capture_output=True, text=True,
                           encoding="utf-8", errors="replace")
        out = (r.stdout + r.stderr).rstrip()
        print(textwrap.indent(out, "  ") if out else "  (no output)")
        if (expect is not None and r.returncode != expect) or any(c not in out for c in contains):
            raise SystemExit(f"\ndemo: step {self.n} did not go as planned (exit {r.returncode}, expected {expect}; wanted {list(contains)})")
        return out

    def spawn(self, ns, name, *cmd):
        log = open(self.work / f"{name}.log", "w", encoding="utf-8")
        self.procs.append(subprocess.Popen(["ip", "netns", "exec", ns, *cmd], cwd=self.work, stdout=log, stderr=subprocess.STDOUT))

    def wait(self, cond, what, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if cond():
                    return
            except Exception:
                pass
            time.sleep(0.5)
        logs = "\n".join(f"--- {f.name}\n{f.read_text(errors='replace')[-1500:]}" for f in sorted(self.work.glob("*.log")))
        raise SystemExit(f"\ndemo: {what} (step {self.n})\n{logs}")

    def pings(self, ns, target, source=None):
        return sh("ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "1", *(["-I", source] if source else []), target, check=False).returncode == 0

    def pings_within(self, ns, target, source=None, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if self.pings(ns, target, source):
                return True
            time.sleep(0.5)
        return False


def network():
    """HQ (LAN 192.168.10.1) with a cable to the branch (LAN 192.168.20.1) and one to the laptop."""
    for ns in (HQ, BRANCH, LAPTOP):
        sh("ip", "netns", "del", ns, check=False)
        sh("ip", "netns", "add", ns)
        sh("ip", "-n", ns, "link", "set", "lo", "up")
    for a, b, a_ip, b_ip, peer_ns in (("dbk-hq-br", "dbk-br-hq", "10.30.0.1", "10.30.0.2", BRANCH),
                                      ("dbk-hq-lap", "dbk-lap-hq", "10.40.0.1", "10.40.0.2", LAPTOP)):
        sh("ip", "link", "add", a, "type", "veth", "peer", "name", b)
        for dev, ns, ip in ((a, HQ, a_ip), (b, peer_ns, b_ip)):
            sh("ip", "link", "set", dev, "netns", ns)
            sh("ip", "-n", ns, "addr", "add", f"{ip}/24", "dev", dev)
            sh("ip", "-n", ns, "link", "set", dev, "up")
    sh("ip", "-n", HQ, "addr", "add", "192.168.10.1/32", "dev", "lo")
    sh("ip", "-n", BRANCH, "addr", "add", "192.168.20.1/32", "dev", "lo")
    sh("ip", "-n", HQ, "route", "add", "192.168.20.0/24", "via", "10.30.0.2")
    sh("ip", "-n", BRANCH, "route", "add", "192.168.10.0/24", "via", "10.30.0.1")


def site_config(work, name, address, peer, peer_address, local, remote, initiate):
    """The headquarters side listens for key agreement; the branch side dials it and starts the tunnel."""
    listen = [] if initiate else [f'keyring_listen = "{address}:7443"']
    dial = ["initiate = true", f'keyring = "{peer_address}:7443"'] if initiate else []
    return "\n".join(["[site]", f'name = "{name}"', f'address = "{address}"', f'cert = "{work}/certs/{name}/chain.pem"',
                      f'key = "{work}/certs/{name}/key.pem"', f'ca = "{work}/pki/ca.crt"', f'crl = "{work}/pki/crl.pem"',
                      f'vici = "unix://{work}/{name}.vici"', *listen, "", "[[peer]]", f'name = "{peer}"', f'address = "{peer_address}"',
                      f'local_subnets = ["{local}"]', f'remote_subnets = ["{remote}"]', "rotate_minutes = 1", *dial, ""])


def branch_part(d, charon):
    work = d.work
    d.step("Branch 0417 joins headquarters over a post-quantum IPsec VPN",
           "Each gateway gets a site certificate from the bank's CA. strongSwan does the IPsec, with a hybrid key exchange: "
           "X25519 and ML-KEM-768 together. On top, the two gateways agree a post-quantum pre-shared key (a PPK) over ML-DSA "
           "mutual TLS and give it to strongSwan, so the tunnel stays safe even if one of the two algorithms falls.")
    for name, addr in (("hq.demobank.example", "10.30.0.1"), ("branch-0417.demobank.example", "10.30.0.2")):
        d.at(None, "ca", "issue", "site", name, "--san", addr, "--out", f"certs/{name}", contains=["issued site certificate"])
    (work / "hq.toml").write_text(site_config(work, "hq.demobank.example", "10.30.0.1", "branch-0417.demobank.example", "10.30.0.2",
                                              "192.168.10.0/24", "192.168.20.0/24", False), encoding="utf-8")
    (work / "branch.toml").write_text(site_config(work, "branch-0417.demobank.example", "10.30.0.2", "hq.demobank.example", "10.30.0.1",
                                                  "192.168.20.0/24", "192.168.10.0/24", True), encoding="utf-8")
    for ns, name in ((HQ, "hq.demobank.example"), (BRANCH, "branch-0417.demobank.example")):
        conf = work / f"{name}.conf"
        conf.write_text(f"charon {{\n plugins {{ vici {{ socket = unix://{work}/{name}.vici }} }}\n"
                        f" filelog {{ log {{ path = {work}/charon-{name}.log\n flush_line = yes\n default = 1\n }} }}\n}}\n", encoding="utf-8")
        d.spawn(ns, f"strongswan-{name}", "unshare", "-m", "sh", "-c", f"mount -t tmpfs tmpfs /run && STRONGSWAN_CONF={conf} exec {charon}")
    d.wait(lambda: (work / "hq.demobank.example.vici").exists() and (work / "branch-0417.demobank.example.vici").exists(), "strongSwan did not start")
    kems = d.at(HQ, "vpn", "check", "--config", "hq.toml", expect=None)
    if "ML_KEM_768" not in kems:
        print("\n  This strongSwan has no ML-KEM (it needs 6.0.2+ with OpenSSL 3.5+ or the ml plugin), so the branch part stops here.")
        return
    print("\n  Start the controller at each site; the branch dials headquarters.")
    d.spawn(HQ, "vpn-hq", sys.executable, "-m", "pqcsuite", "vpn", "up", "--config", "hq.toml")
    d.spawn(BRANCH, "vpn-branch", sys.executable, "-m", "pqcsuite", "vpn", "up", "--config", "branch.toml")
    print(f"\n[headquarters] $ pqcsuite vpn up --config hq.toml\n[branch 0417] $ pqcsuite vpn up --config branch.toml")
    status = lambda: sh("ip", "netns", "exec", HQ, sys.executable, "-m", "pqcsuite", "vpn", "status", "--config", str(work / "hq.toml")).stdout
    d.wait(lambda: "ESTABLISHED" in status() and "PPK yes" in status(), "the tunnel did not come up with a PPK")

    d.step("Is it really post-quantum?", "strongSwan itself reports the key exchange of the live tunnel, and that the PPK is in use.")
    d.at(HQ, "vpn", "status", "--config", "hq.toml", contains=["ML_KEM_768", "PPK yes"])
    print("\n  Say: CURVE_25519 and ML_KEM_768 together, and PPK yes. Both halves would have to be broken to read this link.")
    d.pings_within(BRANCH, "192.168.10.1", "192.168.20.1")
    if "INSTALLED" in status():
        d.at(BRANCH, "-c", "3", "-I", "192.168.20.1", "192.168.10.1", tool="ping", contains=["3 received"])
        d.at(HQ, "vpn", "status", "--config", "hq.toml", contains=["INSTALLED"])
        print("\n  Say: the branch's network reaches headquarters' network, and the byte counters show it went through the tunnel.")
    else:
        print("\n  This machine's kernel could not install the encrypted path (no AES-GCM for IPsec; see "
              "charon-hq.demobank.example.log), so the traffic part is left out. The key exchange above is the real one; on a "
              "standard Linux kernel the tunnel line is followed by an INSTALLED line with byte counters.")

    d.step("Branch 0417 is compromised: cut it off",
           "One command at the CA. The headquarters gateway reads the new revocation list and drops the tunnel within 15 seconds; "
           "the branch cannot agree new keys either.")
    d.at(None, "ca", "revoke", d.serial("branch-0417.demobank.example"), "--reason", "keyCompromise", contains=["revoked"])
    d.wait(lambda: "branch-0417" not in status(), "headquarters kept the revoked branch's tunnel", 45)
    d.at(HQ, "vpn", "status", "--config", "hq.toml", contains=["no tunnels"])
    print("\n  Say: no tunnel. Nobody touched the gateways.")


def laptop_part(d):
    work = d.work
    d.step("A staff laptop connects to headquarters over WireGuard",
           "The laptop has a client certificate. It agrees a fresh pre-shared key with the headquarters gateway over ML-DSA "
           "mutual TLS; WireGuard mixes that key into its own X25519 handshake. The key is replaced every few minutes.")
    d.at(None, "ca", "issue", "server", "vpn.demobank.example", "--san", "10.40.0.1", "--out", "certs/vpn-gateway", contains=["issued"])
    d.at(None, "ca", "issue", "client", "priya.laptop", "--out", "certs/priya", contains=["issued"])
    shutil.copy(work / "pki" / "ca.crt", work / "certs" / "priya" / "ca.crt")
    (work / "gateway.toml").write_text(textwrap.dedent(f"""\
        [wireguard]
        name = "vpn.demobank.example"
        endpoint = "10.40.0.1:51820"
        keyring_listen = "10.40.0.1:7443"
        pool = "10.99.0.0/24"
        routes = ["192.168.10.0/24"]
        interface = "dbk-wg0"
        rotate_minutes = 0.5
        cert = "{work}/certs/vpn-gateway/chain.pem"
        key = "{work}/certs/vpn-gateway/key.pem"
        ca = "{work}/pki/ca.crt"
        crl = "{work}/pki/crl.pem"
        private_key = "{work}/gateway-wireguard.key"
        state = "{work}/gateway-state.json"
        """), encoding="utf-8")
    d.spawn(HQ, "wireguard-gateway", sys.executable, "-m", "pqcsuite", "vpn", "gateway", "--config", "gateway.toml")
    print("\n[headquarters] $ pqcsuite vpn gateway --config gateway.toml")
    d.wait(lambda: sh("ip", "netns", "exec", HQ, "wg", "show", "dbk-wg0", check=False).returncode == 0, "the WireGuard gateway did not start")
    time.sleep(0.5)
    d.spawn(LAPTOP, "wireguard-laptop", sys.executable, "-m", "pqcsuite", "vpn", "connect", "10.40.0.1:7443", "--cert-dir", "certs/priya",
            "--server-name", "vpn.demobank.example", "--interface", "dbk-wg1")
    print("[laptop] $ pqcsuite vpn connect 10.40.0.1:7443 --cert-dir certs/priya --server-name vpn.demobank.example")
    d.wait(lambda: d.pings(LAPTOP, "192.168.10.1"), "no traffic through the WireGuard tunnel")
    d.at(LAPTOP, "-c", "3", "192.168.10.1", tool="ping", contains=["3 received"])
    d.at(HQ, "show", "dbk-wg0", tool="wg", contains=["preshared key"])
    print("\n  Say: 'preshared key: (hidden)' is the post-quantum key, agreed over ML-DSA mutual TLS. Without it the handshake fails.")

    d.step("The laptop is stolen: revoke it", "Same as the branch: one command at the CA, and the gateway removes the laptop.")
    d.at(None, "ca", "revoke", d.serial("priya.laptop"), "--reason", "keyCompromise", contains=["revoked"])
    d.wait(lambda: not sh("ip", "netns", "exec", HQ, "wg", "show", "dbk-wg0", "peers").stdout.strip(), "the gateway kept the revoked laptop", 45)
    d.at(LAPTOP, "-c", "2", "-W", "1", "192.168.10.1", tool="ping", expect=1, contains=["0 received"])
    print("\n  Say: the laptop is out. Its certificate is revoked, so it cannot agree a new key either.")


def main():
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--auto", action="store_true", help="run without pauses and check every result")
    ap.add_argument("--dir", help="work folder (default: a new temporary folder)")
    a = ap.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0 or not shutil.which("ip"):
        raise SystemExit("the VPN demo needs Linux, root (sudo) and iproute2: it builds three small networks on this machine")
    charon, wireguard = charon_path(), wireguard_ready()
    if not charon and not wireguard:
        raise SystemExit("install strongSwan 6.0.2+ (or set PQCSUITE_STRONGSWAN) or wireguard-tools, so there is a VPN to show")
    work = Path(a.dir or tempfile.mkdtemp(prefix="demobank-vpn-")).resolve()
    work.mkdir(parents=True, exist_ok=True)
    d = VPNDemo(work, a.auto)
    print(f"Demo Bank VPN, working in {work}\n  branch over IPsec: {charon or 'skipped (no strongSwan)'}\n"
          f"  laptop over WireGuard: {'yes' if wireguard else 'skipped (no WireGuard)'}")
    try:
        network()
        d.at(None, "ca", "init", "--name", "Demo Bank Root", contains=["created"])
        if charon:
            branch_part(d, charon)
        if wireguard:
            laptop_part(d)
        print(f"\n{'=' * 78}\nDone. Logs and certificates are in {work}")
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        d.stop()
        for ns in (HQ, BRANCH, LAPTOP):
            sh("ip", "netns", "del", ns, check=False)


if __name__ == "__main__":
    main()
