"""Can this strongSwan authenticate IKEv2 with ML-DSA certificates? Two charons in two network namespaces, auth = pubkey,
certificates from acxelin-core's CA; prints what loaded, the IKE SA and charon's authentication lines. Linux, as root:
ACXELIN_STRONGSWAN=/opt/strongswan python mldsa_ike_check.py WORK-DIR [ML-DSA-65]

strongSwan 6.1.0 has no ML-DSA key type, so it refuses the certificates and keys before any IKE message is sent. Until a
release passes this check, IKE in Acxelin VPN authenticates with the PSK, and mixes in the PPK, both from ML-DSA mutual TLS."""
import os
import subprocess
import sys
import time
from pathlib import Path

from acxelin_core.pki import CA

SS = Path(os.environ.get("ACXELIN_STRONGSWAN", "/opt/strongswan"))
D = Path(sys.argv[1])
ALG = sys.argv[2] if len(sys.argv) > 2 else "ML-DSA-65"
D.mkdir(parents=True, exist_ok=True)
sh = lambda *a, check=True: subprocess.run(a, check=check, capture_output=True, text=True)

ca = CA.init(D / "ca", "IKE Root", algorithm=ALG)
for n in ("hq.acme", "branch.acme"):
    ca.issue(n, "site", [n], algorithm=ALG, out=D / n)

for ns in ("ike-hq", "ike-br"):
    sh("ip", "netns", "del", ns, check=False)
    sh("ip", "netns", "add", ns)
sh("ip", "link", "add", "ike-vh", "type", "veth", "peer", "name", "ike-vb")
for ns, dev, addr in (("ike-hq", "ike-vh", "10.40.0.1"), ("ike-br", "ike-vb", "10.40.0.2")):
    sh("ip", "link", "set", dev, "netns", ns)
    sh("ip", "-n", ns, "addr", "add", f"{addr}/24", "dev", dev)
    sh("ip", "-n", ns, "link", "set", dev, "up")
    sh("ip", "-n", ns, "link", "set", "lo", "up")

procs = []
try:
    for tag, ns, me, other, name, peer in (("hq", "ike-hq", "10.40.0.1", "10.40.0.2", "hq.acme", "branch.acme"),
                                           ("br", "ike-br", "10.40.0.2", "10.40.0.1", "branch.acme", "hq.acme")):
        s = D / f"sw-{tag}"
        for sub in ("x509", "x509ca", "private"):
            (s / sub).mkdir(parents=True, exist_ok=True)
        (s / "x509ca/ca.pem").write_bytes((D / "ca/ca.crt").read_bytes())
        (s / "x509/me.pem").write_bytes((D / name / "cert.pem").read_bytes())
        (s / "private/me.pem").write_bytes((D / name / "key.pem").read_bytes())
        (s / "swanctl.conf").write_text(f"""connections {{
  t {{
    version = 2
    local_addrs = {me}
    remote_addrs = {other}
    proposals = aes256gcm16-prfsha384-x25519-ke1_mlkem768
    local {{ auth = pubkey
      certs = me.pem
      id = {name} }}
    remote {{ auth = pubkey
      id = {peer} }}
    children {{ c {{ local_ts = {me}/32
      remote_ts = {other}/32
      esp_proposals = aes256gcm16-x25519-ke1_mlkem768 }} }}
  }}
}}
""")
        conf = D / f"{tag}.conf"
        conf.write_text(f"charon {{\n plugins {{ vici {{ socket = unix://{D}/{tag}.vici }} }}\n"
                        f" filelog {{ log {{ path = {D}/{tag}.log\n flush_line = yes\n default = 1\n ike = 2\n cfg = 2\n }} }}\n}}\n")
        procs.append(subprocess.Popen(["ip", "netns", "exec", ns, "unshare", "-m", "sh", "-c",
                                       f"mount -t tmpfs tmpfs /run && STRONGSWAN_CONF={conf} exec {SS}/libexec/ipsec/charon"],
                                      stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT))
    for _ in range(40):
        if (D / "hq.vici").exists() and (D / "br.vici").exists():
            break
        time.sleep(0.5)
    for tag in ("hq", "br"):
        r = sh(f"{SS}/sbin/swanctl", "--load-all", "--noprompt", "--uri", f"unix://{D}/{tag}.vici", "--file", str(D / f"sw-{tag}/swanctl.conf"), check=False)
        print(f"--- load {tag}:", r.returncode, (r.stdout + r.stderr).strip()[-800:])
    r = sh(f"{SS}/sbin/swanctl", "--initiate", "--child", "c", "--timeout", "20", "--uri", f"unix://{D}/br.vici", check=False)
    print("--- initiate:", r.returncode, (r.stdout + r.stderr).strip()[-1500:])
    r = sh(f"{SS}/sbin/swanctl", "--list-sas", "--uri", f"unix://{D}/hq.vici", check=False)
    print("--- hq SAs:", r.stdout.strip())
    for tag in ("hq", "br"):
        lines = [x for x in (D / f"{tag}.log").read_text().splitlines()
                 if any(k in x for k in ("authentication", "signature", "ML_DSA", "ML-DSA", "IKE_SA t", "no trusted", "unsupported", "failed"))]
        print(f"--- {tag} log:\n" + "\n".join(lines[-15:]))
finally:
    for p in procs:
        p.terminate()
    for ns in ("ike-hq", "ike-br"):
        sh("ip", "netns", "del", ns, check=False)
