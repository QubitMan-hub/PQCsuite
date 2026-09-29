# Pilot: the checks that need your accounts or hardware

What CI cannot do, as a script to follow. Each part ends with what to record in the "Not yet validated" table of
[RELEASE-READINESS.md](RELEASE-READINESS.md); every release report copies that table.

## 1. A cloud image in a real account (about an hour per cloud)

With [Packer](https://developer.hashicorp.com/packer/install) and the cloud's CLI logged in:

```
packer init deploy/packer
packer build -only=amazon-ebs.pqcsuite -var aws_region=eu-west-1 deploy/packer          # AWS
packer build -only=azure-arm.pqcsuite -var azure_subscription_id=... deploy/packer       # Azure
packer build -only=googlecompute.pqcsuite -var gcp_project=... deploy/packer             # Google Cloud
```

Start a small VM from the image, then on it:

```
pqcsuite doctor                                  # "... ready (this machine's OpenSSL 3.5...)", exit 0
pqcsuite try                                     # post-quantum in, classical out
sudo systemctl status strongswan-pqc             # the VPN units are installed
```

Pass: all three succeed. Record the cloud, region, image ID and date.

## 2. Managed Kubernetes (EKS, AKS or GKE; about an hour)

On a small cluster, with `kubectl` pointed at it:

```
helm install pqc deploy/helm/pqcsuite --wait --timeout 5m
kubectl exec pqc-ca-0 -c maintain -- pqcsuite doctor --ca /data/pki      # no FAIL; the CA key is encrypted
kubectl exec pqc-ca-0 -c acme -- sh -c 'test ! -e /data/root && echo "no root in ACME"'
```

Then follow the "Issue an edge certificate" and "Post-quantum request through the edge" steps of the `kubernetes` job in
`.github/workflows/ci.yml`: they issue a certificate, put the edge in front of a web app and send a post-quantum request
through it (`deploy/k8s/smoke.py`). With a LoadBalancer in front of the edge (`--set edge.service.type=LoadBalancer`), also
run from a laptop: `docker run --rm ghcr.io/qubitman-hub/pqcsuite readiness scan <the load balancer's address>:8443`; it
should grade A.

Pass: the smoke request prints `X25519MLKEM768` and an ML-DSA peer key. Record the provider, Kubernetes version and date.

## 3. Production hardware

On the machine that will run the edge (Linux, OpenSSL 3.5+):

```
python scripts/benchmark.py --load-seconds 60 --clients 64      # handshakes, issuance, Vault, and load
python scripts/soak.py --minutes 1440 --out soak.json           # 24 hours: memory, files and threads must stay flat
```

For more connections a second, run the edge with `--workers N` (one per core) and point the load at it. Pass: the soak exits
0. Record the CPU, the connections per second and the soak length.

## 4. Independent security review

Give the reviewer [SECURITY-REVIEW.md](SECURITY-REVIEW.md) (assets, trust boundaries, what to test) and
[THREAT-MODEL.md](THREAT-MODEL.md). The parts no library covers are the VPN key agreement (`pqcsuite/vpn/controller.py`,
`wireguard.py`), Vault's file format (`pqcsuite/vault.py`) and the TLS bridge (`pqcsuite/tls/openssl.py`). Record who
reviewed, the date and where the report is; fix findings as ordinary changes, each with a test.
