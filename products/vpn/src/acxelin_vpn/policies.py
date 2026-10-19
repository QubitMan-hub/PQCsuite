"""What the VPN's own key agreement may negotiate: post-quantum hybrid key exchange, ML-DSA certificates and TLS 1.3 only.
It equals the suite's `strict`, so a gateway on Acxelin VPN agrees keys with one still on PQC Suite 0.4.3 during an upgrade."""
from acxelin_core.tls import Policy

POLICY = Policy("acxelin-vpn", "X25519MLKEM768:SecP384r1MLKEM1024:SecP256r1MLKEM768", "mldsa87:mldsa65:mldsa44",
                "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256")
