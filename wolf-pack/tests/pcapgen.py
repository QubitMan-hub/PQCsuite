"""Builds small synthetic packet captures for the capture scout's tests."""
import struct

from wolfpack.scouts.probe import client_hello


def _eth_ip_tcp(src, dst, sport, dport, seq, payload):
    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 5 << 4, 0x18, 65535, 0, 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, bytes(src), bytes(dst)) + tcp
    return b"\x00" * 12 + b"\x08\x00" + ip


def pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for f in frames:
        out += struct.pack("<IIII", 0, 0, len(f), len(f)) + f
    return out


def _record(hs_type, body):
    hs = bytes([hs_type]) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(hs)) + hs


def server_hello(suite, version=0x0304, group=None):
    ext = b""
    if version == 0x0304:
        ext += struct.pack(">HHH", 0x002B, 2, 0x0304)
    if group is not None:
        ext += struct.pack(">HHHH", 0x0033, 4 + 32, group, 32) + b"\x00" * 32
    body = struct.pack(">H", 0x0303) + b"\x01" * 32 + b"\x00" + struct.pack(">H", suite) + b"\x00" + struct.pack(">H", len(ext)) + ext
    return _record(2, body)


def server_key_exchange(curve):
    return _record(12, b"\x03" + struct.pack(">H", curve) + b"\x20" + b"\x00" * 32)


def kexinit(kex, hostkey, cipher, mac):
    lists = [kex, hostkey, cipher, cipher, mac, mac, "none", "none", "", ""]
    payload = b"\x14" + b"\x00" * 16 + b"".join(struct.pack(">I", len(x)) + x.encode() for x in lists) + b"\x00" + b"\x00" * 4
    pad = 8 - (len(payload) + 5) % 8 or 8
    return struct.pack(">IB", len(payload) + pad + 1, pad) + payload + b"\x00" * pad


def tls_capture(groups, sh, extra=b""):
    c, s = [10, 0, 0, 5], [10, 0, 0, 9]
    return [_eth_ip_tcp(c, s, 50000, 443, 1, client_hello("bank.example", groups)), _eth_ip_tcp(s, c, 443, 50000, 1, sh + extra)]


def ssh_capture(client_kex, server_kex):
    c, s = [10, 0, 0, 5], [10, 0, 0, 22]
    return [_eth_ip_tcp(c, s, 50001, 22, 1, b"SSH-2.0-OpenSSH_9.9\r\n" + kexinit(client_kex, "ssh-ed25519,rsa-sha2-512", "aes256-gcm@openssh.com", "hmac-sha2-256")),
            _eth_ip_tcp(s, c, 22, 50001, 1, b"SSH-2.0-OpenSSH_8.4\r\n" + kexinit(server_kex, "rsa-sha2-512", "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com", "hmac-sha2-256"))]
