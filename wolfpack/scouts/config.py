import re

from ..elders import lookup, pq_from_text, curve, CATALOG
from ..model import Sighting
from . import iter_files, rel, is_test, read, DENY
from .lexer import split_hash
from .suites import cipher_string, ssh_token, sig_scheme

EXT = {".conf", ".cnf", ".cfg", ".ini", ".yaml", ".yml", ".properties", ".toml", ".env", ".xml", ".json", ".tf", ".hcl"}
NAMES = {"sshd_config", "ssh_config", "openssl.cnf", "nginx.conf", "httpd.conf", "haproxy.cfg", "java.security", "dockerfile", ".env"}

TLSV = re.compile(r"\b(SSLv[23]|TLSv1(?:\.[0-3])?|TLS1_[0-3]_VERSION|TLS1_VERSION|TLSv1_[0-3])\b", re.I)
PAIRS = [
    (re.compile(r"^\s*(KexAlgorithms|HostKeyAlgorithms|PubkeyAcceptedAlgorithms|PubkeyAcceptedKeyTypes|HostbasedAcceptedAlgorithms|CASignatureAlgorithms|Ciphers|MACs)\s+(.+)"), "ssh"),
    (re.compile(r"^\s*ssl_protocols\s+([^;#]+)", re.I), "protocols"),
    (re.compile(r"^\s*SSLProtocol\s+(.+)", re.I), "apache_protocols"),
    (re.compile(r"^\s*(?:ssl_ciphers|SSLCipherSuite|ssl-default-bind-ciphers|ssl-default-server-ciphers|ssl-default-bind-ciphersuites|CipherString|Ciphersuites|ssl_cipher|cipher[_-]?suites?|ciphers)\s*[=:\s]\s*(.+)", re.I), "ciphers"),
    (re.compile(r"^\s*(?:ssl_ecdh_curve|Groups|Curves|ssl-default-bind-curves|ssl_ecdh_curves|curves|groups|named[_-]?groups)\s*[=:\s]\s*(.+)", re.I), "groups"),
    (re.compile(r"^\s*[\w.\-\"']*(?:min[_-]?(?:tls|ssl|proto(?:col)?)?[_-]?version|MinProtocol|MaxProtocol|ssl-min-ver|ssl-max-ver|enabled[_-]?protocols|sslEnabledProtocols|sslProtocol|tls[_-]?versions?|protocols?)[\w\"']*\s*[=:]\s*(.+)", re.I), "protocols"),
    (re.compile(r"^\s*[\w.\-\"']*(?:algorithm|alg|signing[_-]?alg\w*|key[_-]?algorithm|keyAlgorithm|hash[_-]?algorithm|digest[_-]?algorithm|kex)[\w\"']*\s*[=:]\s*[\"']?([\w\-/]+)", re.I), "algo"),
    (re.compile(r"^\s*[\w.\-\"']*(?:key[_-]?size|keysize|key[_-]?length|rsa[_-]?bits|modulus[_-]?length|size)[\w\"']*\s*[=:]\s*[\"']?(\d{3,5})\b", re.I), "size"),
]


def is_config(p):
    return p.suffix.lower() in EXT or p.name.lower() in NAMES or p.name.lower().endswith((".conf", "_config"))


def _vals(s):
    return [t for t in re.split(r"[\s,;\"'\[\]]+", s.split("#")[0]) if t]


def parse_line(kind, m):
    if kind == "protocols":
        return [(lookup(t), {}) for t in TLSV.findall(m.group(1))]
    if kind == "apache_protocols":
        return [(lookup(t.lstrip("+")), {}) for t in _vals(m.group(1)) if not t.startswith("-") and TLSV.match(t.lstrip("+"))]
    if kind == "ciphers":
        return cipher_string(m.group(1).split("#")[0].strip().rstrip(";"))
    if kind == "groups":
        out = []
        for g in re.split(r"[:,\s;\"']+", m.group(1).split("#")[0]):
            if not g or g.startswith(("!", "-")):
                continue
            cv = curve(g)
            a = "ECDH" if cv else lookup(g) or pq_from_text(g)
            if a:
                out.append((a, {"curve": cv} if cv else {}))
        return out
    if kind == "ssh":
        out = []
        for t in re.split(r",", m.group(2).split("#")[0].strip()):
            out += ssh_token(t)
        return out
    if kind == "algo":
        v = m.group(1)
        r = sig_scheme(v)
        return r if r else ([(lookup(v), {})] if lookup(v) else [])
    return []


SNIFF = re.compile(r"(?m)^[ \t]*(ssl_protocols|ssl_ciphers|ssl_ecdh_curve|SSLProtocol|SSLCipherSuite|KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|CipherString|MinProtocol)\b")


def sniffed(p, text):
    """A file with no extension, such as `conf`, counts as config when at least two different TLS/SSH directives start its lines."""
    return len({m.group(1) for m in SNIFF.finditer(text[:50000])}) >= 2


def scan(root, scope=False):
    sink, n = [], 0
    for p in iter_files(root, scope):
        if p.suffix and not is_config(p):
            continue
        text = read(p)
        if text is None or not is_config(p) and not sniffed(p, text):
            continue
        n += 1
        path = rel(root, p)
        base = {"test"} if is_test(path) else set()
        code, comments, _ = split_hash(text) if p.suffix.lower() not in (".json", ".xml") else (text, "", [])
        for stream, ctx in ((code, base), (comments, base | {"comment"})):
            for i, line in enumerate(stream.splitlines(), 1):
                if not line.strip():
                    continue
                probe = line.strip().lstrip("#; ").strip()
                if DENY.search(probe.split("=")[0].split(":")[0]):
                    continue
                for rx, kind in PAIRS:
                    m = rx.search(probe)
                    if not m:
                        continue
                    if kind == "size":
                        for s in reversed(sink):
                            if s.file == path and s.algo in ("RSA", "DSA", "DH", "ECDSA", "ECC") and 0 <= i - s.line <= 6 and not s.params.get("key_size"):
                                if s.algo in ("ECDSA", "ECC"):
                                    cv = {"256": "P-256", "384": "P-384", "521": "P-521"}.get(m.group(1))
                                    if cv:
                                        s.params.setdefault("curve", cv)
                                else:
                                    s.params["key_size"] = int(m.group(1))
                                break
                        break
                    for a, params in parse_line(kind, m):
                        if a and a in CATALOG:
                            sink.append(Sighting(algo=a, file=path, line=i, evidence="config", scout="config", snippet=probe[:160], lang="config",
                                                 params={k: v for k, v in params.items() if v}, context=set(ctx)))
                    break
    return sink, n
