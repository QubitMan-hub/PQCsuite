import re

from ..elders import lookup, pq_from_text, curve, parse_symmetric_name

SUITE_HASHES = {"SHA", "SHA1", "SHA256", "SHA384", "MD5"}
KX = {"ECDHE": "ECDH", "ECDH": "ECDH", "EECDH": "ECDH", "DHE": "DH", "EDH": "DH", "DH": "DH", "RSA": "RSA", "ECDSA": "ECDSA", "DSS": "DSA",
      "KRSA": "RSA", "AECDSA": "ECDSA", "ARSA": "RSA", "KEECDH": "ECDH", "KEDH": "DH"}
KEYWORDS = {"HIGH", "MEDIUM", "LOW", "EXPORT", "DEFAULT", "ALL", "COMPLEMENTOFALL", "COMPLEMENTOFDEFAULT", "ANULL", "ENULL", "NULL",
            "@STRENGTH", "PROFILE=SYSTEM", "@SECLEVEL=0", "@SECLEVEL=1", "@SECLEVEL=2", "SUITEB128", "SUITEB192", "FIPS", "PSK", "SRP", "KRB5", "ADH", "AECDH"}


def suite(name):
    n = name.strip().upper()
    if not n or n.startswith(("!", "-")):
        return []
    n = re.sub(r"^(TLS|SSL)_", "", n).replace("_WITH_", "_")
    toks = [t for t in re.split(r"[-_]", n) if t]
    out, i = [], 0
    while i < len(toks):
        t = toks[i]
        if t in KX:
            out.append((KX[t], {}))
        elif t.startswith("AES"):
            size = t[3:] if t[3:].isdigit() else (toks[i + 1] if i + 1 < len(toks) and toks[i + 1].isdigit() else None)
            if size and not t[3:].isdigit():
                i += 1
            p = {"key_size": int(size)} if size else {}
            if i + 1 < len(toks) and toks[i + 1] in ("GCM", "CBC", "CCM"):
                p["mode"] = toks[i + 1]; i += 1
            elif "GCM" in t:
                p["mode"] = "GCM"
            out.append(("AES", p))
        elif t == "CHACHA20":
            out.append(("ChaCha20-Poly1305", {}))
            if i + 1 < len(toks) and toks[i + 1] == "POLY1305":
                i += 1
        elif t in ("3DES", "DES3") or (t == "DES" and i + 1 < len(toks) and toks[i + 1] in ("CBC3", "EDE3")):
            out.append(("3DES", {}))
            if t == "DES":
                i += 1
        elif t == "DES":
            out.append(("DES", {}))
        elif t in ("RC4", "RC2"):
            out.append((t, {}))
        elif t in SUITE_HASHES and i == len(toks) - 1:
            out.append((lookup(t), {}))
        elif t == "AESGCM":
            out.append(("AES", {"mode": "GCM"}))
        i += 1
    return out


def cipher_string(s):
    out = []
    for item in re.split(r"[:,\s]+", s.strip().strip("'\"")):
        if not item or item.startswith(("!", "-")) or item.upper() in KEYWORDS or item.startswith("@"):
            continue
        item = item.lstrip("+")
        if "+" in item:
            for part in item.split("+"):
                u = part.upper()
                if u in KX:
                    out.append((KX[u], {}))
                elif u in ("AESGCM", "AES256", "AES128", "AES"):
                    out.extend(suite(u))
                elif lookup(u):
                    out.append((lookup(u), {}))
            continue
        out.extend(suite(item) or ([(lookup(item), {})] if lookup(item) else []))
    return out


def ssh_token(tok):
    t = tok.strip().lower()
    if not t or t.startswith("-"):
        return []
    t = t.lstrip("+^")
    base = re.sub(r"@(openssh\.com|libssh\.org)$", "", t)
    if pq_from_text(base) or base in ("mlkem768x25519-sha256", "sntrup761x25519-sha512"):
        return [(lookup(t) or lookup(base) or pq_from_text(base), {})]
    m = re.match(r"diffie-hellman-group(\d+|-exchange)-(sha\d+)", base)
    if m:
        size = {"1": 1024, "14": 2048, "15": 3072, "16": 4096, "18": 8192}.get(m.group(1))
        return [("DH", {"key_size": size} if size else {}), (lookup(m.group(2)), {})]
    m = re.match(r"ecdh-sha2-(nistp\d+)", base)
    if m:
        return [("ECDH", {"curve": curve(m.group(1))})]
    m = re.match(r"ecdsa-sha2-(nistp\d+)(-cert-v01)?", base)
    if m:
        return [("ECDSA", {"curve": curve(m.group(1))})]
    if base.startswith("sk-ecdsa"):
        return [("ECDSA", {"curve": "P-256"})]
    if base in ("ssh-rsa", "ssh-rsa-cert-v01"):
        return [("RSA", {"hash": "SHA-1"}), ("SHA-1", {})]
    m = re.match(r"rsa-sha2-(256|512)", base)
    if m:
        return [("RSA", {"hash": f"SHA-{m.group(1)}"}), (f"SHA-{m.group(1)}", {})]
    if "ed25519" in base:
        return [("Ed25519", {})]
    if base.startswith("curve25519"):
        return [("X25519", {})]
    if base.startswith("ssh-dss"):
        return [("DSA", {})]
    m = re.match(r"hmac-(sha2-(256|512)|sha1|md5)(-96)?(-etm)?", base)
    if m:
        h = {"sha1": "SHA-1", "md5": "MD5"}.get(m.group(1)) or f"SHA-{m.group(2)}"
        return [("HMAC", {"hash": h})] + ([(h, {})] if h in ("SHA-1", "MD5") else [])
    if base.startswith("umac"):
        return []
    a, p = parse_symmetric_name(base.replace("-ctr", "-CTR").replace("-gcm", "-GCM").replace("-cbc", "-CBC"))
    return [(a, p)] if a else []


def sig_scheme(s):
    m = re.match(r"(SHA3?-?\d*|MD5|SHA1?)with(RSA|ECDSA|DSA|RSAandMGF1|PLAIN-ECDSA|CVC-ECDSA)", s, re.I)
    if m:
        h = lookup(m.group(1))
        sig = "RSA" if m.group(2).upper().startswith("RSA") else "ECDSA" if "ECDSA" in m.group(2).upper() else "DSA"
        p = {"hash": h} if h else {}
        if "MGF1" in m.group(2).upper():
            p["padding"] = "pss"
        return [(sig, p)] + ([(h, {})] if h else [])
    m = re.match(r"(RSA|ECDSA|DSA)-(SHA\d+|MD5|SHA1)$", s, re.I)
    if m:
        h = lookup(m.group(2))
        return [(m.group(1).upper(), {"hash": h}), (h, {})]
    m = re.match(r"(RS|PS|ES|HS)(256|384|512)$", s)
    if m:
        h = f"SHA-{m.group(2)}"
        algo = {"RS": "RSA", "PS": "RSA", "ES": "ECDSA", "HS": "HMAC"}[m.group(1)]
        p = {"hash": h}
        if m.group(1) == "ES":
            p["curve"] = {"256": "P-256", "384": "P-384", "512": "P-521"}[m.group(2)]
        if m.group(1) == "PS":
            p["padding"] = "pss"
        return [(algo, p), (h, {})]
    if s.upper() == "EDDSA":
        return [("Ed25519", {})]
    a = lookup(s) or pq_from_text(s)
    return [(a, {})] if a else []
