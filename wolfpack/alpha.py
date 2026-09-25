from dataclasses import dataclass
from datetime import datetime, timezone

from .elders import CATALOG, SHOR, LEGACY, GROVER, SAFE, HYBRIDS, classical_bits, nist_status

TIERS = ["critical", "high", "medium", "low", "ok"]
WEIGHT = {"critical": 40, "high": 30, "medium": 20, "low": 10, "ok": 0}
EXPOSURE = [("live", "live network endpoint", 5), ("config", "deployed configuration", 4), ("artifact", "key or certificate material", 3.5), ("binary", "compiled artifact", 3),
            ("call", "application code", 3), ("constant", "application code", 3), ("identifier", "application code", 2.5),
            ("import", "application code", 2), ("string", "application code", 2)]
CONFIDENTIALITY = {"pke", "key-agree", "kem", "protocol", "other"}


@dataclass
class Horizon:
    shelf_life: float = 10
    migration: float = 5
    crqc_year: int = 2035

    @property
    def z(self):
        return self.crqc_year - datetime.now(timezone.utc).year


def exposure(a):
    if any("deployed" in s.context for s in a.sightings):
        return "deployed key or certificate", 4.5
    evs = {s.evidence for s in a.sightings}
    for ev, label, w in EXPOSURE:
        if ev in evs:
            return label, w
    return "application code", 2


def assess(a, h, hybrid_files=None):
    c = CATALOG[a.algo]
    bits = classical_bits(a.algo, a.params)
    label, w = exposure(a)
    a.exposure = label
    a.nist = nist_status(a.algo, a.params)
    a.action = c.replace
    weak_hash = a.params.get("hash") in ("MD5", "SHA-1") and c.primitive in ("signature", "pke")
    if c.threat == LEGACY or (bits is not None and bits < 112) or a.params.get("mode") == "ECB" or weak_hash:
        tier = "critical" if w >= 3 else "high"
        if a.params.get("mode") == "ECB":
            a.why = "ECB mode leaks plaintext structure; broken today regardless of quantum"
            a.action = "Switch to AES-256-GCM (authenticated, randomized)"
        elif weak_hash:
            a.why = f"Signature over {a.params['hash']}, which has practical collision attacks"
            a.action = "Re-sign with SHA-256 or stronger now; plan ML-DSA migration"
        elif bits is not None and bits < 112 and c.threat != LEGACY:
            a.why = f"About {bits}-bit classical security, below NIST's 112-bit floor"
            a.action = "Rotate to at least 3072-bit now, then migrate to " + c.replace
        else:
            a.why = "Broken or disallowed today, independent of any quantum computer"
    elif c.threat == SHOR:
        conf = c.primitive in CONFIDENTIALITY or a.params.get("padding") == "oaep"
        z = h.z
        if conf and h.shelf_life + h.migration > z:
            tier = "high"
            a.why = (f"Harvest now, decrypt later: data needs {h.shelf_life:g}y secrecy + {h.migration:g}y migration "
                     f"= {h.shelf_life + h.migration:g}y, but a CRQC is assumed in {z}y (Mosca)")
        elif not conf and h.migration > z:
            tier = "high"
            a.why = f"Signature migration ({h.migration:g}y) exceeds assumed time to a CRQC ({z}y)"
        else:
            tier = "medium"
            a.why = "Breakable by Shor's algorithm on a future quantum computer" + ("" if conf else "; no harvest-now risk for signatures, but forgery risk once a CRQC exists")
        if a.algo == "ECC":
            a.why += ". Key use (signing or key agreement) not determined, so confidentiality is assumed"
        if hybrid_files is not None:
            files = {s.file for s in a.sightings}
            if files and files <= hybrid_files and a.algo in ("TLS 1.3", "X25519", "X448", "ECDH", "DH"):
                if a.algo == "TLS 1.3":
                    tier, a.why, a.action = "ok", "TLS 1.3 with a hybrid ML-KEM group configured alongside it", ""
                else:
                    tier = "medium"
                    a.why = "Classical fallback next to a configured hybrid PQ group; keep only while peers lack hybrid support"
                    a.action = "Remove once clients support X25519MLKEM768"
    elif c.threat == GROVER and (bits or 0) >= 192:
        tier = "ok"
        a.why = "At least 96-bit security even against Grover"
        a.action = ""
    elif c.threat == GROVER:
        tier = "low"
        a.why = "Grover halves effective strength; fine for most data, prefer 256-bit for long-lived secrets"
        if a.algo == "AES" and not a.params.get("key_size"):
            a.why = "Key size not visible statically; AES-128 is acceptable, AES-256 preferred for long-lived data"
    else:
        tier = "ok"
        a.why = "Quantum-safe" if c.primitive in ("kem", "signature") else "No known quantum break at this strength"
        a.action = ""
    if a.test_only and tier in ("critical", "high", "medium"):
        tier = TIERS[TIERS.index(tier) + 1]
        a.why += " (test code only)"
    a.tier = tier
    a.score = round(WEIGHT[tier] + w + a.confidence, 2)
    return a


def alerts(arts, libs, sightings):
    out = []
    now = datetime.now(timezone.utc)
    for art in arts:
        test = any("test" in s.context for s in sightings if s.file == art.file)
        if art.kind == "private-key" and not art.file.startswith("tls://"):
            sev = "high" if test else "critical"
            enc = " (encrypted)" if art.details.get("encrypted") else ""
            refs = art.details.get("referenced_by", [])
            used = f"; loaded by {', '.join(refs[:3])}" if refs else ""
            out.append((sev, f"Private key{enc} stored in repository{used}", f"{art.file}:{art.line}", "Move to a secrets manager or HSM and rotate the key"))
        if art.kind == "certificate":
            na = datetime.fromisoformat(art.details["not_after"])
            if na < now:
                out.append(("high", f"Expired certificate ({art.details['subject'][:60]})", f"{art.file}:{art.line}", "Reissue"))
            elif art.algo in CATALOG and CATALOG[art.algo].threat == SHOR and na.year > 2030:
                out.append(("medium", f"Certificate valid past 2030 with quantum-vulnerable {art.algo} key", f"{art.file}:{art.line}",
                            "Shorten validity or reissue under an ML-DSA or hybrid hierarchy"))
    for lib in libs:
        if lib.note:
            out.append(("high" if "CVE" in lib.note or "Unmaintained" in lib.note else "low", f"{lib.name}: {lib.note}", f"{lib.manifest}:{lib.line}", ""))
        if not lib.used_in:
            out.append(("info", f"{lib.name} is declared but no import was found", f"{lib.manifest}:{lib.line}", "Remove it or confirm indirect use"))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(out, key=lambda x: order[x[0]])


def readiness(assets):
    asym = [a for a in assets if CATALOG[a.algo].primitive in ("pke", "signature", "key-agree", "kem", "other")]
    safe = [a for a in asym if CATALOG[a.algo].threat == SAFE]
    return {"asymmetric": len(asym), "pq_safe": len(safe), "percent": round(100 * len(safe) / len(asym)) if asym else 0,
            "hybrid": any(a.algo in HYBRIDS for a in assets),
            "tiers": {t: sum(1 for a in assets if a.tier == t) for t in TIERS}}


def lead(assets, h):
    hybrid = {s.file for a in assets if a.algo in HYBRIDS for s in a.sightings}
    for a in assets:
        assess(a, h, hybrid)
    return sorted(assets, key=lambda a: (-a.score, a.variant))
