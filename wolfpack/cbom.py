import re
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath

from . import __version__
from .elders import CATALOG, classical_bits, quantum_level

MODES = {"ecb", "cbc", "ccm", "gcm", "cfb", "ofb", "ctr"}
PADS = {"pkcs5", "pkcs7", "pkcs1v15", "oaep", "raw"}
FUNCS = {"pke": ["keygen", "encrypt", "decrypt", "sign", "verify"], "signature": ["keygen", "sign", "verify"], "key-agree": ["keygen", "keyderive"],
         "kem": ["keygen", "encapsulate", "decapsulate"], "hash": ["digest"], "mac": ["tag"], "kdf": ["keyderive"],
         "block-cipher": ["encrypt", "decrypt"], "stream-cipher": ["encrypt", "decrypt"], "ae": ["encrypt", "decrypt"], "other": ["unknown"]}
PURL = {"binary": "generic", "pypi": "pypi", "npm": "npm", "maven": "maven", "go": "golang", "cargo": "cargo", "nuget": "nuget"}


def _props(**kw):
    return [{"name": f"wolfpack:{k.replace('_', '-')}", "value": str(v)} for k, v in kw.items() if v not in (None, "")]


def _occ(s):
    o = {"location": s.file, "additionalContext": f"{s.evidence}: {s.snippet}"[:300]}
    if s.line:
        o["line"] = s.line
    return o


def algorithm_component(a):
    c = CATALOG[a.algo]
    ev = {"occurrences": [_occ(s) for s in a.sightings[:200]]}
    props = _props(tier=a.tier, risk_score=a.score, confidence=a.confidence, exposure=a.exposure, nist_status=a.nist,
                   rationale=a.why, recommendation=a.action, test_only=a.test_only or None)
    if c.primitive == "protocol":
        ver = re.search(r"(\d\.\d)", a.algo)
        pp = {"type": "tls" if "TLS" in a.algo or "SSL" in a.algo else "other"}
        if ver:
            pp["version"] = ver.group(1)
        suites = sorted({s.params["cipher"] for s in a.sightings if s.params.get("cipher")})
        if suites:
            pp["cipherSuites"] = [{"name": n} for n in suites]
        return {"type": "cryptographic-asset", "bom-ref": a.ref, "name": a.variant,
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp}, "evidence": ev, "properties": props}
    ap = {"primitive": c.primitive, "cryptoFunctions": FUNCS.get(c.primitive, ["unknown"]), "executionEnvironment": "unknown", "implementationPlatform": "unknown"}
    psi = a.params.get("key_size") or "".join(re.findall(r"-(\d+)$", a.algo))
    if psi:
        ap["parameterSetIdentifier"] = str(psi)
    if a.params.get("curve"):
        ap["curve"] = a.params["curve"]
    if a.params.get("mode"):
        ap["mode"] = m if (m := a.params["mode"].lower()) in MODES else "other"
    if a.params.get("padding"):
        ap["padding"] = a.params["padding"] if a.params["padding"] in PADS else "other"
    bits = classical_bits(a.algo, a.params)
    if bits is not None:
        ap["classicalSecurityLevel"] = bits
    q = quantum_level(a.algo, a.params)
    if q is not None:
        ap["nistQuantumSecurityLevel"] = q
    cp = {"assetType": "algorithm", "algorithmProperties": ap}
    if c.oid:
        cp["oid"] = c.oid
    return {"type": "cryptographic-asset", "bom-ref": a.ref, "name": a.variant, "cryptoProperties": cp, "evidence": ev, "properties": props}


def _ref_for(assets, fp, role):
    for a in assets:
        for s in a.sightings:
            if s.params.get("cert") == fp and s.params.get("role") == role:
                return a.ref
    return None


def _provides(lib, assets):
    roots = {m.split(".")[0].split("/")[0] for m in lib.imports} | {lib.name}
    out = []
    for a in assets:
        for s in a.sightings:
            if (s.params.get("lib") and s.params["lib"] in roots) or (lib.ecosystem == "binary" and s.file == lib.manifest):
                out.append(a.ref)
                break
    return out


def build(project, assets, arts, libs, endpoints=()):
    comps = [algorithm_component(a) for a in assets]
    for i, art in enumerate(arts):
        loc = {"occurrences": [{"location": art.file, **({"line": art.line} if art.line else {})}]}
        if art.kind == "certificate":
            d = art.details
            fp = d["sha256"][:16]
            cp = {"subjectName": d["subject"], "issuerName": d["issuer"], "notValidBefore": d["not_before"], "notValidAfter": d["not_after"],
                  "certificateFormat": "X.509", "certificateExtension": "der" if art.file.startswith("tls://") else PurePosixPath(art.file).suffix.lstrip(".") or "der"}
            sig = _ref_for(assets, fp, "certificate-signature")
            pk = _ref_for(assets, fp, "subject-public-key")
            if sig:
                cp["signatureAlgorithmRef"] = sig
            if pk:
                cp["subjectPublicKeyRef"] = pk
            comps.append({"type": "cryptographic-asset", "bom-ref": f"crypto/certificate/{d['sha256'][:24]}", "name": d["subject"][:120] or "certificate",
                          "cryptoProperties": {"assetType": "certificate", "certificateProperties": cp}, "evidence": loc,
                          "properties": _props(sha256=d["sha256"], serial=d["serial"], self_signed=d["self_signed"], source=d.get("source"))})
        else:
            algo_ref = next((a.ref for a in assets for s in a.sightings if s.file == art.file and s.line == art.line and s.params.get("role") == art.kind), None)
            rp = {"type": art.kind}
            if algo_ref:
                rp["algorithmRef"] = algo_ref
            if art.params.get("key_size"):
                rp["size"] = art.params["key_size"]
            rp["format"] = "PEM" if art.details.get("format") != "openssh" else "OpenSSH"
            comps.append({"type": "cryptographic-asset", "bom-ref": f"crypto/{art.kind}/{i}", "name": f"{art.algo} {art.kind}",
                          "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rp}, "evidence": loc,
                          "properties": _props(encrypted=art.details.get("encrypted"))})
    lib_refs, provides = [], {}
    for lib in libs:
        ref = f"lib/{lib.ecosystem}/{lib.name}" + (f"/{lib.manifest}" if lib.ecosystem == "binary" else "")
        if ref in lib_refs:
            continue
        lib_refs.append(ref)
        provides[ref] = _provides(lib, assets)
        ver = re.sub(r"^[=~^<>!\s]+", "", lib.version or "").split(",")[0].strip()
        ver = ver if re.match(r"^[\w.\-+]+$", ver) else ""
        name = lib.name.split(":")[-1] if lib.ecosystem == "maven" else lib.name
        ns = lib.name.split(":")[0] if lib.ecosystem == "maven" and ":" in lib.name else None
        purl = f"pkg:{PURL[lib.ecosystem]}/" + (f"{ns}/" if ns else "") + name + (f"@{ver}" if ver else "")
        comp = {"type": "library", "bom-ref": ref, "name": name, "purl": purl,
                "properties": _props(manifest=f"{lib.manifest}:{lib.line}" if lib.line else lib.manifest, used_in=len(lib.used_in), pq_capable=lib.pq or None, note=lib.note)}
        if ns:
            comp["group"] = ns
        if ver:
            comp["version"] = ver
        comps.append(comp)
    services, svc_deps = [], []
    for ep in endpoints:
        if ep.get("error"):
            continue
        ref = f"svc/{ep['target']}"
        used = [a.ref for a in assets if any(x.file == ep["target"] for x in a.sightings)]
        services.append({"bom-ref": ref, "name": ep["target"].split("://")[1], "endpoints": [ep["target"]],
                         "properties": _props(protocol=ep["kind"], version=ep.get("version"), preferred_group=ep.get("preferred_group"),
                                              pq_groups=",".join(ep.get("pq_groups", [])) or "none", legacy_protocols=",".join(ep.get("legacy", [])) or None)})
        svc_deps.append({"ref": ref, "dependsOn": used})
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                     "tools": {"components": [{"type": "application", "name": "wolfpack", "version": __version__}]},
                     "component": {"type": "application", "name": project, "bom-ref": "root"}},
        "components": comps,
        "dependencies": [{"ref": "root", "dependsOn": lib_refs}] + [dict({"ref": r, "dependsOn": []}, **({"provides": provides[r]} if provides[r] else {})) for r in lib_refs] + svc_deps,
    }
    if services:
        bom["services"] = services
    return bom


LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note"}


def sarif(assets, alerts):
    rules, results = {}, []
    for a in assets:
        if a.tier not in LEVEL:
            continue
        rid = f"WP-{a.algo.replace(' ', '')}"
        rules.setdefault(rid, {"id": rid, "name": a.algo, "shortDescription": {"text": f"{a.algo} usage"},
                               "help": {"text": a.action or a.why}})
        for s in a.sightings:
            if s.file.startswith("tls://"):
                continue
            declared = "non-security" in s.context and a.tier in ("critical", "high", "medium")
            text = (f"{a.variant}, declared not for security here (usedforsecurity=False): fine as a checksum; keep it out of passwords and "
                    f"signatures" if declared else f"{a.variant} [{a.tier}]: {a.why}. Fix: {a.action}")
            results.append({"ruleId": rid, "level": LEVEL["low" if declared else a.tier], "message": {"text": text},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": s.file}, "region": {"startLine": max(1, s.line)}}}],
                            "properties": {"confidence": s.confidence, "evidence": s.evidence}})
    for sev, title, where, fix in alerts:
        if sev not in LEVEL:
            continue
        f, _, ln = where.rpartition(":")
        rules.setdefault("WP-ALERT", {"id": "WP-ALERT", "name": "hygiene", "shortDescription": {"text": "Crypto hygiene alert"}})
        results.append({"ruleId": "WP-ALERT", "level": LEVEL[sev], "message": {"text": f"{title}. {fix}".strip()},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f}, "region": {"startLine": max(1, int(ln or 1))}}}]})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "wolfpack", "version": __version__, "rules": list(rules.values())}}, "results": results}]}


def audit(sightings, notes):
    return {"notes": notes, "sightings": [{"algo": s.algo, "file": s.file, "line": s.line, "evidence": s.evidence, "scout": s.scout,
                                           "verdict": s.verdict, "confidence": s.confidence, "reason": s.reason, "context": sorted(s.context),
                                           "params": s.params, "snippet": s.snippet} for s in sightings]}
