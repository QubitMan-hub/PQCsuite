import io
import re
import zipfile

from ..elders import lookup, pq_from_text
from ..model import Sighting, Library
from . import iter_files, rel, is_test, SKIP_DIRS, BUILD_DIRS
from .source import classify_literal


def _words(hexwords, size=4):
    be = bytes.fromhex("".join(hexwords))
    le = b"".join(bytes.fromhex(w)[::-1] for w in hexwords)
    return [be, le] if be != le else [be]


CONSTANTS = [
    ("AES", [bytes.fromhex("637c777bf26b6fc53001672bfed7ab76")], "AES S-box"),
    ("SHA-256", _words(["428a2f98", "71374491", "b5c0fbcf", "e9b5dba5"]), "SHA-256 round constants"),
    ("SHA-512", _words(["428a2f98d728ae22", "7137449123ef65cd"]), "SHA-512 round constants"),
    ("SHA-1", _words(["67452301", "efcdab89", "98badcfe", "10325476", "c3d2e1f0"]), "SHA-1 initial state"),
    ("MD5", _words(["d76aa478", "e8c7b756", "242070db", "c1bdceee"]), "MD5 sine table"),
    ("ChaCha20", [b"expand 32-byte k"], "ChaCha20 sigma"),
    ("ECDSA", [bytes.fromhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
               bytes.fromhex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")[::-1]], "NIST P-256 prime"),
    ("ECDSA", [bytes.fromhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
               bytes.fromhex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")[::-1]], "secp256k1 prime"),
    ("ML-KEM", [b"ML-KEM-768", b"MLKEM768", b"X25519MLKEM768"], "ML-KEM identifier"),
    ("ML-DSA", [b"ML-DSA-65", b"MLDSA65", b"ML-DSA-44", b"ML-DSA-87"], "ML-DSA identifier"),
]
CURVE_OF = {"NIST P-256 prime": "P-256", "secp256k1 prime": "secp256k1"}
VERSIONS = [
    (re.compile(rb"OpenSSL (\d+\.\d+\.\d+[a-z]?)[ \x00]"), "openssl"),
    (re.compile(rb"LibreSSL (\d+\.\d+\.\d+)"), "libressl"),
    (re.compile(rb"mbed TLS (\d+\.\d+\.\d+)"), "mbedtls"),
    (re.compile(rb"wolfSSL (\d+\.\d+\.\d+)"), "wolfssl"),
    (re.compile(rb"\x00go(1\.\d+(?:\.\d+)?)\x00"), "go"),
]
NATIVE_EXT = {".so", ".dll", ".exe", ".dylib", ".a", ".lib", ".o", ".node", ".pyd", ".bin", ".elf"}
MAGIC = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
ARCHIVES = {".jar", ".war", ".ear", ".aar"}
CRYPTO_REFS = (b"javax/crypto", b"java/security", b"org/bouncycastle", b"javax/net/ssl")
MAX = 256_000_000


def _version_tuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def lib_note(name, ver):
    t = _version_tuple(ver)
    if name == "openssl":
        if t < (1, 1, 1):
            return "End of life; no security fixes", False
        if t < (3, 0, 0):
            return "OpenSSL 1.1.1 reached end of life in September 2023", False
        return ("Supports ML-KEM, ML-DSA and SLH-DSA natively", True) if t >= (3, 5, 0) else ("", False)
    if name == "go":
        return ("crypto/tls offers X25519MLKEM768 by default", True) if t >= (1, 24) else ("", False)
    return "", False


def scan_native(data, path, base):
    sights, libs = [], []
    for algo, pats, label in CONSTANTS:
        for pat in pats:
            i = data.find(pat)
            if i >= 0:
                p = {"role": "implementation"}
                if label in CURVE_OF:
                    p["curve"] = CURVE_OF[label]
                name = (lookup(pat.decode()) or pq_from_text(pat.decode())) if algo in ("ML-KEM", "ML-DSA") else algo
                sights.append(Sighting(algo=name, file=path, line=0, evidence="binary", scout="binary",
                                       snippet=f"{label} at offset 0x{i:x}", lang="native", params=p, context=set(base)))
                break
    seen = set()
    for rx, name in VERSIONS:
        m = rx.search(data)
        if m and name not in seen:
            seen.add(name)
            ver = m.group(1).decode()
            note, pq = lib_note(name, ver)
            libs.append(Library(name=name, ecosystem="binary", manifest=path, line=0, version=ver, used_in=[path], pq=pq, note=note))
    return sights, libs


def scan_class(data, where, base):
    if not any(r in data for r in CRYPTO_REFS):
        return []
    out = []
    for m in re.finditer(rb"[\x20-\x7e]{2,64}", data):
        hits, prose = classify_literal(m.group(0).decode())
        for a, p in [] if prose else hits:
            if a:
                out.append(Sighting(algo=a, file=where, line=0, evidence="binary", scout="binary", snippet=f"class constant \"{m.group(0).decode()}\"",
                                    lang="jvm", params=dict(p), context=set(base)))
    return out


def scan_archive(data, path, base, depth=0):
    sights = []
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return sights
    for info in z.infolist():
        if info.file_size > MAX:
            continue
        n = info.filename
        if not (n.endswith(".class") or depth == 0 and n.endswith(".jar")):
            continue
        try:
            entry = z.read(info)
        except Exception:
            continue
        if n.endswith(".class"):
            sights += scan_class(entry, f"{path}!{n}", base)
        else:
            sights += scan_archive(entry, f"{path}!{n}", base, 1)
    return sights


def scan(root, include_vendor=False):
    sights, libs, n = [], [], 0
    for p in iter_files(root, include_vendor, max_bytes=MAX, skip=SKIP_DIRS - BUILD_DIRS):
        ext = p.suffix.lower()
        if ext not in NATIVE_EXT and ext not in ARCHIVES and ext != ".class":
            try:
                with open(p, "rb") as f:
                    if not f.read(4).startswith(MAGIC):
                        continue
            except OSError:
                continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        path = rel(root, p)
        base = {"test"} if is_test(path) else set()
        n += 1
        if ext in ARCHIVES:
            sights += scan_archive(data, path, base)
        elif ext == ".class":
            sights += scan_class(data, path, base)
        else:
            s, l = scan_native(data, path, base)
            sights += s
            libs += l
    return sights, libs, n
