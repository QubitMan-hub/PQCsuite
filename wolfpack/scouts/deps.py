import json
import re
import tomllib
from pathlib import Path

from ..model import Library
from . import iter_files, rel, read
from .lexer import LANGS

# name: (import markers, implied algorithms, pq-capable, note)
KNOWN = {
    "pypi": {
        "cryptography": (["cryptography"], (), True, ""), "pycryptodome": (["Crypto"], (), False, ""), "pycryptodomex": (["Cryptodome"], (), False, ""),
        "pycrypto": (["Crypto"], (), False, "Unmaintained since 2013 with known CVEs; replace with pycryptodome or cryptography"),
        "pyjwt": (["jwt"], (), False, ""), "python-jose": (["jose"], (), False, ""), "ecdsa": (["ecdsa"], ("ECDSA",), False, ""),
        "rsa": (["rsa"], ("RSA",), False, ""), "pynacl": (["nacl"], ("Ed25519", "X25519"), False, ""), "paramiko": (["paramiko"], (), False, ""),
        "pyopenssl": (["OpenSSL"], (), False, ""), "liboqs-python": (["oqs"], (), True, ""), "bcrypt": (["bcrypt"], ("bcrypt",), False, ""),
        "argon2-cffi": (["argon2"], ("Argon2",), False, ""), "m2crypto": (["M2Crypto"], (), False, ""), "tink": (["tink"], (), False, ""),
        "kyber-py": (["kyber"], ("ML-KEM",), True, "Educational implementation, not constant-time"),
        "dilithium-py": (["dilithium"], ("ML-DSA",), True, "Educational implementation, not constant-time"),
    },
    "npm": {
        "node-forge": (["node-forge"], (), False, ""), "jsonwebtoken": (["jsonwebtoken"], (), False, ""), "jose": (["jose"], (), False, ""),
        "node-rsa": (["node-rsa"], ("RSA",), False, ""), "elliptic": (["elliptic"], ("ECC",), False, ""), "tweetnacl": (["tweetnacl"], ("Ed25519", "X25519"), False, ""),
        "crypto-js": (["crypto-js"], (), False, "Discontinued; migrate to WebCrypto or node:crypto"), "bcrypt": (["bcrypt"], ("bcrypt",), False, ""),
        "bcryptjs": (["bcryptjs"], ("bcrypt",), False, ""), "@noble/curves": (["@noble/curves"], ("ECC",), False, ""),
        "@noble/post-quantum": (["@noble/post-quantum"], (), True, ""), "openpgp": (["openpgp"], (), False, ""), "jsrsasign": (["jsrsasign"], ("RSA",), False, ""),
        "sshpk": (["sshpk"], (), False, ""),
    },
    "maven": {
        "org.bouncycastle": (["org.bouncycastle"], (), True, ""), "com.nimbusds:nimbus-jose-jwt": (["com.nimbusds.jose"], (), False, ""),
        "io.jsonwebtoken": (["io.jsonwebtoken"], (), False, ""), "com.google.crypto.tink": (["com.google.crypto.tink"], (), False, ""),
        "org.openquantumsafe": (["org.openquantumsafe"], (), True, ""),
    },
    "go": {
        "golang.org/x/crypto": (["golang.org/x/crypto"], (), False, ""), "github.com/cloudflare/circl": (["github.com/cloudflare/circl"], (), True, ""),
        "github.com/golang-jwt/jwt": (["github.com/golang-jwt/jwt"], (), False, ""), "filippo.io/mlkem768": (["filippo.io/mlkem768"], ("ML-KEM-768",), True, ""),
        "github.com/open-quantum-safe/liboqs-go": (["github.com/open-quantum-safe/liboqs-go"], (), True, ""),
    },
    "cargo": {
        "ring": (["ring"], (), False, ""), "rsa": (["rsa"], ("RSA",), False, ""), "openssl": (["openssl"], (), False, ""), "rustls": (["rustls"], (), True, ""),
        "ed25519-dalek": (["ed25519_dalek"], ("Ed25519",), False, ""), "x25519-dalek": (["x25519_dalek"], ("X25519",), False, ""),
        "aes-gcm": (["aes_gcm"], ("AES",), False, ""), "sha1": (["sha1"], ("SHA-1",), False, ""), "md-5": (["md5"], ("MD5",), False, ""),
        "md5": (["md5"], ("MD5",), False, ""), "ml-kem": (["ml_kem"], ("ML-KEM",), True, ""), "ml-dsa": (["ml_dsa"], ("ML-DSA",), True, ""),
        "pqcrypto": (["pqcrypto"], (), True, ""), "oqs": (["oqs"], (), True, ""),
    },
    "nuget": {
        "bouncycastle.cryptography": (["Org.BouncyCastle"], (), True, ""), "portable.bouncycastle": (["Org.BouncyCastle"], (), False, ""),
        "system.identitymodel.tokens.jwt": (["System.IdentityModel.Tokens.Jwt"], (), False, ""), "nsec.cryptography": (["NSec.Cryptography"], (), False, ""),
    },
}


def _match(eco, name):
    table = KNOWN[eco]
    n = name.lower() if eco in ("pypi", "npm", "nuget") else name
    if n in table:
        return n, table[n]
    for k, v in table.items():
        if eco in ("maven", "go") and n.startswith(k):
            return k, v
    return None, None


def _add(out, eco, name, version, manifest, line):
    key, info = _match(eco, name)
    if key and not any(l.name == key and l.manifest == manifest for l in out):
        imports, implies, pq, note = info
        lib = Library(name=key, ecosystem=eco, manifest=manifest, line=line, version=version, imports=tuple(imports), implies=implies, pq=pq)
        lib.note = note
        out.append(lib)


def _lineno(text, needle):
    i = text.find(needle)
    return text.count("\n", 0, i) + 1 if i >= 0 else 1


def parse_manifest(p, path, text, out):
    name = p.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        for i, l in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)\s*(?:\[.*?\])?\s*([<>=!~].*)?$", l.split("#")[0])
            if m:
                _add(out, "pypi", m.group(1), (m.group(2) or "").strip(), path, i)
    elif name == "pyproject.toml":
        try:
            d = tomllib.loads(text)
        except Exception:
            return
        deps = list(d.get("project", {}).get("dependencies", [])) + list(d.get("tool", {}).get("poetry", {}).get("dependencies", {}).keys())
        for dep in deps:
            m = re.match(r"^\s*([A-Za-z0-9_.\-]+)(.*)$", dep)
            if m:
                _add(out, "pypi", m.group(1), m.group(2).strip(), path, _lineno(text, m.group(1)))
    elif name == "package.json":
        try:
            d = json.loads(text)
        except Exception:
            return
        for sect in ("dependencies", "devDependencies", "peerDependencies"):
            for k, v in (d.get(sect) or {}).items():
                _add(out, "npm", k, str(v), path, _lineno(text, f'"{k}"'))
    elif name == "pom.xml":
        for m in re.finditer(r"<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<]+)</version>)?", text):
            _add(out, "maven", f"{m.group(1)}:{m.group(2)}", m.group(3) or "", path, text.count("\n", 0, m.start()) + 1)
    elif name in ("build.gradle", "build.gradle.kts"):
        for m in re.finditer(r"""['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]""", text):
            _add(out, "maven", f"{m.group(1)}:{m.group(2)}", m.group(3), path, text.count("\n", 0, m.start()) + 1)
    elif name == "go.mod":
        for i, l in enumerate(text.splitlines(), 1):
            m = re.match(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-/]+)\s+(v[\w.\-+]+)", l)
            if m:
                _add(out, "go", m.group(1), m.group(2), path, i)
    elif name == "cargo.toml":
        try:
            d = tomllib.loads(text)
        except Exception:
            return
        for k, v in (d.get("dependencies") or {}).items():
            _add(out, "cargo", k, v if isinstance(v, str) else str(v.get("version", "")), path, _lineno(text, k))
    elif p.suffix.lower() == ".csproj" or name == "packages.config":
        for m in re.finditer(r'(?:PackageReference|package)\s+(?:Include|id)="([^"]+)"(?:\s+Version|\s+version)?="?([^"\s/>]*)', text):
            _add(out, "nuget", m.group(1), m.group(2), path, text.count("\n", 0, m.start()) + 1)


def used_by(lib, files):
    pats = []
    for mod in lib.imports:
        e = re.escape(mod)
        if lib.ecosystem == "pypi":
            pats.append(rf"^\s*(?:import|from)\s+{e}\b")
        elif lib.ecosystem == "npm":
            pats.append(rf"""(?:require\(\s*['"]{e}(?:/[^'"]*)?['"]|from\s+['"]{e}(?:/[^'"]*)?['"])""")
        elif lib.ecosystem == "go":
            pats.append(rf'"{e}[^"]*"')
        elif lib.ecosystem == "cargo":
            pats.append(rf"\b(?:use|extern crate)\s+{e}\b|\b{e}::")
        else:
            pats.append(rf"^\s*(?:import|using)\s+{e}")
    rx = re.compile("|".join(pats), re.M)
    return [path for path, text in files if rx.search(text)]


def scan(root, include_vendor=False):
    libs, code = [], []
    for p in iter_files(root, include_vendor):
        n = p.name.lower()
        if n.startswith("requirements") or n in ("pyproject.toml", "package.json", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "cargo.toml", "packages.config") or p.suffix.lower() == ".csproj":
            t = read(p)
            if t:
                parse_manifest(p, rel(root, p), t, libs)
        elif p.suffix.lower() in LANGS:
            t = read(p)
            if t:
                code.append((rel(root, p), t))
    for lib in libs:
        lib.used_in = used_by(lib, code)
    return libs
