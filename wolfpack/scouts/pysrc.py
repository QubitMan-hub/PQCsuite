import ast

from ..elders import lookup, pq_from_text, curve, parse_transformation
from .suites import sig_scheme

ROOTS = ("cryptography", "Crypto", "Cryptodome", "nacl", "ecdsa", "rsa", "oqs", "paramiko", "OpenSSL", "jwt", "jose", "hashlib", "hmac", "ssl", "bcrypt", "argon2")
PREFIX = [("cryptography.hazmat.primitives.", "C."), ("cryptography.hazmat.", "C."), ("Cryptodome.", "Crypto.")]
HASHLIB = {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s", "md4"}


def _norm(q):
    for a, b in PREFIX:
        if q.startswith(a):
            return b + q[len(a):]
    return q


class PyScout(ast.NodeVisitor):
    def __init__(self, path, src, constants=True):
        self.path, self.lines, self.alias, self.consts, self.out, self.seen = path, src.splitlines(), {}, {}, [], set()
        self.constants = constants
        self.root = None

    def emit(self, node, algo, params=None, evidence="call"):
        if not algo:
            return
        params = {k: v for k, v in (params or {}).items() if v is not None}
        if self.root and self.root not in ("hashlib", "hmac", "ssl"):
            params["lib"] = self.root
        ln = getattr(node, "lineno", 0)
        snip = self.lines[ln - 1].strip()[:160] if 0 < ln <= len(self.lines) else ""
        self.out.append((algo, ln, evidence, snip, params))

    def qual(self, e):
        if isinstance(e, ast.Name):
            return self.alias.get(e.id, "")
        if isinstance(e, ast.Attribute):
            b = self.qual(e.value)
            return f"{b}.{e.attr}" if b else e.attr
        if isinstance(e, ast.Call):
            return self.qual(e.func)
        return ""

    def val(self, e):
        if isinstance(e, ast.Constant):
            return e.value
        if isinstance(e, ast.Name) and e.id in self.consts:
            return self.consts[e.id]
        if isinstance(e, (ast.List, ast.Tuple)):
            return [self.val(x) for x in e.elts]
        return None

    def arg(self, call, pos, kw):
        for k in call.keywords:
            if k.arg == kw:
                return k.value
        return call.args[pos] if pos is not None and len(call.args) > pos else None

    def hashname(self, e):
        if e is None:
            return None
        v = self.val(e)
        if isinstance(v, str):
            return lookup(v)
        q = _norm(self.qual(e)).split(".")[-1]
        return lookup(q)

    def visit_Import(self, node):
        for n in node.names:
            self.alias[n.asname or n.name.split(".")[0]] = n.name if n.asname else n.name.split(".")[0]
            self._import_sighting(node, n.name)

    def visit_ImportFrom(self, node):
        mod = node.module or ""
        for n in node.names:
            full = f"{mod}.{n.name}"
            self.alias[n.asname or n.name] = full
            self._import_sighting(node, full)

    def _import_sighting(self, node, full):
        if not full.startswith(ROOTS) or full.split(".")[0] in ("hashlib", "hmac", "ssl", "jwt"):
            return
        last = full.split(".")[-1]
        self.root = full.split(".")[0]
        algo = pq_from_text(last) or (lookup(last) if last.upper() not in ("HASHES", "SERIALIZATION", "PADDING", "PRIMITIVES") else None)
        if algo:
            self.emit(node, algo, evidence="import")

    def visit_Assign(self, node):
        v = node.value
        if self.constants and isinstance(v, ast.Constant) and isinstance(v.value, (str, int)):
            for t in node.targets:
                if isinstance(t, ast.Name):
                    self.consts[t.id] = v.value
        q = self.qual(v)
        self.root = None
        if q.startswith("ssl.TLSVersion.") or q.startswith("ssl.PROTOCOL_"):
            a = lookup(q.split(".")[-1])
            if a:
                self.emit(node, a, evidence="constant")
        self.generic_visit(node)

    def visit_Call(self, node):
        if id(node) in self.seen:
            return self.generic_visit(node)
        raw = self.qual(node.func)
        q = _norm(raw)
        self.root = raw.split(".")[0] if raw.split(".")[0] in ROOTS else None
        last = q.split(".")[-1]
        h = self.handle(node, q, last)
        if h is None and (raw.split(".")[0] in ROOTS or q.startswith("C.")):
            pq = pq_from_text(q)
            if pq:
                self.emit(node, pq)
        self.generic_visit(node)

    def handle(self, n, q, last):
        a = lambda pos, kw=None: self.arg(n, pos, kw)
        if q.startswith("hashlib."):
            if last in HASHLIB:
                return self.emit(n, lookup(last)) or True
            if last == "new":
                return self.emit(n, lookup(str(self.val(a(0, "name")) or ""))) or True
            if last == "pbkdf2_hmac":
                return self.emit(n, "PBKDF2", {"hash": self.hashname(a(0, "hash_name"))}) or True
            if last == "scrypt":
                return self.emit(n, "scrypt") or True
        if q in ("hmac.new", "hmac.digest", "C.hmac.HMAC", "Crypto.Hash.HMAC.new"):
            e = a(2, "digestmod") if q.startswith("hmac.") else a(1, "algorithm") if q.startswith("C.") else a(2, "digestmod")
            return self.emit(n, "HMAC", {"hash": self.hashname(e)}) or True
        if q.startswith("C.asymmetric."):
            mod = q.split(".")[2]
            if mod == "rsa" and last == "generate_private_key":
                return self.emit(n, "RSA", {"key_size": self.val(a(1, "key_size"))}) or True
            if mod == "dsa" and last == "generate_private_key":
                return self.emit(n, "DSA", {"key_size": self.val(a(0, "key_size"))}) or True
            if mod == "dh" and last == "generate_parameters":
                return self.emit(n, "DH", {"key_size": self.val(a(1, "key_size"))}) or True
            if mod == "ec" and last in ("generate_private_key", "derive_private_key"):
                c = a(0 if last == "generate_private_key" else 1, "curve")
                if isinstance(c, ast.Call):
                    self.seen.add(id(c))
                return self.emit(n, "ECC", {"curve": curve(self.qual(c).split(".")[-1]) if c is not None else None}) or True
            if mod == "ec" and last == "ECDSA":
                return self.emit(n, "ECDSA", {"hash": self.hashname(a(0, "algorithm"))}) or True
            if mod == "ec" and last == "ECDH":
                return self.emit(n, "ECDH") or True
            if mod in ("ed25519", "ed448", "x25519", "x448"):
                return self.emit(n, lookup(mod)) or True
            if mod == "padding" and last in ("OAEP", "PKCS1v15", "PSS"):
                return self.emit(n, "RSA", {"padding": {"OAEP": "oaep", "PKCS1v15": "pkcs1v15", "PSS": "pss"}[last]}) or True
            if mod == "ec" and curve(last):
                return True
        if q == "C.ciphers.Cipher":
            alg, mode = a(0, "algorithm"), a(1, "mode")
            if isinstance(alg, ast.Call):
                self.seen.add(id(alg))
                algo = self._cipher_algo(_norm(self.qual(alg)).split(".")[-1])
                p = {}
                if isinstance(mode, ast.Call):
                    self.seen.add(id(mode))
                    m = _norm(self.qual(mode)).split(".")[-1].upper()
                    p["mode"] = m if m in ("ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "XTS", "CFB8") else None
                return self.emit(n, algo, p) or True
        if q.startswith("C.ciphers.algorithms."):
            return self.emit(n, self._cipher_algo(last)) or True
        if q.startswith("C.ciphers.modes."):
            return True
        if q.startswith("C.ciphers.aead."):
            base = q.split(".")[3]
            if base.startswith("AES"):
                p = {"mode": base[3:] or None}
                if last == "generate_key":
                    p["key_size"] = self.val(a(0, "bit_length"))
                return self.emit(n, "AES", p) or True
            if base.startswith("ChaCha20"):
                return self.emit(n, "ChaCha20-Poly1305") or True
        if q.startswith("C.hashes."):
            return self.emit(n, lookup(last)) or True
        if q.startswith("C.kdf."):
            if "pbkdf2" in q.lower():
                return self.emit(n, "PBKDF2", {"hash": self.hashname(a(0, "algorithm"))}) or True
            for k in ("HKDF", "Scrypt", "Argon2"):
                if last.startswith(k):
                    return self.emit(n, lookup(k)) or True
        if q.startswith("Crypto."):
            parts = q.split(".")
            if len(parts) >= 3:
                pkg, mod = parts[1], parts[2]
                if pkg == "PublicKey" and last in ("generate", "construct", "import_key", "importKey"):
                    if mod == "RSA":
                        return self.emit(n, "RSA", {"key_size": self.val(a(0, "bits")) if last == "generate" else None}) or True
                    if mod == "ECC":
                        cv = self.val(a(None, "curve"))
                        return self.emit(n, "ECC", {"curve": curve(cv) if isinstance(cv, str) else None}) or True
                    if mod == "DSA":
                        return self.emit(n, "DSA", {"key_size": self.val(a(0, "bits")) if last == "generate" else None}) or True
                if pkg == "Cipher" and last == "new":
                    if mod in ("PKCS1_OAEP", "PKCS1_v1_5"):
                        return self.emit(n, "RSA", {"padding": "oaep" if "OAEP" in mod else "pkcs1v15"}) or True
                    algo = self._cipher_algo(mod)
                    m = a(1, "mode")
                    mode = self.qual(m).split(".")[-1].replace("MODE_", "") if m is not None else None
                    return self.emit(n, algo, {"mode": mode if mode in ("ECB", "CBC", "GCM", "CTR", "CFB", "OFB", "EAX", "CCM", "SIV", "OCB") else None}) or True
                if pkg == "Signature" and mod in ("pkcs1_15", "PKCS1_v1_5", "pss", "PKCS1_PSS") and last == "new":
                    return self.emit(n, "RSA", {"padding": "pss" if "pss" in mod.lower() else "pkcs1v15"}) or True
                if pkg == "Hash" and last == "new" and mod != "HMAC":
                    return self.emit(n, lookup(mod)) or True
                if pkg == "Protocol" and last in ("PBKDF2", "scrypt", "HKDF"):
                    return self.emit(n, lookup(last)) or True
        if q in ("jwt.encode", "jwt.decode", "jose.jwt.encode", "jose.jwt.decode", "jwt.PyJWT.encode"):
            e = a(2, "algorithm" if last == "encode" else "algorithms")
            v = self.val(e)
            vals = v if isinstance(v, list) else [v] if v else (["HS256"] if last == "encode" and e is None else [])
            for s in vals:
                for algo, p in sig_scheme(str(s)) if s else []:
                    self.emit(n, algo, p)
            return True
        if q in ("ssl.SSLContext", "ssl.wrap_socket"):
            e = a(0, "protocol") if q == "ssl.SSLContext" else a(None, "ssl_version")
            if e is not None:
                self.emit(n, lookup(self.qual(e).split(".")[-1]), evidence="constant")
            return True
        if q.startswith("paramiko.") and last == "generate":
            k = q.split(".")[1]
            algo = {"RSAKey": "RSA", "ECDSAKey": "ECDSA", "DSSKey": "DSA", "Ed25519Key": "Ed25519"}.get(k)
            return self.emit(n, algo, {"key_size": self.val(a(0, "bits"))} if algo == "RSA" else {}) or True
        if q in ("rsa.newkeys",):
            return self.emit(n, "RSA", {"key_size": self.val(a(0, "nbits"))}) or True
        if q.startswith("ecdsa.") and last in ("generate", "from_string", "from_pem"):
            cv = a(None, "curve")
            return self.emit(n, "ECDSA", {"curve": curve(self.qual(cv).split(".")[-1].replace("NIST", "P")) if cv is not None else None}) or True
        if q.startswith("nacl."):
            if q.startswith("nacl.signing"):
                return self.emit(n, "Ed25519") or True
            if q.startswith("nacl.public"):
                return self.emit(n, "X25519") or True
        if q in ("oqs.KeyEncapsulation", "oqs.Signature"):
            return self.emit(n, pq_from_text(str(self.val(a(0, "alg_name")) or ""))) or True
        if q.startswith("bcrypt.") and last in ("hashpw", "gensalt", "kdf"):
            return self.emit(n, "bcrypt") or True
        if q.startswith("argon2."):
            return self.emit(n, "Argon2") or True
        return None

    def _cipher_algo(self, name):
        name = name.replace("Cipher", "")
        a = lookup(name) or parse_transformation(name)[0]
        return a


def scan_python(path, src, constants=True):
    try:
        tree = ast.parse(src)
    except (SyntaxError, ValueError):
        return None
    s = PyScout(path, src, constants)
    s.visit(tree)
    return s.out
