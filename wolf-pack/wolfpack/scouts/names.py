"""Code that names its algorithm: aes_encrypt(), md5_update(), BCrypt.HashPassword(), class HkdfSha256. No library API is needed."""
import re
from bisect import bisect

from ..elders import lookup, pq_from_text
from .suites import sig_scheme

TOKEN = (r"ml_?(?:kem|dsa)(?:\d+)?|slh_?dsa|sha3_?(?:224|256|384|512)|sha_?(?:1|224|256|384|512)|md[45]|blake2[bs]?|ripemd_?160|x?chacha20|x?salsa20"
         r"|aes(?:128|192|256)?|ed25519(?:ph|ctx)?|ed448|eddsa|x25519|curve25519|x448|argon2(?:id|i|d)?|pbkdf2"
         r"|(?:rs|ps|es|hs)(?:256|384|512)|3des|des3|tripledes|desede|three_des|des|rc4|arcfour|rc2|blowfish|rijndael"
         r"|hmac|hkdf|bcrypt|scrypt|ecdsa|ecdh|rsa|dsa|md2|aegis(?:128l|256)|concat_?kdf|(?:ansi_?)?x963_?kdf|spake2|balloon(?:_?hashing)?|[ht]otp")
WORD = re.compile(rf"(?:(?<![A-Za-z0-9])|(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Za-z]{{1,6}}\d))(?i:{TOKEN})(?![a-z])")
CALL = re.compile(r"(?<![\w.$])((?:new\s+)?[A-Za-z_$][\w$]*(?:\s*(?:\.|::|->)\s*[A-Za-z_$][\w$]*)*)\s*(?:<[\w\s,<>\[\]]*>)?\s*\(")
DEFN = re.compile(r"\b(?:class|struct|record|trait|impl|object)\s+([A-Za-z_]\w*)|\btype\s+([A-Za-z_]\w*)\s+struct\b")
NOT_USE = re.compile(r"(?i)(?:exception|error|errors|attribute|parameters|params|options|settings|config|info|name|names|size|length|type|types)$"
                     r"|(?:not_?supported|unsupported|invalid)|^(?-i:is|has|can|Is|Has|Can)(?:[A-Z_]|$)")
TEST_WORD = re.compile(r"(?:Test|TEST|(?:^|(?<=_))test)s?(?=$|_|[A-Z])")
UTILITY = re.compile(r"(?i)^(?:en|de)code|^parse|^format|^to\w*string$|^values?$|^valueof$|^from[A-Z_]|^ordinal$|^equals$|^hashcode$")
KDF = {"HKDF", "PBKDF2"}
CIPHER_VERB = re.compile(r"(?i)crypt|cipher|key|setup|ede|cbc|ecb|block|round")
KEYWORDS = {"if", "for", "while", "switch", "return", "sizeof", "typeof", "nameof", "catch", "elif", "and", "or", "not", "in", "assert", "print", "defined"}
QUOTED = re.compile(r"""(?s:(\"\"\"|\'\'\').*?\1)|"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*'|`[^`]*`""")
TYPE_PREFIX = re.compile(r"(?:^|[;{}])\s*(?:(?:static|inline|const|unsigned|signed|struct|enum|virtual|explicit|__\w+)\s+)*[A-Za-z_][\w:<>]*[\s*&]+$")


def algos(name):
    out = []
    for m in WORD.finditer(name):
        t, nxt = m.group(0), name[m.end():m.end() + 1]
        if t.isalpha() and t.isupper() and nxt.isupper() and not name[m.end() + 1:m.end() + 2].islower() and not re.match(r"(?i)sha", name[m.end():]) \
                and not WORD.match(name, m.end()):
            continue
        if re.fullmatch(r"(?i)(?:rs|ps|es|hs)\d+", t):
            out += [a for a, _ in sig_scheme(t.upper()) if a]
            continue
        t = re.sub(r"(?i)^three_des$", "3des", re.sub(r"(?i)^[ht]otp$", "hmac", t))
        a = pq_from_text(t) if re.match(r"(?i)ml|slh", t) else lookup(re.sub(r"(?i)ph$|ctx$", "", t.replace("_", "")))
        if a == "DES" and not CIPHER_VERB.search(name):
            continue
        if a:
            out.append(a)
    if KDF & set(out):
        out = [a for a in out if a != "HMAC"]
    if {"X25519", "X448"} & set(out):
        out = [a for a in out if a != "ECDH"]
    return list(dict.fromkeys(out))


def closes(code, i):
    """Index just past the parenthesis group that opens at code[i]."""
    depth = 0
    for j in range(i, min(len(code), i + 4000)):
        depth += {"(": 1, ")": -1}.get(code[j], 0)
        if depth == 0:
            return j + 1
    return len(code)


def declaration(code, m, lang, header):
    """A prototype, extern or Java enum constant: the name is declared here, not used."""
    before = code[code.rfind("\n", 0, m.start()) + 1:m.start()]
    if re.search(r"\b(?:extern|partial|abstract)\b", before):
        return True
    after = code[closes(code, m.end() - 1):].lstrip()[:1]
    if header and lang == "c" and after == ";" and TYPE_PREFIX.search(before):
        return True
    return lang == "java" and not before.strip() and re.fullmatch(r"[A-Z][A-Z0-9_]*", m.group(1)) is not None and after in (",", ";", "{")


def scan(code, lang, path=""):
    """Yields (line, algo) for calls, constructors and type definitions whose names spell an algorithm."""
    if path.endswith(".d.ts"):
        return
    code = QUOTED.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), code) if lang != "rust" else re.sub(r"(?m)^[ \t]*#!?\[.*$", "", code)
    ends = [m.start() for m in re.finditer("\n", code)]
    header = path.endswith((".h", ".hpp", ".hh"))
    for rx in (CALL, DEFN):
        for m in rx.finditer(code):
            g = m.lastindex
            name = re.sub(r"\s+", "", re.sub(r"^new\s+", "", m.group(g)))
            parts = re.split(r"\.|::|->", name)
            last = parts[-1]
            found = algos(name)
            if not found or last in KEYWORDS or NOT_USE.search(last) or any(TEST_WORD.search(p) for p in parts):
                continue
            if UTILITY.search(last) and not algos(last) or rx is CALL and declaration(code, m, lang, header):
                continue
            for a in found:
                yield bisect(ends, m.start(g)) + 1, a
