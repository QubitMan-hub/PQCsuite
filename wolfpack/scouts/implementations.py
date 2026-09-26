"""Implementation scout: recognises algorithms implemented in source by their published constants."""
import re

from ..model import Sighting
from . import iter_files, rel, is_test, read
from .lexer import LANGS, split, line_of

# Constants that appear in this order in an implementation. Chosen so one algorithm's table is not a prefix of another's:
# MD5 shares SHA-1's first four initial values, so SHA-1 needs the fifth; BLAKE2b reuses SHA-512's initial values, so SHA-2
# is recognised by its round constants only; ChaCha20 and Salsa20 share "expand 32-byte k", so neither is attempted.
WORDS = [
    ("MD5", {}, [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee]),
    ("SHA-1", {}, [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]),
    ("SHA-224", {}, [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939]),
    ("SHA-256", {}, [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]),
    ("SHA-384", {}, [0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17]),
    ("SHA-512", {}, [0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f]),
    ("SHA-3", {}, [0x800000000000808a, 0x8000000080008000, 0x80000001, 0x8000000080008081]),
    ("SM3", {}, [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600]),
    ("SM4", {}, [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]),
    ("SM4", {}, [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7]),
    ("AES", {}, [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01]),
    ("DES", {}, [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]),
]
PRIMES = [
    ("SM2", {}, "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff"),
    ("ECC", {"curve": "P-256"}, "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
    ("ECC", {"curve": "secp256k1"}, "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
]
NUM = re.compile(r"\b0[xX]([0-9a-fA-F_]+)[uUlL]*\b|\b(\d+)[uUlL]*\b")


def packed(sig):
    """The table as bytes, big- and little-endian, in the word size its largest value needs."""
    size = 8 if max(sig) > 0xFFFFFFFF else 4 if max(sig) > 0xFF else 1
    be = b"".join(v.to_bytes(size, "big") for v in sig)
    le = b"".join(v.to_bytes(size, "little") for v in sig)
    return [be, le] if be != le else [be]


def byte_tables():
    """(algo, params, patterns) for the binary scout."""
    return [(a, p, packed(sig)) for a, p, sig in WORDS] + [(a, p, [bytes.fromhex(h), bytes.fromhex(h)[::-1]]) for a, p, h in PRIMES]


def numbers(code):
    return [(int(m.group(1).replace("_", ""), 16) if m.group(1) else int(m.group(2)), m.start()) for m in NUM.finditer(code) if m.group(1) != "_"]


def find(nums, sig):
    """Position of the first literal of `sig` when its values appear consecutively; array indices are skipped for word-sized tables."""
    vals = [(v, p) for v, p in nums if v > 0xFFFF] if min(sig) > 0xFFFF else nums
    n = len(sig)
    for i, (v, p) in enumerate(vals):
        if v == sig[0] and [x for x, _ in vals[i:i + n]] == sig:
            return p
    return None


def scan(root, scope=False):
    sink, n = [], 0
    for p in iter_files(root, scope):
        lang = LANGS.get(p.suffix.lower())
        if not lang:
            continue
        text = read(p)
        if not text:
            continue
        n += 1
        low = text.lower()
        have = {v for v, _ in numbers(text)}
        if not any(set(sig) <= have for _, _, sig in WORDS) and not any(prime in low for _, _, prime in PRIMES):
            continue
        code = split(text, lang)[0]
        path, lines = rel(root, p), text.splitlines()
        ctx = {"test"} if is_test(path) else set()
        hits = []
        nums = numbers(code)
        for algo, params, sig in WORDS:
            pos = find(nums, sig)
            if pos is not None:
                hits.append((algo, params, pos))
        low = code.lower()
        for algo, params, prime in PRIMES:
            pos = low.find(prime)
            if pos >= 0:
                hits.append((algo, params, pos))
        for algo, params, pos in hits:
            line = line_of(code, pos)
            sink.append(Sighting(algo=algo, file=path, line=line, evidence="constant", scout="implementations",
                                 snippet=lines[line - 1].strip()[:160] if line <= len(lines) else "", lang=lang,
                                 params=dict(params, role="implementation"), context=set(ctx)))
    return sink, n
