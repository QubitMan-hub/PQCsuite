import socket
from dataclasses import MISSING

NAME = "pqcsuite"
__version__ = "0.1.0"
HTTP_IDLE = 30  # seconds an HTTP client may stay silent before its connection is closed

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401
except ImportError:
    import cryptography
    raise ImportError(f"pqcsuite needs cryptography 49 or newer for ML-KEM and ML-DSA, and this Python has {cryptography.__version__}: "
                      "pip install --upgrade 'cryptography>=49'") from None


def build(cls, d, where, **extra):
    """A settings dataclass from a TOML table, with clear errors for unknown, missing and mistyped settings."""
    fields = cls.__dataclass_fields__
    unknown = set(d) - set(fields)
    if unknown:
        raise ValueError(f"{where}: unknown settings {', '.join(sorted(unknown))}")
    missing = [n for n, f in fields.items() if n not in d and n not in extra and f.default is MISSING and f.default_factory is MISSING]
    if missing:
        raise ValueError(f"{where}: missing {', '.join(missing)}")
    for k, v in d.items():
        t = fields[k].type
        t = {"str": str, "int": int, "float": float, "bool": bool, "list": list, "dict": dict}.get(t, t)
        ok = isinstance(v, (int, float)) and not isinstance(v, bool) if t is float else isinstance(v, t) if isinstance(t, type) else True
        if not ok:
            kind = {str: "text in quotes", int: "a whole number", float: "a number", bool: "true or false", list: "a list", dict: "a table"}
            raise ValueError(f"{where}: {k} must be {kind.get(t, t.__name__)}, not {v!r}")
    return cls(**d, **extra)


def explain(e):
    """An OSError in words: 'host not found' rather than '[Errno -2] Name or service not known'."""
    if isinstance(e, socket.gaierror):
        return "host not found (not in DNS or the hosts file)"
    if isinstance(e, ConnectionRefusedError):
        return "connection refused (nothing is listening on that port)"
    if isinstance(e, TimeoutError):
        return "no answer (timed out; is a firewall dropping it?)"
    if isinstance(e, ConnectionResetError):
        return "the connection was reset by the other side"
    if isinstance(e, OSError) and e.strerror:
        return f"{e.strerror}: {e.filename}" if e.filename else e.strerror
    return str(e)


def content_length(headers):
    """An HTTP request's body length, or None unless the header is a plain non-negative number (int() would accept "-1",
    and reading -1 bytes reads until the client stops sending)."""
    v = headers.get("Content-Length") or "0"
    return int(v) if v.isascii() and v.isdigit() else None
