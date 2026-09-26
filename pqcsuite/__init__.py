from dataclasses import MISSING

NAME = "pqcsuite"
__version__ = "0.1.0"


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
