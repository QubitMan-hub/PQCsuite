"""Moved to Acxelin VPN (acxelin_vpn). These names work until Stage 6."""
import importlib
import sys

import acxelin_vpn as _moved

globals().update({k: v for k, v in vars(_moved).items() if not k.startswith("__")})
for _name in ("app", "charon", "controller", "desktop", "join", "platforms", "wireguard"):
    sys.modules[f"{__name__}.{_name}"] = importlib.import_module(f"acxelin_vpn.{_name}")
