import json
import os
import re

import logging

from acxelin_core.http import ConfigWatch as _ConfigWatch
from acxelin_core.config import build, env_passphrase, read_text, read_toml  # noqa: F401  (the suite's names until Stage 6)
from acxelin_core.http import HTTP_IDLE, JSON, METRICS, PEM, content_length, explain, file_stamp, restart, serve_http  # noqa: F401

NAME = "pqcsuite"


class ConfigWatch(_ConfigWatch):
    """Core's watcher, logging to the suite's logger as before (until Stage 6)."""
    def __init__(self, *args, log=None, **kwargs):
        super().__init__(*args, log=log or logging.getLogger(NAME), **kwargs)
__version__ = "0.4.3"
RELEASES = "https://api.github.com/repos/QubitMan-hub/PQCsuite/releases?per_page=50"

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem  # noqa: F401
except ImportError:
    import cryptography
    raise ImportError(f"pqcsuite needs cryptography 49 or newer for ML-KEM and ML-DSA, and this Python has {cryptography.__version__}: "
                      "pip install --upgrade 'cryptography>=49'") from None
























def latest_release(url=None, timeout=10):
    """The newest published suite release (tags vX.Y.Z; Wolf Pack's are skipped) from GitHub, or from PQCSUITE_RELEASES_URL (a
    mirror inside your network). None when there is none. Nothing calls this unless asked to."""
    import http.client
    import urllib.request
    url = url or os.environ.get("PQCSUITE_RELEASES_URL") or RELEASES
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"the releases address must start with http:// or https://, not {url!r}")
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            data = json.loads(r.read(5 << 20))
    except http.client.HTTPException as e:
        raise OSError(f"the releases address did not answer in HTTP: {e!r}") from None
    if not isinstance(data, list):
        raise ValueError("the releases address did not return a list of releases")
    found = [(tuple(map(int, m.groups())), r) for r in data if isinstance(r, dict) and not r.get("draft") and not r.get("prerelease")
             and (m := re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", str(r.get("tag_name", ""))))]
    if not found:
        return None
    v, r = max(found, key=lambda x: x[0])
    return {"version": ".".join(map(str, v)), "url": r.get("html_url", ""), "newer": v > tuple(map(int, __version__.split(".")))}
