"""Container images: a `docker save` or OCI archive is unpacked layer by layer, whiteouts applied, and scanned as a filesystem."""
import json
import shutil
import tarfile
from pathlib import Path, PurePosixPath

MAX_FILE = 64_000_000


def is_image(p):
    p = Path(p)
    if not p.is_file() or not tarfile.is_tarfile(p):
        return False
    with tarfile.open(p) as t:
        names = set(t.getnames())
    return "manifest.json" in names or "index.json" in names and "oci-layout" in names


def _json(outer, name):
    return json.load(outer.extractfile(name))


def layers(outer):
    """Layer member names, bottom first."""
    names = set(outer.getnames())
    if "manifest.json" in names:
        return _json(outer, "manifest.json")[0]["Layers"]
    blob = lambda d: "blobs/" + d.replace(":", "/")
    man = _json(outer, "index.json")
    while "manifests" in man:
        man = _json(outer, blob(man["manifests"][0]["digest"]))
    return [blob(x["digest"]) for x in man["layers"]]


def _parts(name):
    parts = [p for p in PurePosixPath(name).parts if p not in ("/", ".")]
    return None if not parts or ".." in parts else parts


def _remove(p):
    if p.is_dir() and not p.is_symlink():
        shutil.rmtree(p, ignore_errors=True)
    elif p.exists():
        p.unlink()


def apply(layer, dest):
    """Regular files and folders only: links, devices and oversized files are left out, so nothing can point outside `dest`."""
    for m in layer:
        parts = _parts(m.name)
        if not parts:
            continue
        where, base = dest.joinpath(*parts[:-1]), parts[-1]
        try:
            if base == ".wh..wh..opq":
                for c in where.iterdir() if where.is_dir() else ():
                    _remove(c)
            elif base.startswith(".wh."):
                _remove(where / base[4:])
            elif m.isdir():
                (where / base).mkdir(parents=True, exist_ok=True)
            elif m.isreg() and m.size <= MAX_FILE:
                where.mkdir(parents=True, exist_ok=True)
                with layer.extractfile(m) as src, open(where / base, "wb") as out:
                    shutil.copyfileobj(src, out)
        except OSError:
            continue


def unpack(archive, dest):
    """Returns notes on layers that could not be read (zstd compression, for one)."""
    notes, dest = [], Path(dest)
    with tarfile.open(archive) as outer:
        names = layers(outer)
        for name in names:
            try:
                with tarfile.open(fileobj=outer.extractfile(name), mode="r:*") as layer:
                    apply(layer, dest)
            except (tarfile.TarError, KeyError, OSError) as e:
                notes.append(f"layer {name} not read: {e}")
    return [f"container image {Path(archive).name}: {len(names)} layer(s) unpacked and scanned as one filesystem"] + notes
