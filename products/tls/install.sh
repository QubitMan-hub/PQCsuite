#!/bin/sh
# Install Acxelin for this user, on Linux or macOS:  sh install.sh        (remove it again:  sh install.sh --uninstall)
# Works offline from a release wheelhouse (the .whl files next to this script) or from a checkout of the repository.
set -eu
PRODUCT=tls
cmd="acxelin-$PRODUCT"
here=$(cd "$(dirname "$0")" && pwd)
home="${ACXELIN_PREFIX:-$HOME/.acxelin}/$PRODUCT"
bin="${ACXELIN_BIN:-$HOME/.local/bin}"

if [ "${1:-}" = "--uninstall" ]; then
  rm -rf "$home" "$bin/$cmd"
  echo "Removed $cmd. Your certificates, consoles and settings stay where you put them."
  exit 0
fi

py=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then py=$c; break; fi
done
[ -n "$py" ] || { echo "$cmd needs Python 3.11 or newer. Install it (python.org, or your package manager), then run this again." >&2; exit 1; }

echo "Installing $cmd into $home"
rm -rf "$home"
mkdir -p "$(dirname "$home")" "$bin"
"$py" -m venv "$home"
if ls "$here"/*.whl >/dev/null 2>&1; then
  echo "  from the wheels next to it (offline)"
  extra=$(cat "$here/extras" 2>/dev/null || true)  # the optional parts this folder carries, such as Readiness's crawler
  "$home/bin/python" -m pip install -q --no-index --find-links "$here" "$cmd$extra" 2>/dev/null \
    || "$home/bin/python" -m pip install -q --no-index --find-links "$here" "$cmd"  # without them where they have no wheel
elif [ -f "$here/pyproject.toml" ] && [ -d "$here/../../core" ]; then
  echo "  from this checkout"
  "$home/bin/python" -m pip install -q "$here/../../core" "$here"
else
  echo "Run this script from a release wheelhouse folder or from products/$PRODUCT in a checkout." >&2; exit 1
fi

# OpenSSL 3.5+ for post-quantum TLS: the system's when it is new enough, otherwise Homebrew's or the one you point at.
ssl="${ACXELIN_OPENSSL:-}"
if [ -z "$ssl" ] && ! openssl version 2>/dev/null | grep -qE "OpenSSL (3\.([5-9]|[1-9][0-9])|[4-9])"; then
  if command -v brew >/dev/null 2>&1 && [ -d "$(brew --prefix openssl@3 2>/dev/null)/lib" ]; then ssl="$(brew --prefix openssl@3)/lib"; fi
  [ -n "$ssl" ] || old_ssl=1
fi
{
  echo "#!/bin/sh"
  if [ -n "$ssl" ]; then
    echo "export ACXELIN_OPENSSL=\"\${ACXELIN_OPENSSL:-$ssl}\""
    echo "export LD_LIBRARY_PATH=\"$ssl\${LD_LIBRARY_PATH:+:\$LD_LIBRARY_PATH}\""
  fi
  echo "exec \"$home/bin/$cmd\" \"\$@\""
} > "$bin/$cmd"
chmod +x "$bin/$cmd"

echo
"$bin/$cmd" doctor || true
echo
"$bin/$cmd" 2>/dev/null | sed -n '/^Start here/,$p' || true
if [ -n "${old_ssl:-}" ]; then
  echo
  echo "Post-quantum TLS needs OpenSSL 3.5 or newer, which this machine does not have. Install OpenSSL 3.5+ (or use Debian 13 or"
  echo "Ubuntu 25.04+, or the container image), then run this installer again with its lib folder, so $cmd always finds it:"
  echo "  ACXELIN_OPENSSL=/path/to/openssl-3.5/lib sh $0"
fi
case ":$PATH:" in *":$bin:"*) ;; *) echo; echo "Add $bin to your PATH to run $cmd from anywhere:  export PATH=\"$bin:\$PATH\"";; esac
