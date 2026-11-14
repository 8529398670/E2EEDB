#!/usr/bin/env bash
# Vendor libsodium.js (sumo: it has crypto_pwhash / Argon2id) as a plain-JS
# build with no WebAssembly in it, into static/vendor/sodium.js.
#
# libsodium.js's browser bundle carries two copies of libsodium: a WebAssembly
# module (as one base64 string) and a plain-JavaScript "wasm2js" backup that it
# falls back to when WebAssembly is unavailable. This app's CSP is script-src
# 'self' with no 'wasm-unsafe-eval', so it never compiles WebAssembly: the
# WebAssembly string is cut out here (that is the only change made to the
# file), and static/js/docs_crypto.js tells the loader to go straight to the
# plain-JS module. See static/vendor/README.md.
#
# Usage: misc/vendor_sodium.sh [version]     (default 0.8.4)
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."

VERSION="${1:-0.8.4}"
DESTINATION="static/vendor/sodium.js"
FULL="static/vendor/sodium-full.js"
if [ -e "$DESTINATION" ]; then
  echo "Refusing to overwrite existing $DESTINATION -- delete it first to upgrade." >&2
  exit 1
fi
rm -f "$FULL"
misc/vendor.sh "https://raw.githubusercontent.com/jedisct1/libsodium.js/${VERSION}/dist/browsers-sumo/sodium.js" sodium-full.js >/dev/null
python3 - "$FULL" "$DESTINATION" <<'PY'
import re, sys
source, destination = sys.argv[1], sys.argv[2]
text = open(source).read()
# The WebAssembly binary is the one string literal holding base64 of "\0asm".
found = list(re.finditer(r'"AGFzbQ[A-Za-z0-9+/=]*"', text))
if len(found) != 1 or "useBackupModule" not in text or "isWasm2js" not in text:
    sys.exit("this libsodium.js build does not have the expected shape (one WebAssembly string and a wasm2js backup); look at it by hand")
stripped = text[:found[0].start()] + '""' + text[found[0].end():]
open(destination, "w").write(stripped)
print(f"removed {found[0].end() - found[0].start()} bytes of WebAssembly; {len(stripped)} bytes left")
PY
rm -f "$FULL"
echo "Saved $DESTINATION (libsodium.js ${VERSION}, sumo, plain JS only)"
echo "sha256: $( shasum -a 256 "$DESTINATION" | cut -d' ' -f1 )"
