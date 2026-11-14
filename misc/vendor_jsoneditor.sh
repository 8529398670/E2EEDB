#!/usr/bin/env bash
# Vendor vanilla-jsoneditor (the plain-JS build of svelte-jsoneditor) into
# static/vendor/jsoneditor/: jsoneditor.js (the standalone ES module, every
# dependency inside), jsoneditor.css, and its LICENSE.md.
#
# The standalone bundle puts its stylesheet in by adding <style> elements to
# the page: one per component, plus one for the color picker. This app's CSP
# is style-src 'self' with no 'unsafe-inline', so the browser refuses those.
# This script lifts that CSS out into jsoneditor.css, served as a real file,
# and turns the two injections off.
# CodeMirror 6 inside it (the text view) is pointed at constructed
# stylesheets, which style-src does not cover. Nothing else changes. See
# static/vendor/README.md.
#
# The tarball comes straight from the npm registry and is checked against the
# registry's sha512 before anything is unpacked.
#
# Usage: misc/vendor_jsoneditor.sh [version]     (default 3.13.0)
set -euo pipefail
cd "$( dirname "${BASH_SOURCE[0]}" )/.."

VERSION="${1:-3.13.0}"
DESTINATION="static/vendor/jsoneditor"
if [ -e "$DESTINATION" ]; then
  echo "Refusing to overwrite existing $DESTINATION -- delete it first to upgrade." >&2
  exit 1
fi

WORK="$( mktemp -d )"
trap 'rm -rf "$WORK"' EXIT

TARBALL="https://registry.npmjs.org/vanilla-jsoneditor/-/vanilla-jsoneditor-${VERSION}.tgz"
echo "Downloading $TARBALL"
curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/package.tgz" "$TARBALL"
curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/meta.json" "https://registry.npmjs.org/vanilla-jsoneditor/${VERSION}"

python3 -I - "$WORK/meta.json" "$WORK/package.tgz" <<'PY'
import base64, hashlib, json, sys
integrity = json.load( open( sys.argv[1] ) )["dist"]["integrity"]
algorithm, expected = integrity.split( "-" , 1 )
if algorithm != "sha512":
    sys.exit( f"unexpected integrity algorithm {algorithm}" )
actual = base64.b64encode( hashlib.sha512( open( sys.argv[2] , "rb" ).read() ).digest() ).decode()
if actual != expected:
    sys.exit( "tarball does not match the registry's sha512 -- not using it" )
print( "sha512 matches the registry" )
PY

mkdir -p "$WORK/unpacked"
tar -xzf "$WORK/package.tgz" -C "$WORK/unpacked" package/standalone.js package/LICENSE.md
mkdir -p "$DESTINATION"
cp "$WORK/unpacked/package/LICENSE.md" "$DESTINATION/LICENSE.md"

python3 -I - "$WORK/unpacked/package/standalone.js" "$DESTINATION/jsoneditor.js" "$DESTINATION/jsoneditor.css" "$VERSION" <<'PY'
import re, sys
source, script_out, css_out, version = sys.argv[1:5]
text = open( source ).read()

def literal( at ):
    """Reads the JS string literal starting at text[at]; answers (value, end)."""
    quote = text[at]
    if quote not in "\"'":
        raise ValueError( f"no string literal at {at}" )
    out , i = [] , at + 1
    simple = { "n": "\n" , "t": "\t" , "r": "\r" , "b": "\b" , "f": "\f" , "v": "\v" , "0": "\0" }
    while True:
        c = text[i]
        if c == quote:
            return "".join( out ) , i + 1
        if c == "\\":
            n = text[i + 1]
            if n in simple: out.append( simple[n] ); i += 2
            elif n == "x": out.append( chr( int( text[i + 2:i + 4] , 16 ) ) ); i += 4
            elif n == "u" and text[i + 2] == "{":
                close = text.index( "}" , i )
                out.append( chr( int( text[i + 3:close] , 16 ) ) ); i = close + 1
            elif n == "u": out.append( chr( int( text[i + 2:i + 6] , 16 ) ) ); i += 6
            elif n == "\n": i += 2
            else: out.append( n ); i += 2
        else:
            out.append( c ); i += 1

# 1. The style-inject helper every Svelte component calls with its CSS.
helpers = list( re.finditer( r'function ([\w$]+)\(e,t\)\{void 0===t&&\(t=\{\}\);var n=t\.insertAt;' , text ) )
if len( helpers ) != 1:
    sys.exit( "this build does not have the expected style-inject helper; look at it by hand" )
name = helpers[0].group( 1 )
sheets = []
for call in re.finditer( r'(?<![\w$.])' + re.escape( name ) + r'\((?=["\'])' , text ):
    css , end = literal( call.end() )
    if text[end] not in ",)":
        sys.exit( f"unexpected text after a {name}(...) call at {end}" )
    if css not in sheets:
        sheets.append( css )
if len( sheets ) < 10:
    sys.exit( f"found only {len( sheets )} stylesheets; look at the build by hand" )
text = text[:helpers[0].end()] + "return;" + text[helpers[0].end():]

# 2. The color picker's own <style>, made and appended when the module loads.
picker = re.search( r'([\w$]+)=document\.createElement\("style"\);\1\.textContent=' , text )
if not picker:
    sys.exit( "this build does not have the expected color picker stylesheet; look at it by hand" )
css , end = literal( picker.end() )
sheets.append( css )
append = "document.documentElement.firstElementChild.appendChild(" + picker.group( 1 ) + "),"
if text.count( append ) != 1:
    sys.exit( "the color picker's appendChild is not where it was expected; look at it by hand" )
text = text.replace( append , "" )

# 3. CodeMirror 6 (the text view) styles itself through style-mod, which uses
# a constructed stylesheet (document.adoptedStyleSheets, which style-src does
# not cover) only inside a shadow root, and a <style> element on a plain page.
# Dropping the "no <head>" test makes it take the constructed-stylesheet road
# on the page too; the <style> element stays as the road for browsers too old
# to have constructed stylesheets.
mod = "if(!e.head&&e.adoptedStyleSheets&&r.CSSStyleSheet)"
if text.count( mod ) != 1:
    sys.exit( "style-mod's stylesheet choice is not where it was expected; look at it by hand" )
text = text.replace( mod , "if(e.adoptedStyleSheets&&r.CSSStyleSheet)" )

# Three <style> elements are made in the bundle: the helper's (now off), the
# picker's (now never attached), and style-mod's fallback for browsers with
# no constructed stylesheets. Any other is new and needs a look.
if text.count( 'createElement("style")' ) != 3 or 'this.styleTag=n.createElement("style")' not in text:
    sys.exit( "this build makes <style> elements somewhere unexpected; look at it by hand" )

banner = f"/* vanilla-jsoneditor {version} (ISC, see LICENSE.md), lifted out of standalone.js by misc/vendor_jsoneditor.sh */\n"
open( script_out , "w" ).write( text )
open( css_out , "w" ).write( banner + "\n".join( sheets ) + "\n" )
print( f"{len( sheets )} stylesheets moved to {css_out}" )
PY

echo "Saved $DESTINATION/ (vanilla-jsoneditor ${VERSION})"
for f in jsoneditor.js jsoneditor.css; do
  echo "sha256 $f: $( shasum -a 256 "$DESTINATION/$f" | cut -d' ' -f1 )"
done
