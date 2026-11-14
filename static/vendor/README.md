# vendor/

Third-party browser libraries live here as plain files, downloaded once and
served by this app.

Nothing in this project is compiled, bundled, or transpiled, and nothing is
fetched from a CDN at runtime. Two reasons that is worth the small hassle of
downloading a file:

- **The page keeps working.** A CDN outage, a DNS block, or a corporate proxy
  cannot take a self-hosted file away, and the version cannot change under you
  because someone re-tagged a release.
- **The Content-Security-Policy stays tight.** `server/middleware` sets
  `script-src 'self'`, so a `<script src="https://cdn...">` is refused by the
  browser. That is the policy working, not a bug -- vendor the file instead of
  loosening it.

Add one with the helper, which downloads the file and prints the tag to paste:

```bash
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/htmx.org/2.0.4/htmx.min.js
```

Then reference it from your HTML:

```html
<script src="/vendor/htmx.min.js"></script>
```

Commit what lands here. It is part of the app, not a build artifact.

## What is here

| File | From |
|---|---|
| `bootstrap.min.css`, `bootstrap.bundle.min.js` | Bootstrap 5.3.8 (the bundle includes Popper) |
| `bootstrap-icons.min.css`, `fonts/bootstrap-icons.woff2`, `fonts/bootstrap-icons.woff` | Bootstrap Icons 1.13.1 |
| `qrcode.js` | qrcode-generator 1.4.4 (MIT), for the two-factor setup screen |
| `jsoneditor/` | vanilla-jsoneditor 3.13.0 (ISC), the Documents JSON editor: tree, text and table views. The standalone ES module (every dependency inside) with its stylesheet lifted out into `jsoneditor.css`. Made by `misc/vendor_jsoneditor.sh`, not `misc/vendor.sh` |

The icon stylesheet loads its font from `fonts/` next to it, so keep that
layout. To upgrade, delete these files and fetch the new version:

```bash
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.8/css/bootstrap.min.css
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.8/js/bootstrap.bundle.min.js
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.13.1/font/bootstrap-icons.min.css
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.13.1/font/fonts/bootstrap-icons.woff2 fonts/bootstrap-icons.woff2
misc/vendor.sh https://cdnjs.cloudflare.com/ajax/libs/bootstrap-icons/1.13.1/font/fonts/bootstrap-icons.woff fonts/bootstrap-icons.woff
misc/vendor.sh https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.js qrcode.js
```
| `sodium.js` | libsodium.js 0.8.4 (ISC), the sumo browser build with its WebAssembly copy removed, for the Documents screen. Made by `misc/vendor_sodium.sh`, not `misc/vendor.sh` |

### sodium.js: plain JavaScript, no WebAssembly

libsodium.js's browser bundle holds libsodium twice: as WebAssembly (one base64
string) and as plain JavaScript ("wasm2js"), which it falls back to when
WebAssembly is unavailable. This app never uses WebAssembly -- the CSP has no
`'wasm-unsafe-eval'` -- so `misc/vendor_sodium.sh` cuts the WebAssembly string
out (about 380 KB) and changes nothing else, and `static/js/docs_crypto.js`
tells the loader to go straight to the plain-JS copy. The sumo build is needed
for `crypto_pwhash` (Argon2id), which unlocks with a passphrase. To upgrade:

```bash
rm static/vendor/sodium.js
misc/vendor_sodium.sh 0.8.4
```

### jsoneditor/: the stylesheet taken out of the script

vanilla-jsoneditor's standalone bundle adds its CSS to the page as `<style>`
elements when it loads, which `style-src 'self'` refuses. `misc/vendor_jsoneditor.sh`
downloads the package from the npm registry, checks it against the registry's
sha512, moves every one of those stylesheets into `jsoneditor/jsoneditor.css`
and switches the two injections off; nothing else in the script changes. Its
colours are `--jse-*` variables, which `css/style.css` points at Bootstrap's
and the theme's. The editor's JavaScript and Lodash transform languages use
`new Function()`, which `script-src 'self'` refuses, so `js/docs.js` offers
JSONQuery, JSONPath and JMESPath only. To upgrade:

```bash
rm -r static/vendor/jsoneditor
misc/vendor_jsoneditor.sh 3.13.0
```
