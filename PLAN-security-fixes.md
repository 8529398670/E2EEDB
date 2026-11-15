# Plan: E2EEDB security fixes, round 3

Written 2026-11-15, from the third security review. Rounds 1 (E0-E4) and
2 (F1-F14) are done (cards 489-493 and 643-656 on the board; round 1's
plan is in git history). This plan covers only
E2EEDB's own code: the document store, collection keys, access keys and the
browser's Documents screen.

The web-app findings are in the go-webserver template. They are S9-S17 in
`~/.claude/skills/PLAN-security-fixes.md` and reach E2EEDB through
`webserver-upgrade`, as step G0 below. Do not patch them here by hand, or
E2EEDB drifts from the template.

Rules: all work goes on `master`. Commits and pushes are left to
`gitPushUpdate.sh`. Each step is a card on the TodoBoard board `e2eedb`.
Nothing is live, so formats and schemas change in place: no compat code, and
dev data in `~/.config/e2eedb/` can be wiped.

The probes that confirmed these are in the session scratchpad and may be
gone. Each step says what its regression test has to show, so rebuild the
probe as that test.

## G0: take the template security update (S9-S17)

This step depends on phase 1 of the skills plan. Then run `webserver-upgrade`
on E2EEDB, take the security entry, and run `go test ./...`.

S9 matters most here. Today a full-role API key can mint its own unlimited
login link, redeem it, and read `/api/keyring`, which the README says no key
reaches. Until G0 lands:

- hand out no full-role API keys you would not hand the passphrase to;
- revoke any key you suspect. Revoking ends the sessions its links made.

## G1 (high): a dishonest server can undo a key rotation

**Confirmed.** The probe reproduced it in Go and in the browser.

1. The owner revokes a token and rotates the collection. The commit succeeds.
2. The server later serves the old `lock` again. It is still validly signed
   by its holder and still carries a valid `own` tag.
3. Any client that opens it from scratch accepts it: a fresh Go client, the
   browser after a reload, or the rotating client after its final `forget()`.

From then on the client accepts documents forged with the revoked write key,
and it seals new writes under the old read key, which the revoked holder can
read. The server can also serve old `lock` plus new `next_lock` forever, so
clients think the rotation is still running and keep accepting old-key
envelopes.

Code: `client/keys.go` (`resolve`, `resolveNext`, `openingKey`) and
`static/js/docs.js` (`keyFor`, `nextKeyFor`, `openingKey`).

Fix:

1. **Epoch.** Every lockbox gets an `epoch`, a counter that starts at 1 and
   that the `sig` covers. A rotation's `next_lock` carries `epoch + 1`.
   Change the signed message in README "Lockboxes", both clients and
   `client/testdata/vectors.json` together.
2. **High-water mark.** Each client remembers the highest epoch it has seen
   for each collection and refuses a lockbox below it (`ErrRolledBack`). When
   it sees a `next_lock`, it records the epoch and does not go back to below
   it.
   - Go: an optional `client.WithState(path)` file, written atomically, mode
     0600. Without one, a single process still keeps the mark in memory
     across `forget()`.
   - Browser: IndexedDB keyed by account and collection. Wipe it on "Forget
     this device".
3. **README.** Rewrite "Rotate keys..." and "Known limits". A client that
   has seen the rotation can no longer be rolled back. A client with no memory
   (a new device, cleared storage, a Go client without `WithState`) still can,
   just as with document rollback.
4. Tests: `TestRotationRollbackRefused` (Go) and the same case in
   `scripts/check_crypto.js`. Each serves the pre-rotation lock after a
   commit and must get `ErrRolledBack`, including after `forget()`.

## G2 (high): a server can make the owner's client mint keys a sharee opens

**Confirmed.** The probe reproduced it in Go and in the browser.

The server reports one of the owner's folders, say `diary`, as sitting under
a shared folder S and with no lockbox. A folder with a parent and no lockbox
gets new keys wrapped for whatever parent the server names. Here that is S,
so every holder of S's token opens them:

- **Go `Set` gets around `ErrSharedCollection`.** `CreateCollection` tags a
  child as owned whatever its parent's status, so `Set` writes owner data for
  the sharee. Code: `client/keys.go:164-176` and `client/client.go:409-420`.
- **Sharing leaks private envelopes.** `PrepareShare` (`client/keys.go:321`)
  and `prepareShare` (`docs.js`) give `diary` keys under S and re-seal its
  private envelopes under them.
- **The browser writes for the sharee.** A new document in `diary` is sealed
  for the sharee. The folder is marked "made by share" only after that.

Fix:

1. **No silent minting.** Never mint keys for a folder with a parent and no
   lockbox unless the caller asks:
   - Go: refuse with `ErrSharedCollection` unless `AllowShared()` is passed;
   - browser: a confirm dialog that names the parent.
2. **Owned means owned all the way down.** A folder counts as owned only if
   every lockbox from the top level down to it carries a valid `own`. A new
   child gets `own` only when its holder is the master key or an owned
   folder. Apply this in `CreateCollection`, `resolve`, `keyFor` and
   `madeByShare`.
3. **Sharing.** `PrepareShare` and `prepareShare` refuse a subtree that
   contains a folder with no lockbox and private envelopes. The error names
   the folder.
4. **Ownership per key, not per collection.** Record it on each set of keys,
   so a flag read from `lock` never vouches for keys read from `next_lock`
   (`client/keys.go:54`, `:96`).
5. Tests:
   - Go: a server that moves `diary` under S with `lock` cleared must make
     `Set`, `CreateCollection{Parent}` and `PrepareShare` all refuse.
   - Browser: the same case in `scripts/check_crypto.js`.

## G3 (medium): deleting a big folder blocks every account's writes

**Confirmed.** Deleting 100k documents held SQLite's only write lock for
9 seconds and returned a 12.4 MB reply. Another account's write failed with
`SQLITE_BUSY` (500). A read-write access key can do this to its own
subfolder. A 1 GiB quota holds about 8.8M small envelopes.

Code: `server/docstore/collections.go:279-316` and
`server/routes/docs.go:537-567`.

Fix:

1. Tombstone with one `UPDATE … WHERE user_id = ? AND collection IN
   (subtree)`, not one row at a time.
2. Reply with counts only. The change feed already lists the tombstones.
3. Cap the live documents one delete removes (`docs.max_delete_docs`, default
   50k). Past that, return `413 delete_too_large` and let the client delete
   the documents in pages first. The browser and Go client do that
   automatically.
4. Test: deleting a 20k-document folder replies in under 1 s, and a
   concurrent write from another account succeeds.

## G4 (medium): tombstones let an account grow without limit, and writes slow with it

**Confirmed.**

- Every write runs `SUM(size)` over the whole account, plus the recursive
  share-quota query, under the write lock (`server/docstore/docs.go:191-212`).
  One write took 0.7 ms at 1k rows and 47 ms at 100k rows.
- Tombstones count 0 bytes (`docs.go:249`). 2000 write+delete cycles under
  a 1 KiB quota left 2000 rows with `used=0`.

Fix:

1. Keep running byte totals per account and per collection in a
   `usage` table, updated inside `setTx` and `deleteTx` and on moves. The
   quota check becomes one row read. The share quota sums at most
   `share_max_collections` rows.
2. Count a tombstone as a fixed 128 bytes until it is purged.
3. `docs.max_tombstones` per account (default 100k). Past it, deletes still
   work and the sweep purges the oldest tombstones early. Clients that synced
   before the oldest purged tombstone get `410 sync_expired`, as today.
4. `scopedCollections` (`server/routes/docs.go:344`) reads the totals
   instead of aggregating per 1000 folders.
5. Test: write time at 100k rows is within 2x of 1k rows, and tombstones
   count toward the quota.

## G5 (low): read-only lookups take the write lock

**Confirmed.** `Subtree` (`server/docstore/collections.go:533`) and
`InRotation` (`server/docstore/rotate.go:131`) call `db.Begin()`. With
`_txlock=immediate`, that queues them behind every writer, so each scoped
`GET /api/collections` competes with writes.

Fix: open a second read-only handle for reads (`mode=ro`, deferred
transactions) and use it for every lookup that does not write. Work the
subtree out in one recursive SQL query. Test: `Subtree` returns while a
write transaction is open.

## G6 (low): a rotation can leave access keys alive

**Found by reading the code.** Keys are revoked only on the stage call that
starts the rotation, after the commit and outside the transaction
(`server/routes/docs.go:625-636`). Two gaps:

- a partial `RevokeScopedKeys` failure is never retried;
- a key minted between the `InRotation` check (`server/routes/api_keys.go:331`)
  and the insert survives.

A surviving key keeps write and delete on the rotated subtree.

Fix: when a rotation starts, give every collection in the subtree a new
`born`, inside the same transaction. The existing `born` check (E2) then cuts
off every old scoped key whether or not revocation ran. Still revoke them, so
the keys list says so, and revoke again at commit. Test: a key minted with
the old `born` gets 404 after the rotation starts, even with revocation
stubbed out.

## G7 (low): a malformed lockbox wedges a rotation and turns off `stale_key`

**Confirmed.** Staging `next_lock: "not json"` was accepted. After that:

- re-staging gave `409 lock_exists`;
- commit always gave `409 rotate_incomplete`;
- moves gave `409 rotating`;
- writes sealed with any key id were accepted.

A write-scoped key can do the same with `lock` on folders it makes, which
turns `stale_key` off for them.

Code: `server/docstore/rotate.go:68-78`, `:118-126`, `:188-193` and
`:247-250`.

Fix:

1. On create, give-keys, move and stage, the server parses `lock` and
   `next_lock`. It refuses (`400 bad_lock`) unless the box is JSON with a
   16-byte `key_id`, a `parent` equal to the real parent, and the fields the
   format needs.
2. Re-staging the same collection replaces its `next_lock` while the
   rotation is open.
3. Add `POST /api/collections/{R}/rotate/abort`, for a full key only. It
   drops every `next_lock` in the subtree. It is refused once any
   collection envelope names a new key id, because those documents would no
   longer open; finish the rotation instead.
4. Tests: a bad lockbox is refused on every route, and a rotation can be
   aborted before any document is resealed.

## G8 (low): the id-squatting fix checks an id's shape, not that it is random

**Confirmed.** A scoped key created the folder `customer_invoices_2025`,
which happens to be 22 characters of `[A-Za-z0-9_-]`. The owner tag still
stops the owner's own writes going in, so this is defense in depth.

Code: `server/routes/docs.go:453` and `server/docstore/docs.go:39`.

Fix: a scoped key's create ignores the id it sends, and the server uses
`newCollectionID()`. Undo needs the old id back, so the server allows a
scoped key to reuse an id only when that id's last instance was in this key's
scope, recorded at delete time. Test: the create above gets a random id.

## G9 (low): a move can swap a folder's lockbox for one with different keys

**Confirmed.** A write-scoped key moved the owner's folder `A` from `p1` to
`p2` and back, each time with a lockbox that names new keys. Both moves were
accepted and `by_key` stayed empty. The client catches this through the
owner tag, but A's real keys are gone, so its subfolders no longer open.

Code: `server/docstore/collections.go:243-253`.

Fix: on a move, the new lockbox's `key_id` must equal the current one
(`409 lock_mismatch`). A move re-wraps the same keys and never swaps them.
Test: the swap above is refused.

## G10 (decide): a rotation re-signs forgeries planted before its reseal pass

**Found by reading the code.** Between the revoke and the reseal, the server
and the revoked holder can plant documents signed with the old write key. The
reseal (`client/rotate.go:151-194`, `docs.js:1270-1294`) opens them and signs
them again with the new key. A legitimate sharee write looks the same, so
this is partly inherent.

Recommended: the reseal pass lists every document changed after the access
key's last legitimate use, or after the revoke when that is not known. The
browser shows that list before the commit, and Go returns it in the
`Rotation` result. Nothing is dropped automatically.

## G11 (low): a parent cycle hangs the browser tab

**Found by reading the code.** If a server reports A in B in A, opening
`/docs/A/x` never returns. `reveal()` (`static/js/docs_tree.js:134`) walks up
the parents with no step limit, and `subtree()` (`:102`) recurses without one.

Fix: cap both walks at `max_depth + 1`, as `path()` already does, and show
the folder as broken. Test: in `scripts/check_crypto.js` or a small node
check of `docs_tree.js`.

## G12 (info): small hardening

1. **Ids on the client.** Both clients check collection and document ids
   against the server's pattern before using them in AD or a path. A NUL
   would make `c || 0 || id` ambiguous, and the browser decodes `%00` from
   `/docs/…` links.
2. **No dots in document ids.** Cloudflare caches `…/docs/notes.pdf` by file
   extension unless a rule says otherwise. S11 adds `no-store`; also drop `.`
   from the id pattern (`server/docstore/docs.go:31`) so the default behaviour
   is safe too.
3. **Versions survive a purge.** A document recreated after its tombstone is
   purged starts again at version 1, so a stale client's `if_version` can
   match a different document. Keep a per-account high-water version per id,
   or make new versions start at the account's change number.
4. **`too_deep` oracle.** The error tells a scoped key how deep its shared
   folder sits. Return `too_deep` with `max_depth` relative to the shared
   root.
5. **Generated key left in the page.** A generated master key stays in
   `docs-new-key-value` until "Use" is pressed. `lock()` clears it
   (`static/js/docs.js:504`, `:516-529`).
6. **Account sweep.** `owners()` (`server/docstore/sweep.go:60`) also sweeps
   `counters` and `trees` rows of deleted accounts.

## G13: document the Cloudflare deployment

Add "Deploying behind Cloudflare" to README.md:

- **Tunnel is the recommended way in.** With cloudflared on the same host,
  the config is:

  ```yaml
  server:
    host: 127.0.0.1
    public_url: https://db.example.com
    secure_cookies: true
    trust_proxy: true
    trusted_proxies: [127.0.0.1, "::1"]
    proxy_header: CF-Connecting-IP
  ```

  With Docker, trust the exact gateway (for example `172.17.0.1`), not
  `172.16.0.0/12`. Check in Logs that real visitor IPs show up.
- **Without a Tunnel.** Use Full (strict) TLS with an Origin CA certificate,
  Authenticated Origin Pulls, and a firewall that allows only Cloudflare's
  ranges. Never use Flexible: the page's JavaScript holds the keys, and it
  would cross the internet unencrypted.
- **Dashboard settings.**
  - Add a Cache Rule that bypasses the whole hostname, and turn on Cache
    Deception Armor.
  - Turn off Rocket Loader, Email Obfuscation and automatic analytics
    injection: they rewrite or inject script.
  - Add a rate-limit rule on `POST /api/login*`.
  - Keep challenges off `/api/*`.
  - Leave Cloudflare's HSTS off, since the app sends its own.
- **Known limits.** Cloudflare can change the page it serves, so in the
  browser it is now trusted the same way the server is. Only the Go client is
  safe from that.

## Order

1. **First, because they break the end-to-end promise:** G2, then G1. Change
   the Go client, the browser and the vectors together for each.
2. **Skills phase 1, then G0:** S9 is the urgent one.
3. **Server load and correctness:** G3, G4, G5, then G7, G6, G8, G9.
4. **The rest:** G11, G12, G10 and G13.

After each step, run `go test ./...`. After the crypto and browser steps,
also check by eye in the Documents screen: sharing, opening an access key,
moving folders and rotating keys.
