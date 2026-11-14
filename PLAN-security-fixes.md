# Plan: E2EEDB security fixes

Written 2026-11-13, from a security review. This plan covers only problems in
E2EEDB's own code: the document store, collection keys and access keys.

The web-app problems are in the go-webserver template. They are covered by
`~/.claude/skills/PLAN-security-fixes.md` and reach E2EEDB through
`webserver-upgrade`, as step E0 below. Do not patch them here by hand, or
E2EEDB drifts from the template:

- an admin can sign in as the owner (S1);
- Settings can make `static_dir` serve secrets (S2);
- the 2FA lockout race, the world-readable `.run/server.log`, and log
  redaction case (S4-S6).

Rules: all work goes on `master`. Commits and pushes are left to
`gitPushUpdate.sh`. Track each step as a card on the TodoBoard board
`e2eedb`.

## E0: take the template security update

This step depends on phase 1 of the skills plan. Once that is committed, run
`webserver-upgrade` on E2EEDB and take the security entry. E2EEDB has no MCP,
so the MCP part of S1 does not apply. Run `go test ./...`.

Until then, there are two stopgaps:

- make no other account an admin;
- `chmod 600 .run/server.log`.

## E1 (high): a sharee can capture documents through collection-id squatting

**Confirmed.** A probe against the real routes showed a sharee reading the
owner's "TOP SECRET" document.

Here is how it happens:

1. A scoped read-write key creates a collection with an id it chooses (for
   example `invoices`) inside its shared folder.
2. Later, a service owned by the account calls `Set(ctx, "invoices", ...)`.
3. `client.resolve` finds the existing `invoices` collection under the shared
   folder and seals with its keys, which the sharee made.

Fix:

1. **Server.** In `CreateCollection` (`server/routes/docs.go`), when the
   caller holds a scoped key, ignore any client-chosen `id` and always use
   `newCollectionID()`. Record which key created the collection, in a new
   `created_by_key` column with a migration.
2. **Client, defense in depth.** In `client.resolve` and the browser's
   equivalent, a write that auto-creates a collection never adopts a
   collection created by a scoped key. When a full-key client resolves a
   target like that, it refuses with a clear error unless the caller passes
   an explicit option (`client.InShared()`).
3. **Already-stored data.** Add a one-off `manage` report that lists
   collections inside a shared subtree whose id is not random-looking, along
   with their creator where known. Run it once on the live database.
4. **README.** Under "Known limits", say that a sharee with write access can
   create folders inside the shared one, and that only random ids are used
   for them.
5. **Tests.** Port the probe into `scoped_test.go` as a regression test. The
   scoped create gets a random id, and the owner's `Set("invoices")` makes a
   fresh top-level collection.

## E2 (medium): deleting a shared folder does not revoke its access key

**Confirmed.** After `shared` was deleted and recreated by id, the old scoped
key listed the new folder's documents. It cannot decrypt them, but it sees
document ids, sizes and the plaintext names of sub-folders.

Fix:

1. Inside the same `DeleteCollection` flow, revoke every API key whose
   `Scope.Collection` is in the deleted set. Log an audit entry for each one.
2. Bind a scope to the collection instance, not only its id. Store the
   collection's creation sequence number in `KeyScope` when the key is
   minted, and have `checkScope` refuse when it no longer matches. This also
   covers keys minted before the fix.
3. Have the account-deletion sweep (`server/jobs/docs.go`) revoke scoped keys
   too.
4. Tests:
   - Delete and recreate, then the old key gets 404 or 401.
   - The key shows as revoked in the API keys list.

## E3 (medium): a read-only key can help a dishonest server forge sub-folder keys

**Found by reading the code, not run.** A sub-folder's lockbox read half is
wrapped only by the parent's read key. A read-only holder working with the
server can therefore plant a sub-folder lockbox that carries its own signing
key. Other read-only holders then accept documents forged with that key.
Holders of the master key or a write key are safe, because they also open the
write half and reject the lockbox.

Fix: signed lockboxes (done; README.md, "Crypto format", "Lockboxes").

1. Every lockbox carries `sig`, Ed25519 by the holder over
   `"e2eedb/lock/sign" || 0 || c || 0 || parent || 0 || key_id || nonce_r || read || nonce_w || write`.
   - For a sub-folder, the holder's key is the parent's `ws`, checked with the
     parent's `vk`.
   - For a top-level folder, the master key derives a signing seed:
     `BLAKE2b-256(key = M, "e2eedb/lock/sign-seed")`.
2. Every reader verifies `sig` before trusting the read half. A lockbox
   without a valid one opens for nobody.
3. The server sets a lockbox once (`409 lock_exists`) and replaces it only
   with a move.
4. The Go client (`client/crypto_collection.go`) and the browser
   (`static/js/docs_crypto.js`) change together. `client/testdata/vectors.json`
   pins them, and `scripts/check_crypto.js` holds the browser to them.
5. Tests: `TestForgedChildLockbox` (`client/crypto_test.go`) and the forged
   lockbox check in `scripts/check_crypto.js`. Both build a sub-folder
   lockbox from a read-only key, which must be refused.

## E4 (low): the access-token view runs as the signed-in account

In a browser that is already signed in, opening an access key on the
signed-out page sends both the cookie and the scoped key. The cookie wins, so
the scoped view sees the whole account's metadata. Fixing this is S7 in the
skills plan, and it arrives with E0. After E0, check by eye that the access
view shows only the shared subtree while you are signed in.

## Order

E1 server part, then E2, then E0 (once the skills plan lands), then E1 client
part and the report, then E3, then E4. After each step, run `go test ./...`,
then check sharing, opening an access key, and moving folders by eye in the
Documents screen.
