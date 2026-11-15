# Plan: E2EEDB security fixes, round 4

Written 2026-11-15, from the fourth security review. Rounds 1-3 (E0-E4,
F1-F14, G0-G13) are done; their plans are in git history and their cards are
on the board. This plan covers E2EEDB's own code. The web-app findings are in
the go-webserver template: they are S18-S21 in
`~/.claude/skills/PLAN-security-fixes.md` and reach E2EEDB through
`webserver-upgrade` (step H0). Do not patch them here by hand.

Rules: all work goes on `master`. Commits and pushes are left to
`gitPushUpdate.sh`. Each step is a card on the TodoBoard board `e2eedb`.
Nothing is live, so formats change in place: no compat code.

The theme of this round: **a sharee can sabotage the rotation meant to cut
them off.** The owner revokes an access key and rotates the folder so the
old keys open nothing new. A read/write sharee who sees that coming can
plant something beforehand that makes the rotation fail, and then every new
document is still sealed under keys they hold.

## H0: no API key makes a login link in E2EEDB; take S19-S21

**Done** (card 680). Took S19-S21 through `webserver-upgrade` (2ad0dbf ->
bbf7241), leaving out the `may_sign_in` route, button and strings, and keeping
`POST /api/account/login-link` session-only. `reissue-login` is session-only
here. The keyring refuses a browser whose sign-in traces back to a key
(`Session.MintedByKey`, `403 key_made_session`), which closes the long way
round (key makes an admin account, that browser reissues someone's link).
Keyring reads are logged. Test: `TestNoKeyFindsAWayToTheKeyring`; the
template tests that reissue through a key were adapted. Checked in the browser.

Card 680. Keys making login links is a template option on purpose, and it
stays in the skills. E2EEDB turns it off for itself: a session here reads
`/api/keyring`, so a key that can sign in can take the keyring away to guess
the passphrase. Today `POST /api/admin/users/{id}/reissue-login` still takes
an admin-role key, including for its own account (confirmed: link, sign-in,
keyring 200, admin key minted).

1. In E2EEDB's own code, `reissue-login` takes a browser session only.
   Regression test: an admin-role key gets 403, for itself and for others.
2. When `webserver-upgrade` brings in `may_sign_in`, keep it off and
   unavailable here, and say so in E2EEDB's notes so no upgrade turns it on.
3. Take S19-S21 from the skills plan through `webserver-upgrade` once they
   are committed there, and run `go test ./...`.

Until then, hand out no admin-role keys you would not hand the passphrase to.

## H1 (medium-high): a sharee can stop the owner's rotation from starting

**Done** (card 681). Server `bad_lock` past 2^32 s ahead; both clients give
a folder whose lock does not open new keys (`Rotation.Broken`). Checked in
the browser with a copied lockbox planted through a real access key.

**Confirmed** (Go; the browser code is the same). A read/write access key can
make folders inside the shared one and give them lockboxes. The server checks
a lockbox's shape, not its signature. Two ways to plant one:

1. a lockbox with epoch `2^53 - 1`, validly signed with the shared folder's
   write key: the rotation cannot give that folder an epoch one higher
   (`... is at the last epoch`);
2. a sibling folder's lockbox copied as is onto another folder: well formed,
   but signed for the sibling (`lockbox signature`).

Either way `RotateKeys` and the browser's `rotateKeys` stop before staging
anything, so the rotation never starts and the shared folder keeps the keys
the revoked sharee holds.

Fix:

1. The server refuses a lockbox whose epoch is more than 2^32 seconds after
   its own clock (`400 bad_lock`). Clients make fresh epochs from the time,
   plus one per rotation, so honest lockboxes never get near it.
2. A rotation gives fresh keys to a folder in the subtree whose `lock` does
   not open (a bad signature or a damaged box), as if it had none: wrapped
   for its parent's new keys, owner tag only if the old lock carried a valid
   one. A lock refused as rolled back still stops the rotation, as does any
   other error.
3. Tests: both plants above, then `RotateKeys` succeeds and the planted folder
   ends with new keys. The same case for the browser in
   `scripts/check_crypto.js` where it can be driven there.

## H2 (medium): one bad document stalls a rotation half way

**Done** (card 682). Both clients delete what no key opens
(`Rotation.Dropped`, a warning toast in the browser). Checked in the browser.

**Confirmed.** A write sharee writes a document whose header names the
folder's current key id but whose signature is broken (the server checks only
the key id). The reseal pass cannot open it, so it stops with
`ciphertext is damaged`, without naming the document. The rotation stays
half done: the subtree cannot have folders made, moved or shared (`409
rotating`) until the owner finds the document, and abort is refused once
anything was resealed.

Fix: the reseal pass deletes (with `if_version`) every collection envelope it
cannot open, since no reader accepts one, and reports them: `Rotation.Dropped`
in Go (`collection/id`), and a count in the browser's done message. A
document that names neither the old nor the new keys is dropped the same
way. Test: the planted document is gone after `RotateKeys`, listed in
`Dropped`, and the commit succeeds.

## H3 (medium-low): a write can slip past the scope check

**Done** (card 683). `Limits.Scope` / `DeleteOptions.Scope`, checked by
`inScopeTx` in every write. The probes now land 0 writes after the move and
0 deletes after the rotation start (8 and 7 before).

**Confirmed** by the server probe. `checkScope` and `checkScopeRoot`
(`server/routes/docs.go`) read the tree before the write's transaction
starts, and the write never checks again. With 24 writes in flight while the
owner moved folder X out of the shared one, 8 landed in X after the move.
With deletes in flight when a rotation started, 7 landed after it, though the
README says the rotation cuts the keys off at once.

Fix: pass the key's scope (`root`, `born`) to the store in `Limits`, and
check inside each write transaction that the root still exists with that
`born` and that the target (and a move's destination) is under it. Tests:
the two races above, run many times, land nothing after the move or the
rotation start.

## H4 (low): lockbox JSON reads differently in Go and in the browser

**Done** (card 684). Server, Go client and browser all refuse a name the
format does not have (the browser cannot see repeats, which read the same in
both anyway).

**Confirmed.** Go's `encoding/json` matches field names regardless of case,
and the last copy of a repeated name wins. `DisallowUnknownFields` lets
`{"key_id":"A","KEY_ID":"B"}` through, and the server reads `B` while the
browser reads `A`. So a write sharee can move a folder with a lockbox
that the server sees as re-wrapping the same keys (passing G9's
`lock_mismatch`) and that the browser sees as naming new ones, which
reopens G9 for the browser.

Fix: the server refuses a lockbox whose top-level names are not exactly the
format's, each once (`400 bad_lock`). The Go client refuses the same when it
opens one. Test: the duplicate-name and other-case boxes are refused.

## H5 (low): a scoped key can set the lockbox of its own root

**Done** (card 685).

**Confirmed.** For a root that had no lockbox when it was shared, `POST
/api/collections/{root}` with `lock` is accepted from its own access key.
The owner then cannot set the real one (`lock_exists`), and `bad_lock`
against 200 confirms a guess at the root's hidden parent.

Fix: refuse `lock` on the root for a scoped key, and refuse to mint a scoped
key for a collection with no lockbox (the share flow always gives keys
first). Tests: both refused.

## H6 (low): deleted-folder records grow without limit

**Done** (card 686). `usage.graves`, kept by triggers; capped in the sweep.

**Confirmed.** Each deleted folder leaves a grave row (for undo), up to about
1.5 KB, that no quota or cap counts. Only age clears them.

Fix: graves count against the quota like tombstones (128 bytes each), the
sweep keeps at most `docs.max_tombstones` per account (oldest go first), and
making an id again removes its grave. Test: past the cap, the oldest go.

## H7 (low): deleting a folder takes its tombstones out of the share's count

**Done** (card 687). `shareUsed` adds the graves under the share and their
tombstones. A new folder also needs 128 bytes of room (account and share),
since it leaves a grave: otherwise empty folders made and deleted would still
grow the account.

**Confirmed.** The share cap sums the folders still in the subtree. Writing
up to the cap and deleting the folder, ten times, charged the account ten
times the share cap in tombstones, bounded by `max_tombstones` × 128 bytes.

Fix: the share check also counts tombstones whose collection's grave lies
under the shared root, until they are purged. Test: the loop above stops at
the share cap.

## H8 (low): a hostile server can keep a client paging forever

**Done** (card 688), in Go only: a hostile server can send the browser any
script it likes, so the browser's paging is no extra risk.

**Found by reading the code.** Every paged read (`Each`, `Collections`, the
tree, `reseal`) takes the server's `next` as is. A
`next` that does not move forward loops forever, and `Collections` grows
without limit.

Fix: refuse a `next` that is not greater than the offset just asked for
(`ErrCorrupt`, `corrupt`). Test: a fake server that always answers `next: 0`.

## H9 (info): folder names may hold invisible and direction-changing characters

**Done** (card 689). Every format character (Cf) is refused but a ZWJ
between emoji parts, so tag characters are out too.

**Confirmed.** A sharee made `X​` beside the owner's `X`, and
`invoices‮fdp.exe`. Fix: refuse the bidi controls (U+061C, U+200E-F,
U+202A-E, U+2066-9) and the zero-width ones (U+200B, U+2060, U+FEFF) in
names. Keep U+200D (ZWJ), which emoji need. Test: refused.

## Order

H1 and H2 together (they share the rotation code in both clients), then H3,
H4, H5, H8, H9, H6, H7. H0 when the skills plan's round 3 is committed.
After each step, run `go test ./...`. After H1/H2, also check rotation by eye
in the Documents screen.
