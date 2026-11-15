# E2EEDB

A self-hosted, end-to-end encrypted document store that works like a minimal
Firestore: collections of JSON documents, versioned writes, and a change feed
for sync. The server never sees what is inside a document. Clients encrypt
with libsodium-compatible crypto under a key the server never holds, and the
server stores ciphertext plus the small amount of metadata it needs to find and
sync documents.

- **Services** use an API key and the JSON API, usually through the Go client
  in [`client/`](client/).
- **People** use the Documents screen in the browser. Documents are decrypted
  there with the same key, or with a passphrase that unlocks it.

Sharing documents between accounts, merging concurrent edits, and server-side
search are not in this version.

The web app around it (sign-in links, API keys, two-factor, logs, settings,
backups, Docker) comes from the go-webserver template; `config/api.md` lists
every route.

## What the server sees

| The server knows | The server never sees |
|---|---|
| which account a document belongs to | the document's contents |
| collection ids, and the folder tree: each collection's name, parent and order (plaintext, like Firestore) | the master key, or anything derived from it |
| document ids (chosen by the client; random by default) | the passphrase |
| size of each ciphertext, version, change number, when it changed | |
| a 16-byte key id per document (which key sealed it, not the key) | any collection's keys |
| the account's keyring: the master key sealed under the passphrase | |
| each collection's lockbox: its keys, sealed under its parent's keys or the master key (two, while its keys are being rotated) | |
| which API keys are scoped to which collection, read or write | |

Put nothing secret in collection names or document ids. `client.NewID()` gives
random ids.

## Collections and folders

Collections nest, like folders. Each one has an **id** and a **name**:

- The **id** is what documents are filed under (`/api/collections/{id}/docs/...`)
  and what each document's encryption is bound to. It never changes.
- The **name**, its **parent** and its place among its siblings can change at any
  time. Renaming, moving or reordering a collection touches none of its
  documents, so it needs no key, and a service that writes by id keeps working.
  Names are unique among siblings, ignoring case.

Writing a document into an id that has no collection yet makes one at the top
level, named after the id, so code that never thinks about folders keeps
working.

Moving a *document* to another collection does need the key: its ciphertext is
bound to where it is, so the client opens it and seals it again for the new
place, and the server swaps the two in one step
(`POST .../docs/{id}/move`, or `client.MoveDoc`). Deleting a collection deletes
every collection under it and every document in them, each leaving a tombstone
in the change feed. `docs.max_collections` and `docs.max_depth` cap how many
there are and how deep they nest.

In the browser, the Documents screen shows the tree: drag a collection to
reorder or nest it, drop documents on one to move them (press and hold first on
a touch screen), or use each one's menu for New, Rename, Move to and Delete.
Every change can be undone.

Known limits, by design:

- **Rollback and withholding.** A malicious server cannot read or forge a
  document, or move one to another collection or id: the ciphertext is bound
  to its place. It can still serve an older version it kept, or pretend a
  document does not exist. Version numbers are not authenticated.
- **A key rotation can be rolled back for a client with no memory.** Once a
  client has seen a rotation (see "Rotating keys"), it refuses the lockbox
  from before it. A client that never saw it cannot tell: a new device, a
  browser whose site data was cleared or that used **Forget this device**, or
  a Go client without `client.WithState`, which remembers only while the
  process runs. A dishonest server can hand such a client the old lockbox,
  whose keys a revoked access token still holds.
- **The keyring can be guessed against.** Anyone holding the database can try
  passphrases offline. Argon2id makes each guess expensive, but a weak
  passphrase is still weak. Use a long one, or never set one: services use the
  raw key and do not need a keyring.
- **One node.** `docs.db` is SQLite in WAL mode, written by one server process.
- **Sharing with write access lets someone add folders.** Whoever holds a
  read/write access key can make folders inside the shared one. They always
  get random ids, and the Go client refuses to write your own documents into
  them unless asked to. It knows them by the owner tag in each lockbox,
  which only your master key makes, not by anything the server says. The
  Documents screen marks them in the folder list once your key is unlocked.
  Making a folder with an id that is already taken is
  refused, so someone who already knows one of your folder ids can learn that
  it exists, even outside what you shared. Ids are random and never shown to
  them, so they would have to get it some other way. What a key adds is
  capped (`docs.share_quota_mb`, `docs.share_max_collections`), so it cannot
  use up your quota or folder limit. You can still add to a shared folder
  past that cap.
- **An access key sees that you are busy elsewhere.** Change numbers count
  every change in the account, so the gaps in what an access key syncs show
  how much changed outside its folder, though not where or what. Each account
  has its own counter, so nobody sees another account's activity.
- **The web page trusts the server it came from.** The browser runs the
  JavaScript the server sends, so a dishonest server could send a page that
  takes the master key (or an access token) as you type it. Only the Go client,
  built from source you hold, is safe from that.
- **An opened access token stays in the tab.** Opening Documents with an access
  token keeps it in that tab's `sessionStorage`, so a reload stays open, until
  the tab is closed. Close the tab on a shared computer.

## Keys

Every account has one **master key**: 32 random bytes, written in standard
base64. Make one with the browser's **Generate a new key** button or with
`client.GenerateKey()`, and keep a copy. Losing it, with no passphrase set,
loses the documents. Nobody can recover them, the server included.

A **passphrase** is optional. Setting one stores the master key, sealed under
an Argon2id hash of the passphrase, as the account's keyring on the server.
The browser fetches the keyring and opens it. Changing the passphrase replaces
the keyring and never re-encrypts documents. Only a signed-in browser reaches
the keyring (`/api/keyring`). An API key gets 403, even the account's own full
key, so a script that was never given the master key cannot take the keyring
away to guess the passphrase, or replace it. Services hold the raw key.

### Collection keys and access keys

Every collection also has **its own keys**: a read key that encrypts its
documents, and a write key that signs them. They live in the collection's
**lockbox**, sealed under its parent's keys (the master key's, at the top
level), so:

- the master key opens every collection;
- a collection's keys open that collection **and every collection under it**,
  and nothing beside or above it;
- a **read-only** key holds only the read half. It opens documents but cannot
  sign one, and readers refuse unsigned documents, so it cannot forge a
  document even with the server's help. Nor can it plant keys for a folder
  under its own: every lockbox is signed by its parent's write key, which a
  read-only key does not hold. The server also refuses its
  writes.

To hand one collection to someone, use **Share...** in that collection's menu
on the Documents screen (unlocked with the master key). Choose read only or read
and write, name it, and set when it expires. It shows an **access key**
(`e2eedb-ck.…`) once. The access key holds:

- a **scoped API key** that the server lets reach only that collection's subtree,
  only on the document routes (`/api/collections…`, `/api/changes`), read or
  write. Everything else, including `/api/me`, the keyring and other keys, is
  403. It appears in your API keys list, where you revoke it;
- the collection's keys. These never leave the client: only the API key part
  is sent.

Whoever gets it pastes it under **Have an access key?** on the signed-out page
(no account needed), or, in Go, uses `client.NewScoped( baseURL , token )`. A
scoped key cannot move, delete or leave its own collection, or make one at the
top level. It can make, move and delete collections inside its own, always
with random ids (22 characters, as `client.NewID()` makes), so it cannot take
an id your own code writes to by name. A collection made that way has no
owner tag in its lockbox (see "Lockboxes"), and the Go client will not write
your documents into one, or into anything under one, unless you pass
`client.AllowShared()` (`ErrSharedCollection` otherwise). The Documents
screen asks first. The server also reports it (`by_key`), but neither client
goes by that: a dishonest server could leave it out.

Where a collection sits is only the server's word, so a client never quietly
gives keys to a folder that has none yet and that the server puts under a
parent: they would be wrapped for the parent's keys, which open for whoever
holds an access key to the parent. The Go client refuses
(`ErrSharedCollection`) unless you pass `AllowShared`, and the Documents
screen asks, naming the parent. A folder at the top level gets its keys
without asking, since only the master key opens those.

Sharing first gives every collection in the subtree its keys, and seals any
private envelope in it (which only the master key opens) again as a
collection envelope. A collection in the subtree whose keys are not your own,
or that has none yet, could be there only because the server says so: if it
holds private envelopes, sharing stops before it changes anything and names
it. Move it out, or its documents, then share again. In Go, `PrepareShare` does that and returns the keys, and
`client.NewAccessToken( scopedAPIKey , keys )` builds the token. API keys
are minted from a signed-in browser only, as for every key.

**Revoking** the API key cuts access at once. Deleting the collection revokes
every access key for it, and a key never reaches a later collection that
reuses the id. Revoking does not change the collection's keys, though: the
server stops serving them, but someone who kept the token still holds keys
that open whatever the collection holds later and sign documents its readers
accept, if they get the ciphertext some other way (a leak, a backup, a
dishonest server). Moving a collection out of a shared subtree is the same:
the server stops serving it to that token, but its keys stay.

**Rotate keys...** in a collection's menu closes that. It gives the collection,
and every collection under it, new keys, and seals every document in them
again under those (see "Rotating keys" below). From then on the old keys open
nothing new, and nothing signed with them is accepted. It revokes every
access key for a collection in that subtree, since what their tokens carry is
the old keys: share again afterwards. Access keys for a collection above it
keep working. What someone could read before, they could have copied, so
documents nobody changes since are not made secret again: they are sealed
again so that forgeries under the old write key are refused. In Go,
`store.RotateKeys( ctx , "projects" )`.

## Go client

```go
import client "github.com/8529398670/E2EEDB/client"

key , _ := client.GenerateKey()        // once; keep it with your secrets
store , err := client.New( "https://docs.example.com" , apiKey , key ,
	client.WithState( "/var/lib/myapp/e2eedb-state.json" ) )  // remembers key rotations seen

meta , err := store.Set( ctx , "invoices" , client.NewID() , invoice , client.MustNotExist() )
_ , err = store.Get( ctx , "invoices" , meta.ID , &invoice )
_ , err = store.Set( ctx , "invoices" , meta.ID , invoice , client.IfVersion( meta.Version ) )
err = store.Each( ctx , "invoices" , func( meta client.Meta , data json.RawMessage ) error { ... } )

folder , err := store.CreateCollection( ctx , client.NewCollection{ Name: "Archive" } )
_ , err = store.MoveDoc( ctx , "invoices" , meta.ID , folder.ID )   // re-sealed for its new place
_ , err = store.MoveCollection( ctx , "invoices" , folder.ID , "" ) // nest invoices inside Archive
_ , err = store.Delete( ctx , "invoices" , meta.ID )

changes , err := store.Changes( ctx , since , 500 )  // sync: keep changes.NextSince

rotation , err := store.RotateKeys( ctx , "projects" )  // after revoking someone's access key
```

Errors: `ErrNotFound`, `*ConflictError` (`ErrConflict`, with the current
version), `ErrWrongKey`, `ErrCorrupt`, `ErrTooLarge`, `ErrQuota`,
`ErrSyncExpired` (start again from 0), `ErrRotating` (the collection's keys
are being rotated: finish that first), `ErrSharedCollection` (the keys are not
this master key's own, or would not be: pass `AllowShared` to write anyway),
`ErrRolledBack` (the server sent keys from before a rotation this client has
seen), and `*APIError` for anything else. A
client that cached a collection's keys before they were rotated fetches the
new ones by itself (`Set` and `MoveDoc` retry once on `ErrStaleKey`). The
package depends only on the standard library and `golang.org/x/crypto`.

### Sync

`GET /api/changes?since=N` lists every write and delete in the account after
change number N, oldest first and without bodies. Start from 0. Keep calling
with `next_since` while `more` is true, and store `next_since` for next time.
A deleted document shows up once with `deleted: true` and is purged after
`docs.tombstone_days`. A client that last synced before that gets
`410 sync_expired` and starts again from 0. Change numbers are counted per
account.

### Conditional writes

`if_version` on a write or delete: absent means unconditional, `0` means only
if there is no live document, and `n` means only if the live document is at
version `n`. A mismatch is `409 version_conflict` with `current_version`.

## Crypto format

One format, built from these pieces:

- **Collection envelope**: what every document write produces. It is sealed
  with its collection's read key and signed with its write key.
- **Private envelope**: the other option. It is sealed with the master key
  alone, so no access token can open it, and it is never shared as it is.
  Clients don't write one unless asked (`Key.Seal`, `DocsCrypto.seal`). They
  open one with the master key, and sharing seals it again as a collection
  envelope.
- **Lockbox**: a collection's keys, wrapped and signed by its holder.
- **Keyring**: the master key, wrapped under a passphrase.

The Go client (`client/crypto.go`, `client/crypto_collection.go`) and the
browser (`static/js/docs_crypto.js`) both implement them.
`client/testdata/vectors.json` pins them, and `scripts/check_crypto.js` (run by
`go test ./server/static`) holds the browser to the same vectors. The first
byte of an envelope names its kind: `0x01` private, `0x02` collection.

### The master key

Subkeys from the master key `M` (keyed BLAKE2b, `crypto_generichash`):

```
enc_key = BLAKE2b-256( key = M , message = "e2eedb/master/enc" )
key_id  = BLAKE2b-128( key = M , message = "e2eedb/master/kid" )
```

`key_id` names the master key wherever it appears: in the keyring, in the `by`
of a top-level lockbox, and in a private envelope.

The keyring (`GET/POST /api/keyring`, stored as opaque text):

```json
{"alg":"argon2id13","ops":2,"mem":33554432,
 "salt":"<16 bytes>","nonce":"<24 bytes>","key_id":"<16 bytes>","wrapped":"<48 bytes>"}
```

```
wrap_key = crypto_pwhash( 32 , passphrase (UTF-8, as typed) , salt , ops , mem , ALG_ARGON2ID13 )
wrapped  = XChaCha20-Poly1305-IETF( wrap_key , nonce , M , AD = "e2eedb/keyring" || key_id )
```

### Collection keys

Per collection `c`, the client that first gives it keys picks two random
32-byte secrets: a read key `rk` and an Ed25519 seed `ws` (write key), whose
public key is `vk`.

```
enc_key = BLAKE2b-256( key = rk , message = "e2eedb/collection/enc" )
key_id  = BLAKE2b-128( key = rk , message = "e2eedb/collection/kid" )
```

### Envelopes

A document body (the `body` field, standard base64 with padding) is one of:

```
collection = 0x02 || key_id (16) || nonce (24) || XChaCha20-Poly1305-IETF( enc_key , nonce , plaintext , AD ) || sig (64)
             AD  = 0x02 || key_id || collection || 0x00 || doc_id
             sig = Ed25519-sign( ws , envelope-before-sig || collection || 0x00 || doc_id )

private    = 0x01 || key_id (16) || nonce (24) || XChaCha20-Poly1305-IETF( enc_key , nonce , plaintext , AD )
             AD  = 0x01 || key_id || collection || 0x00 || doc_id
```

Use the collection key's `enc_key` and `key_id` for a collection envelope, and
the master key's for a private one. `plaintext` is the document's JSON as
UTF-8. The nonce is random. The AD binds the ciphertext to its collection and
id. Readers check a collection envelope's `sig` against `vk` before
decrypting. A scoped key may only write collection envelopes.

### Lockboxes

The lockbox (`lock` on the collection, opaque text to the server) is wrapped
and signed by a holder: the master key for a top-level collection, or the
parent collection's keys.

The holder's secret `h` is:

- the master key `M`, for a top-level collection;
- for a parent collection, its `rk` for the read half and its `ws` for the
  write half.

```
wrap_r = BLAKE2b-256( key = h_read  , message = "e2eedb/lock/wrap-r" )
wrap_w = BLAKE2b-256( key = h_write , message = "e2eedb/lock/wrap-w" )
read   = XChaCha20-Poly1305-IETF( wrap_r , nonce_r , rk || vk , AD = "e2eedb/lock/read"  || 0x00 || c || 0x00 || parent )
write  = XChaCha20-Poly1305-IETF( wrap_w , nonce_w , ws      , AD = "e2eedb/lock/write" || 0x00 || c || 0x00 || parent )
```

The holder signs it with its own Ed25519 key. A parent collection uses its
write key `ws`, checked with its `vk`. The master key uses one derived from
it:

```
lock_seed = BLAKE2b-256( key = M , message = "e2eedb/lock/sign-seed" )
sig       = Ed25519-sign( holder , "e2eedb/lock/sign" || 0x00 || c || 0x00 || parent || 0x00 || key_id || epoch || nonce_r || read || nonce_w || write )
```

`epoch` is 8 bytes, big-endian: how new the keys are. Keys made fresh get the
time in Unix seconds, or one more than the highest epoch the client has seen
for that id when that is later. A rotation's new keys get one more than the
keys they replace. A move re-wraps the same keys, so it keeps the epoch. It
is at least 1 and at most 2^53 - 1, so a browser's numbers hold it exactly.

A collection whose keys the master key made also carries the owner tag
`own`, which only the master key can make or check:

```
own = BLAKE2b-256( key = M , message = "e2eedb/lock/own" || 0x00 || c || 0x00 || key_id )
```

```json
{"parent":"<parent id, or \"\">","by":"<holder's key id>","key_id":"<c's key id>","epoch":1793000000,
 "nonce_r":"…","read":"…","nonce_w":"…","write":"…","sig":"…","own":"…"}
```

`sig` does not cover `own`, so a re-wrap for a move carries it over unchanged,
whoever does the move. It names `c` and `key_id`, not the parent, so it stays
true, and copying it onto other keys makes it fail. Clients add it when they
make a collection with the master key in hand. They leave it out when they
give keys to an existing folder that has none, unless that folder is at the
top level: under a parent, such a folder could be anyone's who holds the
parent's keys. A master-key client treats a collection as its own only if
its lockbox, and every lockbox above it, carries a valid `own`. A folder made
inside one that is not its own gets no `own` either. Ownership belongs to
each set of keys: a collection's `next_lock` is judged by its own `own`, not
by `lock`'s.

Every reader checks `sig` before opening `read`, and a lockbox without a valid
one opens for nobody. A read-only key holds the parent's `vk` but not its
`ws`, so it cannot plant a lockbox for a folder under its own.

A holder without a write half (a read-only key) opens only `read`, so
everything under it is read-only too.

The server sets a lockbox only once (`409 lock_exists`). The one exception is
a move: moving a collection to another parent sends its lockbox wrapped again
for that parent, and the server refuses the move without one
(`409 lock_required`).

### Rotating keys

A rotation gives a collection `R` and every collection under it new keys.
Each one gets a second lockbox, `next_lock`, in the same format as `lock`:

- `R`'s is wrapped for the same holder as its `lock` (its parent's keys, or
  the master key at the top level), which is not rotated;
- every other one's is wrapped for its parent's **new** keys, so the new
  keys form a tree of their own.

The owner tag carries over as it was: a collection the master key's keys
made gets one for its new keys, one made through an access token does not.

It runs in three steps, because the documents are too much for one request:

1. `POST /api/collections/{R}/rotate` with `locks`, the new lockboxes, parents
   first, in as many calls as it takes. The call that carries `R`'s starts
   the rotation and revokes every access key scoped to a collection in the
   subtree.
2. The client seals every collection envelope in the subtree again with the
   new keys, each with `if_version`, through the ordinary write route.
3. `POST /api/collections/{R}/rotate/commit`. Once every collection has a
   `next_lock` and every collection envelope in them names the new keys'
   `key_id`, each `next_lock` becomes its `lock`, all at once. Otherwise it
   is `409 rotate_incomplete`, saying how many are left.

Meanwhile readers open a collection envelope with whichever keys it names,
old or new, and writers seal with the new ones. The server reads the
`key_id` a lockbox names and the 16 bytes after an envelope's first byte,
and takes a collection envelope only if it names the keys its collection
uses now: the new ones mid-rotation, otherwise `lock`'s (`409 stale_key`).
Until the commit, the subtree's collections cannot be made, moved or given
lockboxes, and no access key can be made for them (`409 rotating`).

A rotation stopped half way stays as it is: documents open with either
keys, and starting it again on `R` finishes it (the new keys already staged
are kept). Private envelopes are not touched: only the master key opens them.

**Rolling it back.** Each `next_lock` carries an epoch one more than its
`lock` (see "Lockboxes"). Every client remembers the highest epoch it has
seen for each collection, as a `lock` and as a `next_lock`, and refuses a
lockbox below it (`ErrRolledBack` in Go):

- a `lock` below the highest `lock` seen;
- a `lock` below the highest `next_lock` seen, unless a `next_lock` one epoch
  on is still there and opens (the rotation still under way);
- a `next_lock` below either.

So once a client has seen a rotation staged, the server cannot go back to the
old keys alone, and once it has seen the commit, not even dressed up as a
rotation still under way. The client that rotates records both.

The browser keeps this in IndexedDB, per account (or per access token), and
**Forget this device** on the Documents screen drops it. The Go client keeps
it in memory for as long as the `Client` lives, and across restarts with
`client.WithState( path )`: a JSON file, mode 0600, written atomically, that
several accounts and tokens can share. A client with no memory cannot tell
(see "Known limits").

### Access tokens

An access token is `e2eedb-ck.` followed by the unpadded URL-safe base64 of
`{"k":"<api key>","c":"<collection>","r":"<rk>","v":"<vk>","w":"<ws, read/write only>"}`.

### Keyring cost

New keyrings use 2 passes over 32 MiB (about 3.5 seconds in the browser's
plain-JS libsodium). Each keyring records its own cost, so one made with other
settings opens too. Clients refuse keyrings asking for more than 10 passes or outside 8 MiB-1 GiB
of memory, so a server cannot make them spend unbounded time on an unlock.

### In the browser: plain JavaScript, no WebAssembly

The page's Content-Security-Policy stays `script-src 'self'`, with no
`'wasm-unsafe-eval'`. `static/vendor/sodium.js` is libsodium.js 0.8.4 (sumo,
for Argon2id) with its WebAssembly copy cut out by `misc/vendor_sodium.sh`.
The browser runs the plain-JS build libsodium.js ships as its fallback, and
the loader is told never to try WebAssembly. Encrypting and decrypting
documents is instant. A passphrase unlock is slower in plain JS than it would
be in WebAssembly.

## Running it

```bash
scripts/run.sh            # build and start; prints the URL
scripts/login.sh          # a sign-in link for the owner
go test ./...             # everything, including the client against the real routes
```

On the Account screen, make an API key for each service. A key acts as its
account: it sees that account's documents and no one else's. That holds even
for an admin's key, since admin rights here only decide who gets in.

Data lives in `~/.config/e2eedb/`: `app.db` (bbolt: accounts, sessions,
keys) and `docs.db` (SQLite: documents). `manage backup` and the scheduled
backup include both. `docs:` in `config/config.yaml` sets the largest document
(`max_doc_kb`), the per-account quota (`quota_mb`), how long deletes stay
visible to syncing clients (`tombstone_days`), and how much writes through one
access key may grow its shared folder (`share_quota_mb`,
`share_max_collections`; 0 leaves only the account's limits). An access key
that reaches either cap, or the account's own, gets `413
share_quota_exceeded` or `413 share_too_many_collections`. The hourly `docs` job purges old
tombstones and the documents of deleted accounts.
