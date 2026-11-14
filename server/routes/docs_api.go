package routes

import (
	time "time"

	apidoc "github.com/8529398670/E2EEDB/server/apidoc"
)

// The API docs for docs.go's routes: config/openapi.json and config/api.md
// are written from these by scripts/api_docs.sh (see server/apidoc).

const docsTag = "Documents"

type docAddressParamsDoc struct {
	Collection string `path:"collection" doc:"1-64 of A-Z a-z 0-9 _ -"`
	DocID string `path:"doc_id" doc:"1-128 of A-Z a-z 0-9 _ - . ; chosen by the client, random by default."`
}

type collectionParamsDoc struct {
	Collection string `path:"collection" doc:"1-64 of A-Z a-z 0-9 _ -"`
	Limit int `query:"limit" minimum:"1" maximum:"1000" doc:"Rows to return. Default 200."`
	Offset int `query:"offset" minimum:"0"`
	IncludeBody string `query:"include_body" enum:"true" doc:"Add each document's ciphertext."`
}

type pageParamsDoc struct {
	Limit int `query:"limit" minimum:"1" maximum:"1000" doc:"Rows to return. Default 200."`
	Offset int `query:"offset" minimum:"0"`
}

// docMetaSchema is one document's metadata: what the server knows about it.
type docMetaSchema struct {
	Collection string `json:"collection"`
	ID string `json:"id"`
	Version int64 `json:"version" doc:"Goes up by one on every write and delete."`
	Seq int64 `json:"seq" doc:"Change number, for GET /api/changes?since=."`
	UpdatedAt time.Time `json:"updated_at"`
	Size int `json:"size" doc:"Bytes of ciphertext; 0 for a delete."`
}

func ( docMetaSchema ) APIName() string { return "DocMeta" }

type docListRowDoc struct {
	docMetaSchema
	Body string `json:"body,omitempty" doc:"Only with include_body=true. Standard base64 (with padding) of the client's envelope. v1: 0x01, a 16-byte key id, a 24-byte nonce, then XChaCha20-Poly1305 ciphertext of the JSON document. v2 (collection keys): 0x02, the collection key's id, nonce and ciphertext the same way, then a 64-byte Ed25519 signature. See README.md. The server stores it and never opens it."`
}

type docWithBodyDoc struct {
	docMetaSchema
	Body string `json:"body" doc:"Standard base64 (with padding) of the client's envelope. v1: 0x01, a 16-byte key id, a 24-byte nonce, then XChaCha20-Poly1305 ciphertext of the JSON document. v2 (collection keys): 0x02, the collection key's id, nonce and ciphertext the same way, then a 64-byte Ed25519 signature. See README.md. The server stores it and never opens it."`
}

type docChangeDoc struct {
	docMetaSchema
	Deleted bool `json:"deleted" doc:"The document was deleted: drop your copy."`
}

var _ = apidoc.Doc( (*Handlers).ListCollections , apidoc.Op{
	Summary: "Your collections",
	Description: "Every collection (folder) in your account, each parent's children together in their order, with what your documents use against the quota. Rebuild the tree from parent and position. tree_seq moves on whenever a folder is made, renamed, moved or deleted.",
	Tag: docsTag,
	Params: pageParamsDoc{},
	Reply: listCollectionsReplyDoc{},
	Errors: []int{ 400 , 401 },
} )

// collectionSchema is one folder.
type collectionSchema struct {
	ID string `json:"id" doc:"What its documents are filed under and their encryption is bound to. Never changes."`
	Name string `json:"name" doc:"Shown name, unique among its siblings ignoring case. A collection made by writing a document is named after its id."`
	Parent string `json:"parent" doc:"The parent's id; \"\" for the top level."`
	Position int `json:"position" doc:"Place among its siblings, from 0."`
	Version int64 `json:"version" doc:"Goes up by one on every rename or move."`
	UpdatedAt time.Time `json:"updated_at"`
	Lock string `json:"lock,omitempty" doc:"The collection's lockbox: its own keys, wrapped by the client for its parent (or the master key at the top level). Opaque to the server. Absent until a client gives the collection keys. See README.md, Crypto format."`
	ByKey string `json:"by_key,omitempty" doc:"Present when the collection was made through an access token: the id of that scoped API key. The Go client will not write the account's own documents into such a collection unless asked to (client.AllowShared)."`
}

func ( collectionSchema ) APIName() string { return "Collection" }

type collectionRowDoc struct {
	collectionSchema
	Count int `json:"count" doc:"Its own live documents, not its subfolders'."`
	Bytes int64 `json:"bytes" doc:"Their ciphertext, in bytes."`
}

type listCollectionsReplyDoc struct {
	Collections []collectionRowDoc `json:"collections"`
	Next *int `json:"next" doc:"Offset of the next page, or null on the last one."`
	Total int `json:"total"`
	TreeSeq int64 `json:"tree_seq" doc:"Change number of the last change to your folders; 0 if none."`
	UsedBytes int64 `json:"used_bytes" doc:"All your live documents."`
	DocCount int `json:"doc_count"`
	QuotaBytes int64 `json:"quota_bytes" doc:"0: no quota."`
	MaxDocBytes int `json:"max_doc_bytes" doc:"Largest one document may be, in ciphertext bytes."`
	MaxCollections int `json:"max_collections" doc:"Most folders an account may have."`
	MaxDepth int `json:"max_depth" doc:"How deep folders may nest; a top-level folder is depth 1."`
}

var _ = apidoc.Doc( (*Handlers).CreateCollection , apidoc.Op{
	Summary: "Make a collection",
	Description: "A folder, empty until a document is written into it. Writing a document into an id that has no folder also makes one, at the top level. 409 name_taken: a sibling has that name. 409 version_conflict: the id is in use. 400 too_deep (with max_depth), 413 too_many_collections (with max_collections).",
	Tag: docsTag,
	Body: createCollectionBodyDoc{},
	Reply: collectionSchema{},
	Errors: []int{ 400 , 401 , 403 , 404 , 409 , 413 },
} )

type createCollectionBodyDoc struct {
	ID string `json:"id,omitempty" doc:"1-64 of A-Z a-z 0-9 _ -. Default: random. A scoped key may only send a random 22-character id (client.NewID), so it cannot take an id the account's own code writes to by name."`
	Name string `json:"name,omitempty" doc:"1-128 characters, no control characters, no space at either end. Default: the id."`
	Parent string `json:"parent,omitempty" doc:"Parent's id. Default \"\": the top level."`
	Before string `json:"before,omitempty" doc:"The sibling to go in front of. Default: at the end."`
	Lock string `json:"lock,omitempty" maxLength:"2048" doc:"The new collection's lockbox, wrapped for parent."`
	CSRFToken string `json:"csrf_token,omitempty" doc:"From GET /api/me. Browser sessions only."`
}

var _ = apidoc.Doc( (*Handlers).UpdateCollection , apidoc.Op{
	Summary: "Rename, move or reorder a collection",
	Description: "Give any of name, parent, before and lock. Its documents are not touched: they stay filed under the same id. Moving a folder into itself or one of its own subfolders is 400 collection_cycle; deeper than max_depth is 400 too_deep.",
	Tag: docsTag,
	Params: collectionAddressParamsDoc{},
	Body: updateCollectionBodyDoc{},
	Reply: collectionSchema{},
	Errors: []int{ 400 , 401 , 403 , 404 , 409 },
} )

type collectionAddressParamsDoc struct {
	Collection string `path:"collection" doc:"The collection's id."`
}

type updateCollectionBodyDoc struct {
	Name string `json:"name,omitempty" doc:"New name."`
	Parent string `json:"parent,omitempty" doc:"New parent's id; \"\" for the top level."`
	Before string `json:"before,omitempty" doc:"The sibling to go in front of; \"\" for the end. Read when parent or before is given."`
	IfVersion *int64 `json:"if_version,omitempty" minimum:"1" doc:"Change only if the collection is at this version."`
	Lock string `json:"lock,omitempty" maxLength:"2048" doc:"A lockbox: on a collection that has none yet, or wrapped again for the new parent, which a move of a collection with a lockbox must send (409 lock_required without it). Replacing one without a move is 409 lock_exists, except replacing an unsigned v2 lockbox with its signed v3 form (same key_id, parent and by)."`
	CSRFToken string `json:"csrf_token,omitempty" doc:"From GET /api/me. Browser sessions only."`
}

var _ = apidoc.Doc( (*Handlers).DeleteCollection , apidoc.Op{
	Summary: "Delete a collection and everything in it",
	Description: "Removes the folder, every folder under it, and every document in them. Each document leaves a tombstone GET /api/changes reports. To undo: make the folders again with the same ids, then write the documents back with if_version 0.",
	Tag: docsTag,
	Params: collectionAddressParamsDoc{},
	Body: deleteCollectionBodyDoc{},
	Reply: deleteCollectionReplyDoc{},
	Errors: []int{ 400 , 401 , 403 , 404 , 409 },
} )

type deleteCollectionBodyDoc struct {
	IfVersion *int64 `json:"if_version,omitempty" minimum:"1" doc:"Delete only if the collection is at this version."`
	CSRFToken string `json:"csrf_token,omitempty" doc:"From GET /api/me. Browser sessions only."`
}

type deleteCollectionReplyDoc struct {
	Collections []string `json:"collections" doc:"Every folder removed, the one asked for first, parents before children."`
	Docs []docChangeDoc `json:"docs" doc:"The tombstones left."`
}

var _ = apidoc.Doc( (*Handlers).ListDocs , apidoc.Op{
	Summary: "A collection's documents",
	Description: "Live documents by id. Deleted ones are left out; GET /api/changes reports them.",
	Tag: docsTag,
	Params: collectionParamsDoc{},
	Reply: listDocsReplyDoc{},
	Errors: []int{ 400 , 401 },
} )

type listDocsReplyDoc struct {
	Docs []docListRowDoc `json:"docs"`
	Next *int `json:"next" doc:"Offset of the next page, or null on the last one."`
	Total int `json:"total"`
}

var _ = apidoc.Doc( (*Handlers).GetDoc , apidoc.Op{
	Summary: "One document",
	Tag: docsTag,
	Params: docAddressParamsDoc{},
	Reply: docWithBodyDoc{},
	Errors: []int{ 400 , 401 , 404 },
} )

var _ = apidoc.Doc( (*Handlers).SetDoc , apidoc.Op{
	Summary: "Create or replace a document",
	Description: "Too big is 413 doc_too_large (with max_bytes), over your quota 413 quota_exceeded (with quota_bytes).",
	Tag: docsTag,
	Params: docAddressParamsDoc{},
	Body: setDocBodyDoc{},
	Reply: docMetaSchema{},
	Errors: []int{ 400 , 401 , 403 , 409 , 413 },
} )

type setDocBodyDoc struct {
	Body string `json:"body" doc:"Standard base64 (with padding) of the client's envelope. v1: 0x01, a 16-byte key id, a 24-byte nonce, then XChaCha20-Poly1305 ciphertext of the JSON document. v2 (collection keys): 0x02, the collection key's id, nonce and ciphertext the same way, then a 64-byte Ed25519 signature. See README.md. The server stores it and never opens it."`
	IfVersion *int64 `json:"if_version,omitempty" minimum:"0" doc:"Write only if the document is at this version: 0 means only if there is no live document. Absent: unconditional. A mismatch is 409 version_conflict with current_version and live."`
	CSRFToken string `json:"csrf_token,omitempty" doc:"From GET /api/me. Browser sessions only."`
}

var _ = apidoc.Doc( (*Handlers).DeleteDoc , apidoc.Op{
	Summary: "Delete a document",
	Description: "Leaves a tombstone that GET /api/changes reports for docs.tombstone_days. Writing the document again with if_version 0 brings it back.",
	Tag: docsTag,
	Params: docAddressParamsDoc{},
	Body: deleteDocBodyDoc{},
	Reply: docChangeDoc{},
	Errors: []int{ 400 , 401 , 403 , 404 , 409 },
} )

type deleteDocBodyDoc struct {
	IfVersion *int64 `json:"if_version,omitempty" minimum:"1" doc:"Delete only if the document is at this version. Absent: unconditional."`
	CSRFToken string `json:"csrf_token,omitempty" doc:"From GET /api/me. Browser sessions only."`
}

var _ = apidoc.Doc( (*Handlers).MoveDoc , apidoc.Op{
	Summary: "Move a document to another collection",
	Description: "In one step: the document is written at to_collection/to_id and the old one becomes a tombstone. A document's ciphertext is bound to its collection and id, so the client opens it and seals it again for the new place, and sends that as body. 409 version_conflict: the source is not at if_version, or a live document is already at the destination. 404: no such document, or no such destination collection.",
	Tag: docsTag,
	Params: docAddressParamsDoc{},
	Body: moveDocBodyDoc{},
	Reply: moveDocReplyDoc{},
	Errors: []int{ 400 , 401 , 403 , 404 , 409 , 413 },
} )

type moveDocBodyDoc struct {
	ToCollection string `json:"to_collection" doc:"The destination collection's id. It must exist."`
	ToID string `json:"to_id,omitempty" doc:"The document's id there. Default: the same id."`
	Body string `json:"body" doc:"Standard base64 of the document's v1 or v2 envelope, sealed for to_collection and to_id. See README.md."`
	IfVersion *int64 `json:"if_version,omitempty" minimum:"1" doc:"Move only if the source is at this version."`
	CSRFToken string `json:"csrf_token,omitempty" doc:"From GET /api/me. Browser sessions only."`
}

type moveDocReplyDoc struct {
	Doc docMetaSchema `json:"doc" doc:"The document in its new place."`
	Deleted docChangeDoc `json:"deleted" doc:"The tombstone left where it was."`
}

var _ = apidoc.Doc( (*Handlers).ListChanges , apidoc.Op{
	Summary: "What changed since you last synced",
	Description: "Every write and delete in your account after change number since, oldest first, without bodies. Start from 0, keep calling with next_since while more is true, and save next_since for next time. 410 sync_expired: deletes you never saw have been purged; start again from 0.",
	Tag: docsTag,
	Params: listChangesParamsDoc{},
	Reply: listChangesReplyDoc{},
	Errors: []int{ 400 , 401 , 410 },
} )

type listChangesParamsDoc struct {
	Since int64 `query:"since" minimum:"0" doc:"The next_since of your last call. Default 0: everything."`
	Limit int `query:"limit" minimum:"1" maximum:"1000" doc:"Changes to return. Default 200."`
}

type listChangesReplyDoc struct {
	Changes []docChangeDoc `json:"changes"`
	NextSince int64 `json:"next_since" doc:"Pass as since next time."`
	More bool `json:"more" doc:"Another page is waiting."`
}

var _ = apidoc.Doc( (*Handlers).GetKeyring , apidoc.Op{
	Summary: "Your wrapped master key",
	Description: "The master key sealed under a key derived from your passphrase (Argon2id), stored as the client wrote it. Useless without the passphrase. 404 when no passphrase has been set.",
	Tag: docsTag,
	Reply: getKeyringReplyDoc{},
	Errors: []int{ 401 , 404 },
} )

type getKeyringReplyDoc struct {
	Keyring string `json:"keyring" doc:"JSON text; see README.md, Keyring."`
	Version int64 `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

var _ = apidoc.Doc( (*Handlers).SetKeyring , apidoc.Op{
	Summary: "Set or change your passphrase",
	Description: "Stores a new wrapped master key. Documents are not re-encrypted: they stay under the same master key.",
	Tag: docsTag,
	Body: setKeyringBodyDoc{},
	Reply: setKeyringReplyDoc{},
	Errors: []int{ 400 , 401 , 403 , 409 },
} )

type setKeyringBodyDoc struct {
	Keyring string `json:"keyring" minLength:"1" maxLength:"4096" doc:"JSON text; see README.md, Keyring."`
	IfVersion *int64 `json:"if_version,omitempty" minimum:"0" doc:"0: only if none is set yet. n: only if the stored one is at n."`
	CSRFToken string `json:"csrf_token,omitempty" doc:"From GET /api/me. Browser sessions only."`
}

type setKeyringReplyDoc struct {
	Version int64 `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}
