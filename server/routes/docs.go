package routes

import (
	rand "crypto/rand"
	base64 "encoding/base64"
	errors "errors"
	strconv "strconv"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	apidoc "github.com/8529398670/E2EEDB/server/apidoc"
	docstore "github.com/8529398670/E2EEDB/server/docstore"
	logs "github.com/8529398670/E2EEDB/server/logs"
	models "github.com/8529398670/E2EEDB/server/models"
	security "github.com/8529398670/E2EEDB/server/security"
)

// The document store's routes. Every one is about the caller's own account
// and nothing else: there is no admin view of anyone's documents, because an
// admin here decides who gets in, and the documents are ciphertext nobody but
// their owner's clients can open anyway. Another account's document answers
// exactly like one that does not exist.
//
// Bodies travel as standard base64 (with padding) of the client's envelope;
// see README.md for the format. The server checks only that it is an
// envelope (docstore.ValidEnvelope) and how big it is.

// docMeta is one document's metadata: what the server knows about it.
type docMeta struct {
	Collection string    `json:"collection"`
	ID         string    `json:"id"`
	Version    int64     `json:"version" jsonschema_description:"Goes up by one on every write and delete."`
	Seq        int64     `json:"seq" jsonschema_description:"Change number, for GET /api/changes?since=."`
	UpdatedAt  time.Time `json:"updated_at"`
	Size       int       `json:"size" jsonschema_description:"Bytes of ciphertext; 0 for a delete."`
}

func ( docMeta ) APIName() ( name string ) { name = "DocMeta"; return }

func newDocMeta( doc docstore.Doc ) ( meta docMeta ) {
	meta = docMeta{ Collection: doc.Collection , ID: doc.ID , Version: doc.Version , Seq: doc.Seq , UpdatedAt: doc.UpdatedAt , Size: doc.Size }
	return
}

// docListRow is a document in a collection's list, with its body only when
// asked for.
type docListRow struct {
	docMeta
	Body string `json:"body,omitempty" jsonschema_description:"Only with include_body=true. Standard base64 (with padding) of the client's envelope (see Doc)."`
}

// docWithBody is one document with its ciphertext.
type docWithBody struct {
	docMeta
	Body string `json:"body" jsonschema_description:"Standard base64 (with padding) of the client's envelope. A collection envelope (what clients write): 0x02, the collection key's 16-byte id, a 24-byte nonce, XChaCha20-Poly1305 ciphertext of the JSON document, then a 64-byte Ed25519 signature. A private envelope (sealed by the master key alone, so never shareable): 0x01, the master key's id, nonce and ciphertext the same way, no signature. See README.md. The server stores it and never opens it."`
}

func ( docWithBody ) APIName() ( name string ) { name = "Doc"; return }

// docChange is a write or a delete, as the change feed and the deletes
// report it.
type docChange struct {
	docMeta
	Deleted bool `json:"deleted" jsonschema_description:"The document was deleted: drop your copy."`
}

func ( docChange ) APIName() ( name string ) { name = "DocChange"; return }

func newDocChange( doc docstore.Doc , deleted bool ) ( change docChange ) {
	change = docChange{ docMeta: newDocMeta( doc ) , Deleted: deleted }
	return
}

// collectionPath is the collection in a route's path.
type collectionPath struct {
	Collection string `json:"collection" path:"collection" jsonschema:"minLength=1,maxLength=64" jsonschema_description:"The collection's id: 1-64 of A-Z a-z 0-9 _ -" error:"collection must be 1-64 of A-Z a-z 0-9 _ -"`
}

// docPath is a document's collection and id in a route's path.
type docPath struct {
	collectionPath
	DocID string `json:"doc_id" path:"doc_id" jsonschema:"minLength=1,maxLength=128" jsonschema_description:"1-128 of A-Z a-z 0-9 _ - . ; chosen by the client, random by default." error:"id must be 1-128 of A-Z a-z 0-9 _ - ."`
}

// check is what the schema cannot say: which characters an id may have.
func ( path collectionPath ) check() ( refused *refusal ) {
	if docstore.ValidCollection( path.Collection ) == false {
		refused = refuse( fiber.StatusBadRequest , "collection must be 1-64 of A-Z a-z 0-9 _ -" )
	}
	return
}

func ( path docPath ) check() ( refused *refusal ) {
	if refused = path.collectionPath.check(); refused != nil { return }
	if docstore.ValidDocID( path.DocID ) == false {
		refused = refuse( fiber.StatusBadRequest , "id must be 1-128 of A-Z a-z 0-9 _ - ." )
	}
	return
}

// docOwner is whose documents this request may touch: always the caller's.
func docOwner( c fiber.Ctx ) ( user_id uint64 ) {
	user_id = security.UserFrom( c ).ID
	return
}

// docScope is the caller's key scope: the one collection (and its subtree)
// a scoped API key may reach, or nil for the whole account. See
// models.APIKey.Scope; security.RestrictScopedKeys keeps such a key on these
// routes.
func docScope( c fiber.Ctx ) ( scope *models.KeyScope ) {
	if key := security.APIKeyFrom( c ); key != nil {
		scope = key.Scope
	}
	return
}

// checkScope refuses a collection outside the caller's scope, answering as
// one that does not exist, and a write through a read-only scope.
func ( handlers *Handlers ) checkScope( c fiber.Ctx , collection string , write bool ) ( refused *refusal ) {
	scope := docScope( c )
	if scope == nil { return }
	if refused = handlers.checkScopeRoot( c ); refused != nil { return }
	inside , err := handlers.Docs.Within( docOwner( c ) , scope.Collection , collection )
	switch {
	case err != nil:
		refused = internalFailure( err )
	case inside == false:
		refused = refuse( fiber.StatusNotFound , "no such collection" )
	case write && scope.Write == false:
		refused = refuse( fiber.StatusForbidden , "read_only" )
	}
	return
}

// checkScopeRoot refuses a scoped key whose collection is gone, or was
// deleted and made again under the same id: the key was for that one folder
// (KeyScope.Born), not for whatever later takes its id.
func ( handlers *Handlers ) checkScopeRoot( c fiber.Ctx ) ( refused *refusal ) {
	scope := docScope( c )
	if scope == nil { return }
	entry , err := handlers.Docs.GetCollection( docOwner( c ) , scope.Collection )
	switch {
	case errors.Is( err , docstore.ErrNoCollection ):
		refused = refuse( fiber.StatusNotFound , "no such collection" )
	case err != nil:
		refused = internalFailure( err )
	case entry.Born != scope.Born:
		refused = refuse( fiber.StatusNotFound , "no such collection" )
	}
	return
}

// docLimits is what a write is checked against, from the running config.
func ( handlers *Handlers ) docLimits() ( limits docstore.Limits ) {
	docs := handlers.cfg().Docs.Limits()
	limits = docstore.Limits{ MaxDocBytes: docs.MaxDocBytes , QuotaBytes: docs.QuotaBytes , MaxCollections: docs.MaxCollections , MaxDepth: docs.MaxDepth }
	return
}

// docRefusal turns what the store said no with into an answer.
func ( handlers *Handlers ) docRefusal( cause error ) ( refused *refusal ) {
	var conflict *docstore.ConflictError
	limits := handlers.docLimits()
	switch {
	case errors.As( cause , &conflict ):
		refused = refuse( fiber.StatusConflict , "version_conflict" , fiber.Map{ "current_version": conflict.Current , "live": conflict.Live } )
	case errors.Is( cause , docstore.ErrNotFound ):
		refused = refuse( fiber.StatusNotFound , "no such document" )
	case errors.Is( cause , docstore.ErrNoCollection ):
		refused = refuse( fiber.StatusNotFound , "no such collection" )
	case errors.Is( cause , docstore.ErrNameTaken ):
		refused = refuse( fiber.StatusConflict , "name_taken" )
	case errors.Is( cause , docstore.ErrCycle ):
		refused = refuse( fiber.StatusBadRequest , "collection_cycle" )
	case errors.Is( cause , docstore.ErrTooDeep ):
		refused = refuse( fiber.StatusBadRequest , "too_deep" , fiber.Map{ "max_depth": limits.MaxDepth } )
	case errors.Is( cause , docstore.ErrTooMany ):
		refused = refuse( fiber.StatusRequestEntityTooLarge , "too_many_collections" , fiber.Map{ "max_collections": limits.MaxCollections } )
	case errors.Is( cause , docstore.ErrLockRequired ):
		refused = refuse( fiber.StatusConflict , "lock_required" )
	case errors.Is( cause , docstore.ErrLockExists ):
		refused = refuse( fiber.StatusConflict , "lock_exists" )
	case errors.Is( cause , docstore.ErrSamePlace ):
		refused = refuse( fiber.StatusBadRequest , "same_place" )
	case errors.Is( cause , docstore.ErrTooLarge ):
		refused = refuse( fiber.StatusRequestEntityTooLarge , "doc_too_large" , fiber.Map{ "max_bytes": limits.MaxDocBytes } )
	case errors.Is( cause , docstore.ErrQuota ):
		refused = refuse( fiber.StatusRequestEntityTooLarge , "quota_exceeded" , fiber.Map{ "quota_bytes": limits.QuotaBytes } )
	case errors.Is( cause , docstore.ErrSyncExpired ):
		refused = refuse( fiber.StatusGone , "sync_expired" )
	default:
		refused = internalFailure( cause )
	}
	return
}


// collectionRow is one folder as the API shows it.
type collectionRow struct {
	ID        string    `json:"id" jsonschema_description:"What its documents are filed under and their encryption is bound to. Never changes."`
	Name      string    `json:"name" jsonschema_description:"Shown name, unique among its siblings ignoring case. A collection made by writing a document is named after its id."`
	Parent    string    `json:"parent" jsonschema_description:"The parent's id; \"\" for the top level."`
	Position  int       `json:"position" jsonschema_description:"Place among its siblings, from 0."`
	Version   int64     `json:"version" jsonschema_description:"Goes up by one on every rename or move."`
	UpdatedAt time.Time `json:"updated_at"`
	Lock      string    `json:"lock,omitempty" jsonschema_description:"The collection's lockbox: its own keys, wrapped by the client for its parent (or the master key at the top level). Opaque to the server. Absent until a client gives the collection keys. See README.md, Crypto format."`
	// ByKey: made through someone's access key, so a client writing by id
	// can refuse to put the account's own documents there.
	ByKey string `json:"by_key,omitempty" jsonschema_description:"Present when the collection was made through an access token: the id of that scoped API key. The Go client will not write the account's own documents into such a collection unless asked to (client.AllowShared)."`
}

func ( collectionRow ) APIName() ( name string ) { name = "Collection"; return }

func newCollectionRow( entry docstore.Collection ) ( row collectionRow ) {
	row = collectionRow{ ID: entry.ID , Name: entry.Name , Parent: entry.Parent , Position: entry.Position , Version: entry.Version , UpdatedAt: entry.UpdatedAt , Lock: entry.Lock , ByKey: entry.ByKey }
	return
}

// collectionCountedRow is a folder in the list, with what is in it.
type collectionCountedRow struct {
	collectionRow
	Count int   `json:"count" jsonschema_description:"Its own live documents, not its subfolders'."`
	Bytes int64 `json:"bytes" jsonschema_description:"Their ciphertext, in bytes."`
}

type listCollectionsReply struct {
	Collections []collectionCountedRow `json:"collections"`
	Paged
	TreeSeq        int64 `json:"tree_seq" jsonschema_description:"Change number of the last change to your folders; 0 if none."`
	UsedBytes      int64 `json:"used_bytes" jsonschema_description:"All your live documents."`
	DocCount       int   `json:"doc_count"`
	QuotaBytes     int64 `json:"quota_bytes" jsonschema_description:"0: no quota."`
	MaxDocBytes    int   `json:"max_doc_bytes" jsonschema_description:"Largest one document may be, in ciphertext bytes."`
	MaxCollections int   `json:"max_collections" jsonschema_description:"Most folders an account may have."`
	MaxDepth       int   `json:"max_depth" jsonschema_description:"How deep folders may nest; a top-level folder is depth 1."`
}

// pagedOf is the Paged of a list the database cut itself.
func pagedOf( page Page , count int , total int ) ( paged Paged ) {
	paged.Total = total
	if end := page.Offset + count; end < total {
		paged.Next = &end
	}
	return
}

// pageLimit is a Page's limit, with the default filled in.
func pageLimit( page Page ) ( limit int ) {
	limit = page.Limit
	if limit == 0 { limit = pageDefault }
	return
}

// listCollections is the caller's folders, each parent's children together
// in their order, with what the documents use against the quota.
//
// @route("GET /api/collections", summary="Your collections", tag="Documents",
//     description="Every collection (folder) in your account, each parent's children together in their order, "
//         "with what your documents use against the quota. Rebuild the tree from parent and position. tree_seq "
//         "moves on whenever a folder is made, renamed, moved or deleted.",
// )
func ( handlers *Handlers ) listCollections( c fiber.Ctx , in *Page ) ( reply *listCollectionsReply , err error ) {
	owner := docOwner( c )
	limit := pageLimit( *in )
	var collections []docstore.Collection
	var total , count int
	var used int64
	if scope := docScope( c ); scope != nil {
		if refused := handlers.checkScopeRoot( c ); refused != nil {
			err = refused
			return
		}
		collections , total , used , count , err = handlers.scopedCollections( owner , scope.Collection , in.Offset , limit )
		if err != nil { return }
	} else {
		if collections , total , err = handlers.Docs.Collections( owner , in.Offset , limit ); err != nil { return }
		if used , count , err = handlers.Docs.Usage( owner ); err != nil { return }
	}
	tree_seq , err := handlers.Docs.TreeSeq( owner )
	if err != nil { return }
	rows := make( []collectionCountedRow , 0 , len( collections ) )
	for _ , entry := range collections {
		rows = append( rows , collectionCountedRow{ collectionRow: newCollectionRow( entry ) , Count: entry.Count , Bytes: entry.Bytes } )
	}
	limits := handlers.docLimits()
	reply = &listCollectionsReply{
		Collections:    rows,
		Paged:          pagedOf( *in , len( rows ) , total ),
		TreeSeq:        tree_seq,
		UsedBytes:      used,
		DocCount:       count,
		QuotaBytes:     limits.QuotaBytes,
		MaxDocBytes:    limits.MaxDocBytes,
		MaxCollections: limits.MaxCollections,
		MaxDepth:       limits.MaxDepth,
	}
	return
}

// scopedCollections is listCollections for a scoped key: root and the
// folders under it, root shown at the top level, one page of them, and what
// their documents use.
func ( handlers *Handlers ) scopedCollections( owner uint64 , root string , offset int , limit int ) ( page []docstore.Collection , total int , used int64 , count int , err error ) {
	ids , err := handlers.Docs.Subtree( owner , root )
	if err != nil { return }
	inside := map[ string ]bool{}
	for _ , id := range ids { inside[ id ] = true }
	kept := []docstore.Collection{}
	var all []docstore.Collection
	for start , account_total := 0 , 1 ; start < account_total ; start += 1000 {
		var batch []docstore.Collection
		if batch , account_total , err = handlers.Docs.Collections( owner , start , 1000 ); err != nil { return }
		all = append( all , batch... )
	}
	for _ , entry := range all {
		if inside[ entry.ID ] == false { continue }
		if entry.ID == root { entry.Parent = "" }
		used += entry.Bytes
		count += entry.Count
		kept = append( kept , entry )
	}
	total = len( kept )
	if offset > total { offset = total }
	end := offset + limit
	if end > total { end = total }
	page = kept[ offset:end ]
	return
}

// collectionFields are what a folder write may change.
type collectionFields struct {
	Name   *string `json:"name,omitempty" jsonschema_description:"1-128 characters, no control characters, no space at either end."`
	Parent *string `json:"parent,omitempty" jsonschema_description:"Parent's id; \"\" for the top level."`
	Before *string `json:"before,omitempty" jsonschema_description:"The sibling to go in front of; \"\" or absent for the end."`
	Lock   *string `json:"lock,omitempty" jsonschema:"minLength=1,maxLength=2048" jsonschema_description:"A lockbox, wrapped by the client for parent. On an update: on a collection that has none yet, or wrapped again for the new parent, which a move of a collection with a lockbox must send (409 lock_required without it). Replacing one without a move is 409 lock_exists." error:"lock must be 1-2048 bytes"`
}

type createCollectionRequest struct {
	ID string `json:"id,omitempty" jsonschema:"maxLength=64" jsonschema_description:"1-64 of A-Z a-z 0-9 _ -. Default: random. A scoped key may only send a random 22-character id (client.NewID), so it cannot take an id the account's own code writes to by name." error:"id must be 1-64 of A-Z a-z 0-9 _ -"`
	collectionFields
}

type updateCollectionRequest struct {
	collectionPath
	collectionFields
	IfVersion *int64 `json:"if_version,omitempty" jsonschema:"minimum=1" jsonschema_description:"Change only if the collection is at this version." error:"if_version must be 1 or more"`
}

// change is the request checked and turned into what the store takes.
func ( fields collectionFields ) change( if_version *int64 ) ( change docstore.CollectionChange , refused *refusal ) {
	if fields.Name != nil && docstore.ValidCollectionName( *fields.Name ) == false {
		refused = refuse( fiber.StatusBadRequest , "name must be 1-" + strconv.Itoa( docstore.CollectionNameMax ) + " characters, with no control characters and no space at either end" )
		return
	}
	for _ , other := range []*string{ fields.Parent , fields.Before } {
		if other != nil && *other != "" && docstore.ValidCollection( *other ) == false {
			refused = refuse( fiber.StatusBadRequest , "parent and before must be \"\" or a collection id" )
			return
		}
	}
	if fields.Lock != nil && ( *fields.Lock == "" || len( *fields.Lock ) > docstore.LockMaxBytes ) {
		refused = refuse( fiber.StatusBadRequest , "lock must be 1-" + strconv.Itoa( docstore.LockMaxBytes ) + " bytes" )
		return
	}
	change = docstore.CollectionChange{ Name: fields.Name , Parent: fields.Parent , Before: fields.Before , IfVersion: if_version , Lock: fields.Lock }
	return
}

// newCollectionID is a random id for a folder the client did not name: 16
// characters of A-Z a-z 0-9, like the browser's document ids.
func newCollectionID() ( id string ) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	raw := make( []byte , 16 )
	rand.Read( raw )
	for index := range raw {
		raw[ index ] = alphabet[ int( raw[ index ] ) % len( alphabet ) ]
	}
	id = string( raw )
	return
}

// createCollection makes a folder. id is optional (random when left out);
// name defaults to the id, parent to the top level, and the folder goes in
// front of before, or at the end.
//
// @route("POST /api/collections", summary="Make a collection", tag="Documents", errors=(404, 409, 413),
//     description="A folder, empty until a document is written into it. Writing a document into an id that "
//         "has no folder also makes one, at the top level. 409 name_taken: a sibling has that name. 409 "
//         "version_conflict: the id is in use. 400 too_deep (with max_depth), 413 too_many_collections (with "
//         "max_collections).",
// )
func ( handlers *Handlers ) createCollection( c fiber.Ctx , in *createCollectionRequest ) ( reply *collectionRow , err error ) {
	change , refused := in.change( nil )
	if refused != nil {
		err = refused
		return
	}
	id := in.ID
	if id == "" {
		id = newCollectionID()
	} else if docstore.ValidCollection( id ) == false {
		err = refuse( fiber.StatusBadRequest , "id must be 1-64 of A-Z a-z 0-9 _ -" )
		return
	}
	if docScope( c ) != nil {
		// A scoped key makes folders only inside its own, and only with a
		// random id: one it chose ("invoices") could be an id the account's
		// own code later writes to by name, sealing those documents with keys
		// the key's holder has.
		if in.ID != "" && docstore.ValidRandomID( in.ID ) == false {
			err = refuse( fiber.StatusBadRequest , "a scoped key's folder id must be a random 22-character id (client.NewID)" )
			return
		}
		parent := ""
		if change.Parent != nil { parent = *change.Parent }
		if refused := handlers.checkScope( c , parent , true ); refused != nil {
			err = refused
			return
		}
		change.ByKey = security.APIKeyFrom( c ).ID
	}
	entry , create_err := handlers.Docs.CreateCollection( docOwner( c ) , id , change , handlers.docLimits() )
	if create_err != nil {
		err = handlers.docRefusal( create_err )
		return
	}
	row := newCollectionRow( entry )
	reply = &row
	return
}

// updateCollection renames, moves or reorders a folder: name, parent and
// before, each optional. Its documents stay as they are.
//
// @route("POST /api/collections/{collection}", summary="Rename, move or reorder a collection",
//     tag="Documents", errors=(403, 404, 409),
//     description="Give any of name, parent, before and lock. Its documents are not touched: they stay filed "
//         "under the same id. Moving a folder into itself or one of its own subfolders is 400 "
//         "collection_cycle; deeper than max_depth is 400 too_deep. A scoped key cannot rename or move the "
//         "collection it is for (403).",
// )
func ( handlers *Handlers ) updateCollection( c fiber.Ctx , in *updateCollectionRequest ) ( reply *collectionRow , err error ) {
	change , refused := in.change( in.IfVersion )
	if refused == nil { refused = in.collectionPath.check() }
	if refused == nil { refused = handlers.checkScope( c , in.Collection , true ) }
	if refused != nil {
		err = refused
		return
	}
	id := in.Collection
	if scope := docScope( c ); scope != nil && id == scope.Collection && ( change.Name != nil || change.Parent != nil || change.Before != nil ) {
		// The folder a key is for stays where and what it is. A rename
		// would check its name against the owner's other top-level
		// folders (409 name_taken), telling the key's holder their names.
		err = refuse( fiber.StatusForbidden , "a scoped key cannot rename or move the collection it is for" )
		return
	}
	if docScope( c ) != nil && change.Parent != nil {
		// Others move only within it.
		if refused = handlers.checkScope( c , *change.Parent , true ); refused != nil {
			err = refused
			return
		}
	}
	entry , update_err := handlers.Docs.UpdateCollection( docOwner( c ) , id , change , handlers.docLimits() )
	if update_err != nil {
		err = handlers.docRefusal( update_err )
		return
	}
	row := newCollectionRow( entry )
	reply = &row
	return
}

type deleteCollectionRequest struct {
	collectionPath
	IfVersion *int64 `json:"if_version,omitempty" jsonschema:"minimum=1" jsonschema_description:"Delete only if the collection is at this version." error:"if_version must be 1 or more"`
}

type deleteCollectionReply struct {
	Collections []string    `json:"collections" jsonschema_description:"Every folder removed, the one asked for first, parents before children."`
	Docs        []docChange `json:"docs" jsonschema_description:"The tombstones left."`
}

// deleteCollection removes a folder, the folders under it and every document
// in them, each document leaving a tombstone the change feed reports.
//
// @route("POST /api/collections/{collection}/delete", summary="Delete a collection and everything in it",
//     tag="Documents", errors=(404, 409),
//     description="Removes the folder, every folder under it, and every document in them. Each document leaves "
//         "a tombstone GET /api/changes reports. To undo: make the folders again with the same ids, then write "
//         "the documents back with if_version 0.",
// )
func ( handlers *Handlers ) deleteCollection( c fiber.Ctx , in *deleteCollectionRequest ) ( reply *deleteCollectionReply , err error ) {
	refused := in.check()
	if refused == nil { refused = handlers.checkScope( c , in.Collection , true ) }
	if refused != nil {
		err = refused
		return
	}
	id := in.Collection
	if scope := docScope( c ); scope != nil && id == scope.Collection {
		err = refuse( fiber.StatusForbidden , "a scoped key cannot delete the collection it is for" )
		return
	}
	deleted , delete_err := handlers.Docs.DeleteCollection( docOwner( c ) , id , in.IfVersion )
	if delete_err != nil {
		err = handlers.docRefusal( delete_err )
		return
	}
	// The access keys for a folder that is gone go with it, so one can never
	// reach a later folder that reuses the id.
	revoked , err := models.RevokeScopedKeys( handlers.Store , docOwner( c ) , deleted.Collections )
	for _ , key_id := range revoked {
		handlers.audit( c , logs.KindAdmin , "api key revoked: its collection was deleted" , fiber.Map{ "key_id": key_id , "collection": id } )
	}
	if err != nil { return }
	rows := make( []docChange , 0 , len( deleted.Docs ) )
	for _ , doc := range deleted.Docs {
		rows = append( rows , newDocChange( doc , true ) )
	}
	reply = &deleteCollectionReply{ Collections: deleted.Collections , Docs: rows }
	return
}

type listDocsRequest struct {
	collectionPath
	Page
	IncludeBody string `json:"include_body,omitempty" query:"include_body" jsonschema:"enum=true" jsonschema_description:"Add each document's ciphertext. A page with bodies stops early at 8 MiB of them; follow next." error:"include_body must be true"`
}

type listDocsReply struct {
	Docs []docListRow `json:"docs"`
	Paged
}

// listBodyBytes caps the ciphertext one page of documents with bodies
// carries. Without it, limit=1000 of the largest documents is gigabytes in
// memory for one request, which even a read-only access key could ask for.
// A page that reaches it ends early, and next says where to carry on.
const listBodyBytes = 8 << 20

// listDocs is one page of a collection's documents, by id. ?include_body=true
// adds each one's ciphertext, so a client can fetch a collection in pages
// rather than one document at a time.
//
// @route("GET /api/collections/{collection}/docs", summary="A collection's documents", tag="Documents",
//     description="Live documents by id. Deleted ones are left out; GET /api/changes reports them.",
// )
func ( handlers *Handlers ) listDocs( c fiber.Ctx , in *listDocsRequest ) ( reply *listDocsReply , err error ) {
	refused := in.check()
	if refused == nil { refused = handlers.checkScope( c , in.Collection , false ) }
	if refused != nil {
		err = refused
		return
	}
	with_bodies := in.IncludeBody == "true"
	docs , total , err := handlers.Docs.List( docOwner( c ) , in.Collection , in.Offset , pageLimit( in.Page ) , with_bodies , listBodyBytes )
	if err != nil { return }
	rows := make( []docListRow , 0 , len( docs ) )
	for _ , doc := range docs {
		row := docListRow{ docMeta: newDocMeta( doc ) }
		if with_bodies { row.Body = base64.StdEncoding.EncodeToString( doc.Body ) }
		rows = append( rows , row )
	}
	reply = &listDocsReply{ Docs: rows , Paged: pagedOf( in.Page , len( rows ) , total ) }
	return
}

// getDoc is one document with its ciphertext.
//
// @route("GET /api/collections/{collection}/docs/{doc_id}", summary="One document", tag="Documents",
//     errors=(404,),
// )
func ( handlers *Handlers ) getDoc( c fiber.Ctx , in *docPath ) ( reply *docWithBody , err error ) {
	refused := in.check()
	if refused == nil { refused = handlers.checkScope( c , in.Collection , false ) }
	if refused != nil {
		err = refused
		return
	}
	doc , get_err := handlers.Docs.Get( docOwner( c ) , in.Collection , in.DocID )
	if get_err != nil {
		err = handlers.docRefusal( get_err )
		return
	}
	reply = &docWithBody{ docMeta: newDocMeta( doc ) , Body: base64.StdEncoding.EncodeToString( doc.Body ) }
	return
}

type setDocRequest struct {
	docPath
	Body      string `json:"body" jsonschema_description:"Standard base64 (with padding) of the client's envelope. A collection envelope (what clients write): 0x02, the collection key's 16-byte id, a 24-byte nonce, XChaCha20-Poly1305 ciphertext of the JSON document, then a 64-byte Ed25519 signature. A private envelope (sealed by the master key alone, so never shareable): 0x01, the master key's id, nonce and ciphertext the same way, no signature. See README.md. The server stores it and never opens it." error:"body must be a base64 private or collection envelope (see README.md); the server stores ciphertext only"`
	IfVersion *int64 `json:"if_version,omitempty" jsonschema:"minimum=0" jsonschema_description:"Write only if the document is at this version: 0 means only if there is no live document. Absent: unconditional. A mismatch is 409 version_conflict with current_version and live." error:"if_version must be 0 or more"`
}

// envelope decodes a write's body and checks it is one the server takes.
func envelope( encoded string ) ( body []byte , refused *refusal ) {
	body , err := base64.StdEncoding.DecodeString( encoded )
	if err != nil || docstore.ValidEnvelope( body ) == false {
		refused = refuse( fiber.StatusBadRequest , "body must be a base64 private or collection envelope (see README.md); the server stores ciphertext only" )
		return
	}
	return
}

// setDoc creates or replaces a document. if_version makes it conditional:
// 0 only if there is no live document, n only if the live one is at n.
//
// @route("POST /api/collections/{collection}/docs/{doc_id}", summary="Create or replace a document",
//     tag="Documents", errors=(409, 413),
//     description="Too big is 413 doc_too_large (with max_bytes), over your quota 413 quota_exceeded (with "
//         "quota_bytes).",
// )
func ( handlers *Handlers ) setDoc( c fiber.Ctx , in *setDocRequest ) ( reply *docMeta , err error ) {
	refused := in.check()
	var body []byte
	if refused == nil { body , refused = envelope( in.Body ) }
	if refused == nil { refused = handlers.checkScope( c , in.Collection , true ) }
	if refused == nil && docScope( c ) != nil && body[ 0 ] != docstore.EnvelopeCollection {
		refused = refuse( fiber.StatusBadRequest , "a scoped key writes collection envelopes only" )
	}
	if refused != nil {
		err = refused
		return
	}
	limits := handlers.docLimits()
	limits.NoAutoCreate = docScope( c ) != nil
	doc , set_err := handlers.Docs.Set( docOwner( c ) , in.Collection , in.DocID , body , in.IfVersion , limits )
	if set_err != nil {
		err = handlers.docRefusal( set_err )
		return
	}
	meta := newDocMeta( doc )
	reply = &meta
	return
}

type deleteDocRequest struct {
	docPath
	IfVersion *int64 `json:"if_version,omitempty" jsonschema:"minimum=1" jsonschema_description:"Delete only if the document is at this version. Absent: unconditional." error:"if_version must be 1 or more"`
}

// deleteDoc deletes a document, leaving a tombstone syncing clients see.
// Writing it again with if_version 0 brings it back, which is the undo.
//
// @route("POST /api/collections/{collection}/docs/{doc_id}/delete", summary="Delete a document",
//     tag="Documents", errors=(404, 409),
//     description="Leaves a tombstone that GET /api/changes reports for docs.tombstone_days. Writing the "
//         "document again with if_version 0 brings it back.",
// )
func ( handlers *Handlers ) deleteDoc( c fiber.Ctx , in *deleteDocRequest ) ( reply *docChange , err error ) {
	refused := in.check()
	if refused == nil { refused = handlers.checkScope( c , in.Collection , true ) }
	if refused != nil {
		err = refused
		return
	}
	doc , delete_err := handlers.Docs.Delete( docOwner( c ) , in.Collection , in.DocID , in.IfVersion )
	if delete_err != nil {
		err = handlers.docRefusal( delete_err )
		return
	}
	change := newDocChange( doc , true )
	reply = &change
	return
}

type moveDocRequest struct {
	docPath
	ToCollection string `json:"to_collection" jsonschema:"minLength=1,maxLength=64" jsonschema_description:"The destination collection's id. It must exist." error:"to_collection must be 1-64 of A-Z a-z 0-9 _ -"`
	ToID         string `json:"to_id,omitempty" jsonschema:"maxLength=128" jsonschema_description:"The document's id there. Default: the same id." error:"to_id must be 1-128 of A-Z a-z 0-9 _ - ."`
	Body         string `json:"body" jsonschema_description:"Standard base64 of the document's private or collection envelope, sealed for to_collection and to_id. See README.md." error:"body must be a base64 private or collection envelope (see README.md); the server stores ciphertext only"`
	IfVersion    *int64 `json:"if_version,omitempty" jsonschema:"minimum=1" jsonschema_description:"Move only if the source is at this version." error:"if_version must be 1 or more"`
}

type moveDocReply struct {
	Doc     docMeta   `json:"doc" jsonschema_description:"The document in its new place."`
	Deleted docChange `json:"deleted" jsonschema_description:"The tombstone left where it was."`
}

// moveDoc moves a document to another folder (or id) in one step. The body
// is the document sealed again by the client for its new place, since the
// old ciphertext is bound to the old one. if_version is the source's.
//
// @route("POST /api/collections/{collection}/docs/{doc_id}/move", summary="Move a document to another collection",
//     tag="Documents", errors=(404, 409, 413),
//     description="In one step: the document is written at to_collection/to_id and the old one becomes a "
//         "tombstone. A document's ciphertext is bound to its collection and id, so the client opens it and "
//         "seals it again for the new place, and sends that as body. 409 version_conflict: the source is not at "
//         "if_version, or a live document is already at the destination. 404: no such document, or no such "
//         "destination collection.",
// )
func ( handlers *Handlers ) moveDoc( c fiber.Ctx , in *moveDocRequest ) ( reply *moveDocReply , err error ) {
	to_id := in.ToID
	if to_id == "" { to_id = in.DocID }
	refused := in.check()
	if refused == nil && docstore.ValidCollection( in.ToCollection ) == false {
		refused = refuse( fiber.StatusBadRequest , "to_collection must be 1-64 of A-Z a-z 0-9 _ -" )
	}
	if refused == nil && docstore.ValidDocID( to_id ) == false {
		refused = refuse( fiber.StatusBadRequest , "to_id must be 1-128 of A-Z a-z 0-9 _ - ." )
	}
	var body []byte
	if refused == nil { body , refused = envelope( in.Body ) }
	for _ , place := range []string{ in.Collection , in.ToCollection } {
		if refused == nil { refused = handlers.checkScope( c , place , true ) }
	}
	if refused == nil && docScope( c ) != nil && body[ 0 ] != docstore.EnvelopeCollection {
		refused = refuse( fiber.StatusBadRequest , "a scoped key writes collection envelopes only" )
	}
	if refused != nil {
		err = refused
		return
	}
	moved , gone , move_err := handlers.Docs.MoveDoc( docOwner( c ) , in.Collection , in.DocID , in.ToCollection , to_id , body , in.IfVersion , handlers.docLimits() )
	if move_err != nil {
		err = handlers.docRefusal( move_err )
		return
	}
	reply = &moveDocReply{ Doc: newDocMeta( moved ) , Deleted: newDocChange( gone , true ) }
	return
}

type listChangesRequest struct {
	Since int64 `json:"since,omitempty" query:"since" jsonschema:"minimum=0" jsonschema_description:"The next_since of your last call. Default 0: everything." error:"since must be 0 or more"`
	Limit int   `json:"limit,omitempty" query:"limit" jsonschema:"minimum=1,maximum=1000,default=200" jsonschema_description:"Changes to return. Default 200." error:"limit must be 1-1000"`
}

type listChangesReply struct {
	Changes   []docChange `json:"changes"`
	NextSince int64       `json:"next_since" jsonschema_description:"Pass as since next time."`
	More      bool        `json:"more" jsonschema_description:"Another page is waiting."`
}

// listChanges is the sync feed: everything in the caller's account that
// changed after ?since=, oldest first, deletes included, without bodies.
// Keep calling with next_since while more is true.
//
// @route("GET /api/changes", summary="What changed since you last synced", tag="Documents", errors=(410,),
//     description="Every write and delete in your account after change number since, oldest first, without "
//         "bodies. Start from 0, keep calling with next_since while more is true, and save next_since for next "
//         "time. 410 sync_expired: deletes you never saw have been purged; start again from 0.",
// )
func ( handlers *Handlers ) listChanges( c fiber.Ctx , in *listChangesRequest ) ( reply *listChangesReply , err error ) {
	limit := in.Limit
	if limit == 0 { limit = pageDefault }
	root := ""
	if scope := docScope( c ); scope != nil {
		if refused := handlers.checkScopeRoot( c ); refused != nil {
			err = refused
			return
		}
		root = scope.Collection
	}
	changes , more , changes_err := handlers.Docs.ChangesIn( docOwner( c ) , root , in.Since , limit )
	if changes_err != nil {
		err = handlers.docRefusal( changes_err )
		return
	}
	rows := make( []docChange , 0 , len( changes ) )
	next_since := in.Since
	for _ , doc := range changes {
		rows = append( rows , newDocChange( doc , doc.Deleted ) )
		next_since = doc.Seq
	}
	reply = &listChangesReply{ Changes: rows , NextSince: next_since , More: more }
	return
}

type keyringReply struct {
	Keyring   string    `json:"keyring" jsonschema_description:"JSON text; see README.md, Keyring."`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// getKeyring is the caller's wrapped master key, for unlocking with a
// passphrase. It is useless without the passphrase; see README.md. Only a
// browser session reaches it: an API key that was never given the master key
// must not be able to take the keyring away and guess the passphrase offline,
// and services hold the raw key instead.
//
// @route("GET /api/keyring", summary="Your wrapped master key", tag="Documents", errors=(404,), access=SESSION_ONLY,
//     description="The master key sealed under a key derived from your passphrase (Argon2id), stored as the "
//         "client wrote it. Useless without the passphrase. 404 when no passphrase has been set.",
// )
func ( handlers *Handlers ) getKeyring( c fiber.Ctx , in *apidoc.None ) ( reply *keyringReply , err error ) {
	keyring , err := handlers.Docs.GetKeyring( docOwner( c ) )
	if errors.Is( err , docstore.ErrNotFound ) {
		err = refuse( fiber.StatusNotFound , "no keyring" )
		return
	}
	if err != nil { return }
	reply = &keyringReply{ Keyring: keyring.Body , Version: keyring.Version , UpdatedAt: keyring.UpdatedAt }
	return
}

type setKeyringRequest struct {
	Keyring   string `json:"keyring" jsonschema:"minLength=1,maxLength=4096" jsonschema_description:"JSON text; see README.md, Keyring." error:"keyring must be 1-4096 bytes"`
	IfVersion *int64 `json:"if_version,omitempty" jsonschema:"minimum=0" jsonschema_description:"0: only if none is set yet. n: only if the stored one is at n." error:"if_version must be 0 or more"`
}

type setKeyringReply struct {
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
}

// setKeyring stores a new wrapped master key: a passphrase set or changed.
// Browser sessions only, like getKeyring, so an API key cannot replace it
// and lock the owner's passphrase out.
//
// @route("POST /api/keyring", summary="Set or change your passphrase", tag="Documents", errors=(409,), access=SESSION_ONLY,
//     description="Stores a new wrapped master key. Documents are not re-encrypted: they stay under the same "
//         "master key.",
// )
func ( handlers *Handlers ) setKeyring( c fiber.Ctx , in *setKeyringRequest ) ( reply *setKeyringReply , err error ) {
	keyring , set_err := handlers.Docs.SetKeyring( docOwner( c ) , in.Keyring , in.IfVersion )
	if errors.Is( set_err , docstore.ErrTooLarge ) {
		err = refuse( fiber.StatusBadRequest , "keyring must be 1-" + strconv.Itoa( docstore.KeyringMaxBytes ) + " bytes" )
		return
	}
	if set_err != nil {
		err = handlers.docRefusal( set_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "keyring set" , fiber.Map{ "version": keyring.Version } )
	reply = &setKeyringReply{ Version: keyring.Version , UpdatedAt: keyring.UpdatedAt }
	return
}
