package routes

import (
	rand "crypto/rand"
	base64 "encoding/base64"
	errors "errors"
	strconv "strconv"

	fiber "github.com/gofiber/fiber/v3"

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

// docRow is one document's metadata, and its body when asked for.
func docRow( doc docstore.Doc , with_body bool ) ( row fiber.Map ) {
	row = fiber.Map{
		"collection": doc.Collection,
		"id":         doc.ID,
		"version":    doc.Version,
		"seq":        doc.Seq,
		"updated_at": doc.UpdatedAt,
		"size":       doc.Size,
	}
	if with_body {
		row[ "body" ] = base64.StdEncoding.EncodeToString( doc.Body )
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
	case scope.Born != 0 && entry.Born != scope.Born:
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

// docAddress is the collection and id in the path, checked.
func docAddress( c fiber.Ctx , with_id bool ) ( collection string , id string , refused *refusal ) {
	collection = c.Params( "collection" )
	if docstore.ValidCollection( collection ) == false {
		refused = refuse( fiber.StatusBadRequest , "collection must be 1-64 of A-Z a-z 0-9 _ -" )
		return
	}
	if with_id {
		id = c.Params( "doc_id" )
		if docstore.ValidDocID( id ) == false {
			refused = refuse( fiber.StatusBadRequest , "id must be 1-128 of A-Z a-z 0-9 _ - ." )
		}
	}
	return
}

// pageQuery reads ?limit= and ?offset= the way sendPage does, for lists the
// database pages itself rather than reading whole.
func pageQuery( c fiber.Ctx ) ( limit int , offset int , refused *refusal ) {
	limit = pageDefault
	if raw := c.Query( "limit" ); raw != "" {
		parsed , err := strconv.Atoi( raw )
		if err != nil || parsed < 1 || parsed > pageMax {
			refused = refuse( fiber.StatusBadRequest , pageLimitMessage )
			return
		}
		limit = parsed
	}
	if raw := c.Query( "offset" ); raw != "" {
		parsed , err := strconv.Atoi( raw )
		if err != nil || parsed < 0 {
			refused = refuse( fiber.StatusBadRequest , pageOffsetMessage )
			return
		}
		offset = parsed
	}
	return
}

// next is the offset of the page after this one, or nil on the last.
func next( offset int , count int , total int ) ( result any ) {
	if offset + count < total {
		result = offset + count
	}
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
func collectionRow( entry docstore.Collection , with_counts bool ) ( row fiber.Map ) {
	row = fiber.Map{
		"id":         entry.ID,
		"name":       entry.Name,
		"parent":     entry.Parent,
		"position":   entry.Position,
		"version":    entry.Version,
		"updated_at": entry.UpdatedAt,
	}
	if entry.Lock != "" {
		row[ "lock" ] = entry.Lock
	}
	if entry.ByKey != "" {
		// Made through someone's access key: a client writing by id can
		// refuse to put the account's own documents there.
		row[ "by_key" ] = entry.ByKey
	}
	if with_counts {
		row[ "count" ] = entry.Count
		row[ "bytes" ] = entry.Bytes
	}
	return
}

// ListCollections is the caller's folders, each parent's children together
// in their order, with what the documents use against the quota.
func ( handlers *Handlers ) ListCollections( c fiber.Ctx ) ( err error ) {
	limit , offset , refused := pageQuery( c )
	if refused != nil {
		err = refused.send( c )
		return
	}
	owner := docOwner( c )
	var collections []docstore.Collection
	var total , count int
	var used int64
	if scope := docScope( c ); scope != nil {
		if refused := handlers.checkScopeRoot( c ); refused != nil {
			err = refused.send( c )
			return
		}
		collections , total , used , count , err = handlers.scopedCollections( owner , scope.Collection , offset , limit )
		if err != nil {
			err = serverError( c , err )
			return
		}
	} else {
		var list_err , usage_err error
		collections , total , list_err = handlers.Docs.Collections( owner , offset , limit )
		if list_err != nil {
			err = serverError( c , list_err )
			return
		}
		used , count , usage_err = handlers.Docs.Usage( owner )
		if usage_err != nil {
			err = serverError( c , usage_err )
			return
		}
	}
	tree_seq , seq_err := handlers.Docs.TreeSeq( owner )
	if seq_err != nil {
		err = serverError( c , seq_err )
		return
	}
	rows := make( []fiber.Map , 0 , len( collections ) )
	for _ , entry := range collections {
		rows = append( rows , collectionRow( entry , true ) )
	}
	limits := handlers.docLimits()
	err = c.JSON( fiber.Map{
		"collections":     rows,
		"next":            next( offset , len( rows ) , total ),
		"total":           total,
		"tree_seq":        tree_seq,
		"used_bytes":      used,
		"doc_count":       count,
		"quota_bytes":     limits.QuotaBytes,
		"max_doc_bytes":   limits.MaxDocBytes,
		"max_collections": limits.MaxCollections,
		"max_depth":       limits.MaxDepth,
	} )
	return
}

// scopedCollections is ListCollections for a scoped key: root and the
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

type collectionRequest struct {
	ID        string  `json:"id"`
	Name      *string `json:"name"`
	Parent    *string `json:"parent"`
	Before    *string `json:"before"`
	IfVersion *int64  `json:"if_version"`
	Lock      *string `json:"lock"`
	CSRFToken string  `json:"csrf_token"`
}

// change is the request checked and turned into what the store takes.
func ( request collectionRequest ) change() ( change docstore.CollectionChange , refused *refusal ) {
	if request.Name != nil && docstore.ValidCollectionName( *request.Name ) == false {
		refused = refuse( fiber.StatusBadRequest , "name must be 1-" + strconv.Itoa( docstore.CollectionNameMax ) + " characters, with no control characters and no space at either end" )
		return
	}
	for _ , other := range []*string{ request.Parent , request.Before } {
		if other != nil && *other != "" && docstore.ValidCollection( *other ) == false {
			refused = refuse( fiber.StatusBadRequest , "parent and before must be \"\" or a collection id" )
			return
		}
	}
	if request.IfVersion != nil && *request.IfVersion < 1 {
		refused = refuse( fiber.StatusBadRequest , "if_version must be 1 or more" )
		return
	}
	if request.Lock != nil && ( *request.Lock == "" || len( *request.Lock ) > docstore.LockMaxBytes ) {
		refused = refuse( fiber.StatusBadRequest , "lock must be 1-" + strconv.Itoa( docstore.LockMaxBytes ) + " bytes" )
		return
	}
	change = docstore.CollectionChange{ Name: request.Name , Parent: request.Parent , Before: request.Before , IfVersion: request.IfVersion , Lock: request.Lock }
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

// readCollectionRequest binds and checks a folder write's body.
func ( handlers *Handlers ) readCollectionRequest( c fiber.Ctx ) ( request collectionRequest , change docstore.CollectionChange , done bool , err error ) {
	if c.Bind().JSON( &request ) != nil {
		err = badRequest( c , "malformed request body" )
		done = true
		return
	}
	if handlers.Guard.CheckCSRF( c , request.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		done = true
		return
	}
	change , refused := request.change()
	if refused != nil {
		err = refused.send( c )
		done = true
	}
	return
}

// CreateCollection makes a folder. id is optional (random when left out);
// name defaults to the id, parent to the top level, and the folder goes in
// front of before, or at the end.
func ( handlers *Handlers ) CreateCollection( c fiber.Ctx ) ( err error ) {
	request , change , done , err := handlers.readCollectionRequest( c )
	if done { return }
	id := request.ID
	if id == "" {
		id = newCollectionID()
	} else if docstore.ValidCollection( id ) == false {
		err = badRequest( c , "id must be 1-64 of A-Z a-z 0-9 _ -" )
		return
	}
	if docScope( c ) != nil {
		// A scoped key makes folders only inside its own, and only with a
		// random id: one it chose ("invoices") could be an id the account's
		// own code later writes to by name, sealing those documents with keys
		// the key's holder has.
		if request.ID != "" && docstore.ValidRandomID( request.ID ) == false {
			err = badRequest( c , "a scoped key's folder id must be a random 22-character id (client.NewID)" )
			return
		}
		parent := ""
		if change.Parent != nil { parent = *change.Parent }
		if refused := handlers.checkScope( c , parent , true ); refused != nil {
			err = refused.send( c )
			return
		}
		change.ByKey = security.APIKeyFrom( c ).ID
	}
	entry , create_err := handlers.Docs.CreateCollection( docOwner( c ) , id , change , handlers.docLimits() )
	if create_err != nil {
		err = handlers.docRefusal( create_err ).send( c )
		return
	}
	err = c.JSON( collectionRow( entry , false ) )
	return
}

// UpdateCollection renames, moves or reorders a folder: name, parent and
// before, each optional. Its documents stay as they are.
func ( handlers *Handlers ) UpdateCollection( c fiber.Ctx ) ( err error ) {
	_ , change , done , err := handlers.readCollectionRequest( c )
	if done { return }
	id , _ , refused := docAddress( c , false )
	if refused != nil {
		err = refused.send( c )
		return
	}
	if refused = handlers.checkScope( c , id , true ); refused != nil {
		err = refused.send( c )
		return
	}
	if scope := docScope( c ); scope != nil && ( change.Parent != nil || change.Before != nil ) {
		// The folder a key is for stays where it is; others move only
		// within it.
		if id == scope.Collection {
			err = forbidden( c , "a scoped key cannot move the collection it is for" )
			return
		}
		if change.Parent != nil {
			if refused = handlers.checkScope( c , *change.Parent , true ); refused != nil {
				err = refused.send( c )
				return
			}
		}
	}
	entry , update_err := handlers.Docs.UpdateCollection( docOwner( c ) , id , change , handlers.docLimits() )
	if update_err != nil {
		err = handlers.docRefusal( update_err ).send( c )
		return
	}
	err = c.JSON( collectionRow( entry , false ) )
	return
}

// DeleteCollection removes a folder, the folders under it and every document
// in them, each document leaving a tombstone the change feed reports.
func ( handlers *Handlers ) DeleteCollection( c fiber.Ctx ) ( err error ) {
	var request deleteDocRequest
	if c.Bind().JSON( &request ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , request.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	id , _ , refused := docAddress( c , false )
	if refused != nil {
		err = refused.send( c )
		return
	}
	if refused = handlers.checkScope( c , id , true ); refused != nil {
		err = refused.send( c )
		return
	}
	if scope := docScope( c ); scope != nil && id == scope.Collection {
		err = forbidden( c , "a scoped key cannot delete the collection it is for" )
		return
	}
	deleted , delete_err := handlers.Docs.DeleteCollection( docOwner( c ) , id , request.IfVersion )
	if delete_err != nil {
		err = handlers.docRefusal( delete_err ).send( c )
		return
	}
	// The access keys for a folder that is gone go with it, so one can never
	// reach a later folder that reuses the id.
	revoked , revoke_err := models.RevokeScopedKeys( handlers.Store , docOwner( c ) , deleted.Collections )
	for _ , key_id := range revoked {
		handlers.audit( c , logs.KindAdmin , "api key revoked: its collection was deleted" , fiber.Map{ "key_id": key_id , "collection": id } )
	}
	if revoke_err != nil {
		err = serverError( c , revoke_err )
		return
	}
	rows := make( []fiber.Map , 0 , len( deleted.Docs ) )
	for _ , doc := range deleted.Docs {
		row := docRow( doc , false )
		row[ "deleted" ] = true
		rows = append( rows , row )
	}
	err = c.JSON( fiber.Map{ "collections": deleted.Collections , "docs": rows } )
	return
}

// ListDocs is one page of a collection's documents, by id. ?include_body=true
// adds each one's ciphertext, so a client can fetch a collection in pages
// rather than one document at a time.
func ( handlers *Handlers ) ListDocs( c fiber.Ctx ) ( err error ) {
	collection , _ , refused := docAddress( c , false )
	if refused == nil {
		refused = handlers.checkScope( c , collection , false )
	}
	if refused == nil {
		var limit , offset int
		limit , offset , refused = pageQuery( c )
		if refused == nil {
			with_bodies := c.Query( "include_body" ) == "true"
			docs , total , list_err := handlers.Docs.List( docOwner( c ) , collection , offset , limit , with_bodies )
			if list_err != nil {
				err = serverError( c , list_err )
				return
			}
			rows := make( []fiber.Map , 0 , len( docs ) )
			for _ , doc := range docs {
				rows = append( rows , docRow( doc , with_bodies ) )
			}
			err = c.JSON( fiber.Map{ "docs": rows , "next": next( offset , len( rows ) , total ) , "total": total } )
			return
		}
	}
	err = refused.send( c )
	return
}

// GetDoc is one document with its ciphertext.
func ( handlers *Handlers ) GetDoc( c fiber.Ctx ) ( err error ) {
	collection , id , refused := docAddress( c , true )
	if refused != nil {
		err = refused.send( c )
		return
	}
	if refused = handlers.checkScope( c , collection , false ); refused != nil {
		err = refused.send( c )
		return
	}
	doc , get_err := handlers.Docs.Get( docOwner( c ) , collection , id )
	if get_err != nil {
		err = handlers.docRefusal( get_err ).send( c )
		return
	}
	err = c.JSON( docRow( doc , true ) )
	return
}

type setDocRequest struct {
	Body      string `json:"body"`
	IfVersion *int64 `json:"if_version"`
	CSRFToken string `json:"csrf_token"`
}

type deleteDocRequest struct {
	IfVersion *int64 `json:"if_version"`
	CSRFToken string `json:"csrf_token"`
}

// SetDoc creates or replaces a document. if_version makes it conditional:
// 0 only if there is no live document, n only if the live one is at n.
func ( handlers *Handlers ) SetDoc( c fiber.Ctx ) ( err error ) {
	var request setDocRequest
	if c.Bind().JSON( &request ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , request.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	collection , id , refused := docAddress( c , true )
	if refused != nil {
		err = refused.send( c )
		return
	}
	if request.IfVersion != nil && *request.IfVersion < 0 {
		err = badRequest( c , "if_version must be 0 or more" )
		return
	}
	body , decode_err := base64.StdEncoding.DecodeString( request.Body )
	if decode_err != nil || docstore.ValidEnvelope( body ) == false {
		err = badRequest( c , "body must be a base64 v1 or v2 envelope (see README.md); the server stores ciphertext only" )
		return
	}
	if refused = handlers.checkScope( c , collection , true ); refused != nil {
		err = refused.send( c )
		return
	}
	if docScope( c ) != nil && body[ 0 ] != docstore.EnvelopeV2 {
		err = badRequest( c , "a scoped key writes v2 envelopes only" )
		return
	}
	doc , set_err := handlers.Docs.Set( docOwner( c ) , collection , id , body , request.IfVersion , handlers.docLimits() )
	if set_err != nil {
		err = handlers.docRefusal( set_err ).send( c )
		return
	}
	err = c.JSON( docRow( doc , false ) )
	return
}

// DeleteDoc deletes a document, leaving a tombstone syncing clients see.
// Writing it again with if_version 0 brings it back, which is the undo.
func ( handlers *Handlers ) DeleteDoc( c fiber.Ctx ) ( err error ) {
	var request deleteDocRequest
	if c.Bind().JSON( &request ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , request.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	collection , id , refused := docAddress( c , true )
	if refused != nil {
		err = refused.send( c )
		return
	}
	if refused = handlers.checkScope( c , collection , true ); refused != nil {
		err = refused.send( c )
		return
	}
	doc , delete_err := handlers.Docs.Delete( docOwner( c ) , collection , id , request.IfVersion )
	if delete_err != nil {
		err = handlers.docRefusal( delete_err ).send( c )
		return
	}
	row := docRow( doc , false )
	row[ "deleted" ] = true
	err = c.JSON( row )
	return
}

type moveDocRequest struct {
	ToCollection string `json:"to_collection"`
	ToID         string `json:"to_id"`
	Body         string `json:"body"`
	IfVersion    *int64 `json:"if_version"`
	CSRFToken    string `json:"csrf_token"`
}

// MoveDoc moves a document to another folder (or id) in one step. The body
// is the document sealed again by the client for its new place, since the
// old ciphertext is bound to the old one. if_version is the source's.
func ( handlers *Handlers ) MoveDoc( c fiber.Ctx ) ( err error ) {
	var request moveDocRequest
	if c.Bind().JSON( &request ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , request.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	collection , id , refused := docAddress( c , true )
	if refused != nil {
		err = refused.send( c )
		return
	}
	to_id := request.ToID
	if to_id == "" { to_id = id }
	if docstore.ValidCollection( request.ToCollection ) == false {
		err = badRequest( c , "to_collection must be 1-64 of A-Z a-z 0-9 _ -" )
		return
	}
	if docstore.ValidDocID( to_id ) == false {
		err = badRequest( c , "to_id must be 1-128 of A-Z a-z 0-9 _ - ." )
		return
	}
	if request.IfVersion != nil && *request.IfVersion < 1 {
		err = badRequest( c , "if_version must be 1 or more" )
		return
	}
	body , decode_err := base64.StdEncoding.DecodeString( request.Body )
	if decode_err != nil || docstore.ValidEnvelope( body ) == false {
		err = badRequest( c , "body must be a base64 v1 or v2 envelope (see README.md); the server stores ciphertext only" )
		return
	}
	for _ , place := range []string{ collection , request.ToCollection } {
		if refused = handlers.checkScope( c , place , true ); refused != nil {
			err = refused.send( c )
			return
		}
	}
	if docScope( c ) != nil && body[ 0 ] != docstore.EnvelopeV2 {
		err = badRequest( c , "a scoped key writes v2 envelopes only" )
		return
	}
	moved , gone , move_err := handlers.Docs.MoveDoc( docOwner( c ) , collection , id , request.ToCollection , to_id , body , request.IfVersion , handlers.docLimits() )
	if move_err != nil {
		err = handlers.docRefusal( move_err ).send( c )
		return
	}
	deleted := docRow( gone , false )
	deleted[ "deleted" ] = true
	err = c.JSON( fiber.Map{ "doc": docRow( moved , false ) , "deleted": deleted } )
	return
}

// ListChanges is the sync feed: everything in the caller's account that
// changed after ?since=, oldest first, deletes included, without bodies.
// Keep calling with next_since while more is true.
func ( handlers *Handlers ) ListChanges( c fiber.Ctx ) ( err error ) {
	limit , _ , refused := pageQuery( c )
	if refused != nil {
		err = refused.send( c )
		return
	}
	var since int64
	if raw := c.Query( "since" ); raw != "" {
		parsed , parse_err := strconv.ParseInt( raw , 10 , 64 )
		if parse_err != nil || parsed < 0 {
			err = badRequest( c , "since must be 0 or more" )
			return
		}
		since = parsed
	}
	root := ""
	if scope := docScope( c ); scope != nil {
		if refused = handlers.checkScopeRoot( c ); refused != nil {
			err = refused.send( c )
			return
		}
		root = scope.Collection
	}
	changes , more , changes_err := handlers.Docs.ChangesIn( docOwner( c ) , root , since , limit )
	if changes_err != nil {
		err = handlers.docRefusal( changes_err ).send( c )
		return
	}
	rows := make( []fiber.Map , 0 , len( changes ) )
	next_since := since
	for _ , doc := range changes {
		row := docRow( doc , false )
		row[ "deleted" ] = doc.Deleted
		rows = append( rows , row )
		next_since = doc.Seq
	}
	err = c.JSON( fiber.Map{ "changes": rows , "next_since": next_since , "more": more } )
	return
}

// GetKeyring is the caller's wrapped master key, for unlocking with a
// passphrase. It is useless without the passphrase; see README.md.
func ( handlers *Handlers ) GetKeyring( c fiber.Ctx ) ( err error ) {
	keyring , get_err := handlers.Docs.GetKeyring( docOwner( c ) )
	if errors.Is( get_err , docstore.ErrNotFound ) {
		err = notFound( c , "no keyring" )
		return
	}
	if get_err != nil {
		err = serverError( c , get_err )
		return
	}
	err = c.JSON( fiber.Map{ "keyring": keyring.Body , "version": keyring.Version , "updated_at": keyring.UpdatedAt } )
	return
}

type setKeyringRequest struct {
	Keyring   string `json:"keyring"`
	IfVersion *int64 `json:"if_version"`
	CSRFToken string `json:"csrf_token"`
}

// SetKeyring stores a new wrapped master key: a passphrase set or changed.
func ( handlers *Handlers ) SetKeyring( c fiber.Ctx ) ( err error ) {
	var request setKeyringRequest
	if c.Bind().JSON( &request ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , request.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	if request.IfVersion != nil && *request.IfVersion < 0 {
		err = badRequest( c , "if_version must be 0 or more" )
		return
	}
	keyring , set_err := handlers.Docs.SetKeyring( docOwner( c ) , request.Keyring , request.IfVersion )
	if errors.Is( set_err , docstore.ErrTooLarge ) {
		err = badRequest( c , "keyring must be 1-" + strconv.Itoa( docstore.KeyringMaxBytes ) + " bytes" )
		return
	}
	if set_err != nil {
		err = handlers.docRefusal( set_err ).send( c )
		return
	}
	handlers.audit( c , logs.KindAuth , "keyring set" , fiber.Map{ "version": keyring.Version } )
	err = c.JSON( fiber.Map{ "version": keyring.Version , "updated_at": keyring.UpdatedAt } )
	return
}
