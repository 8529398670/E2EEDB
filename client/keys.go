package client

// Finding a collection's keys: its lockbox is wrapped by its parent's keys,
// or by the master key at the top level, so the client opens lockboxes from
// the top (or from a scoped client's own collection) down to the one it
// needs, and keeps what it opened. A move only re-wraps a lockbox, so the
// keys stay; a rotation (RotateKeys) replaces them, and the cache is dropped
// and filled again when the server says a write used old keys (stale_key)
// or a document names keys the cache does not hold.
//
// While a rotation is under way a collection has two lockboxes: lock (the
// keys it had) and next_lock (the new ones, wrapped for its parent's new
// keys, or for its parent's keys when only it and those under it are being
// rotated). Documents may be sealed with either until it is done; writes use
// the new ones.

import (
	context "context"
	errors "errors"
	fmt "fmt"
	http "net/http"
	url "net/url"
	strconv "strconv"
)

var (
	// errNoMaster: what was asked needs the master key, and this client
	// holds only one collection's keys.
	errNoMaster = errors.New( "e2eedb: this needs the master key, not an access token" )
	// errOutOfScope: the collection is not the scoped client's or under it.
	errOutOfScope = &APIError{ Status: http.StatusNotFound , Message: "no such collection" }
)

func ( client *Client ) cached( collection string ) ( key *CollectionKey ) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	key = client.keys[ collection ]
	return
}

// cachedNext is collection's new keys, mid-rotation, if opened already.
func ( client *Client ) cachedNext( collection string ) ( key *CollectionKey ) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	key = client.next[ collection ]
	return
}

// rememberNext keeps collection's new keys, opened from lock.
func ( client *Client ) rememberNext( key *CollectionKey , lock string ) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	client.next[ key.collection ] = key
	client.owned[ key.collection ] = client.key != nil && client.key.owns( lock , key.collection )
}

// forget drops every key opened from a lockbox, for when they may have been
// rotated. A scoped client keeps its own collection's, which came with its
// token.
func ( client *Client ) forget() {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	client.keys = map[ string ]*CollectionKey{}
	client.next = map[ string ]*CollectionKey{}
	client.owned = map[ string ]bool{}
	if client.scope != nil {
		client.keys[ client.scope.collection ] = client.scope
	}
}

// isOwned is whether collection's lockbox, when its keys were opened, held
// this client's owner tag (Key.ownTag).
func ( client *Client ) isOwned( collection string ) bool {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return client.owned[ collection ]
}

// remember keeps key, and whether the master key made it.
func ( client *Client ) remember( key *CollectionKey , owned bool ) {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	client.keys[ key.collection ] = key
	client.owned[ key.collection ] = owned
}

// ownTag is the owner tag for key, "" for a scoped client.
func ( client *Client ) ownTag( key *CollectionKey ) string {
	if client.key == nil { return "" }
	return client.key.ownTag( key.collection , key.id[ : ] )
}

// rememberLock keeps key, opened from lock: owned if lock holds this
// client's tag.
func ( client *Client ) rememberLock( key *CollectionKey , lock string ) {
	client.remember( key , client.key != nil && client.key.owns( lock , key.collection ) )
}

// tree is every collection this client can see, by id.
func ( client *Client ) tree( ctx context.Context ) ( tree map[ string ]Collection , err error ) {
	collections , err := client.Collections( ctx )
	if err != nil { return }
	tree = make( map[ string ]Collection , len( collections ) )
	for _ , entry := range collections {
		tree[ entry.ID ] = entry
	}
	// Keys are found by walking up the parents, so a dishonest server's
	// cycle (A in B in A) would recurse until the stack runs out. Every
	// walk must leave the tree (the top level, or a scoped key's root)
	// within as many steps as there are folders.
	for id := range tree {
		steps := 0
		for at := id ; ; steps++ {
			entry , found := tree[ at ]
			if found == false { break }
			if steps > len( tree ) {
				tree , err = nil , fmt.Errorf( "%w: collection %s is inside itself" , ErrCorrupt , id )
				return
			}
			at = entry.Parent
		}
	}
	return
}

// CollectionKey is collection's keys, opened from its lockbox. With create,
// a collection without keys yet gets them, which needs write access to its
// parent; and one that does not exist yet is made at the top level, which
// needs the master key. Without create, a collection with no keys is
// ErrCorrupt (nothing in it can be a collection envelope).
func ( client *Client ) CollectionKey( ctx context.Context , collection string , create bool ) ( key *CollectionKey , err error ) {
	if key = client.cached( collection ); key != nil { return }
	tree , err := client.tree( ctx )
	if err != nil { return }
	key , err = client.resolve( ctx , tree , collection , create )
	return
}

// resolve is CollectionKey with the tree in hand.
func ( client *Client ) resolve( ctx context.Context , tree map[ string ]Collection , id string , create bool ) ( key *CollectionKey , err error ) {
	if key = client.cached( id ); key != nil { return }
	entry , found := tree[ id ]
	if found == false {
		if create == false || client.key == nil {
			err = errOutOfScope
			return
		}
		key , err = client.createTopLevel( ctx , id )
		return
	}
	if entry.Lock == "" && entry.NextLock != "" {
		// Given its first keys by a rotation: they are its new ones.
		err = ErrRotating
		return
	}
	holder , err := client.holder( ctx , tree , entry.Parent , create )
	if err != nil { return }
	if entry.Lock != "" {
		if key , err = openLock( entry.Lock , id , holder ); err == nil {
			client.rememberLock( key , entry.Lock )
		}
		return
	}
	if create == false {
		err = fmt.Errorf( "%w: collection %s has no keys yet" , ErrCorrupt , id )
		return
	}
	if key , err = generateCollectionKey( id ); err != nil { return }
	// Fresh keys for a folder someone else made: the master key tags them
	// only at the top level, where it alone holds them. Under a parent, the
	// folder could be anyone's who holds the parent's keys (a sharee's, put
	// there with no lockbox by a server), so it stays untagged.
	own := ""
	if entry.Parent == "" { own = client.ownTag( key ) }
	lock , err := sealLock( key , holder , own )
	if err != nil { return }
	err = client.call( ctx , http.MethodPost , collectionPath( id ) , map[string]any{ "lock": lock } , nil )
	var refused *APIError
	if errors.As( err , &refused ) && refused.Message == "lock_exists" {
		// Someone else gave it keys first: use theirs.
		if tree , err = client.tree( ctx ); err != nil { return }
		entry = tree[ id ]
		if entry.Lock == "" {
			err = fmt.Errorf( "%w: collection %s lost its keys" , ErrCorrupt , id )
			return
		}
		lock = entry.Lock
		key , err = openLock( lock , id , holder )
	}
	if err == nil {
		client.rememberLock( key , lock )
	}
	return
}

// resolveNext is id's new keys while a rotation is under way, nil when id
// has none (or is not in tree). They are wrapped for the parent's new keys when the parent is
// being rotated too, else for its keys (or the master key's).
func ( client *Client ) resolveNext( ctx context.Context , tree map[ string ]Collection , id string ) ( key *CollectionKey , err error ) {
	if key = client.cachedNext( id ); key != nil { return }
	entry , found := tree[ id ]
	if found == false || entry.NextLock == "" { return }
	var holder lockHolder
	if parent , inside := tree[ entry.Parent ]; inside && parent.NextLock != "" {
		next , next_err := client.resolveNext( ctx , tree , entry.Parent )
		if next_err != nil { return nil , next_err }
		holder = next
	} else if holder , err = client.holder( ctx , tree , entry.Parent , false ); err != nil {
		return
	}
	if key , err = openLock( entry.NextLock , id , holder ); err == nil {
		client.rememberNext( key , entry.NextLock )
	}
	return
}

// sealingKey is what a write to collection seals with: its new keys while a
// rotation is under way, else its keys, given to it now if it has none.
func ( client *Client ) sealingKey( ctx context.Context , collection string ) ( key *CollectionKey , err error ) {
	if key = client.cachedNext( collection ); key != nil { return }
	if key = client.cached( collection ); key != nil { return }
	tree , err := client.tree( ctx )
	if err != nil { return }
	if key , err = client.resolveNext( ctx , tree , collection ); key != nil || err != nil { return }
	key , err = client.resolve( ctx , tree , collection , true )
	return
}

// openingKey is the keys that open a collection envelope in collection: the
// ones it names, old or new. Keys it names that are not cached may have
// been rotated in since, so the cache is filled again once before it is
// ErrWrongKey.
func ( client *Client ) openingKey( ctx context.Context , collection string , envelope []byte ) ( key *CollectionKey , err error ) {
	if len( envelope ) < headerSize { return nil , ErrCorrupt }
	named := string( envelope[ 1:headerSize ] )
	matching := func() *CollectionKey {
		for _ , held := range []*CollectionKey{ client.cachedNext( collection ) , client.cached( collection ) } {
			if held != nil && string( held.id[ : ] ) == named { return held }
		}
		return nil
	}
	if key = matching(); key != nil { return }
	client.forget()
	tree , err := client.tree( ctx )
	if err != nil { return }
	entry , found := tree[ collection ]
	if found == false { return nil , errOutOfScope }
	if _ , err = client.resolveNext( ctx , tree , collection ); err != nil { return }
	switch {
	case entry.Lock != "":
		if _ , err = client.resolve( ctx , tree , collection , false ); err != nil { return }
	case entry.NextLock == "":
		return nil , fmt.Errorf( "%w: collection %s has no keys yet" , ErrCorrupt , collection )
	}
	if key = matching(); key == nil { err = ErrWrongKey }
	return
}

// holder is what wraps a collection under parent: the master key at the top
// level, otherwise parent's keys.
func ( client *Client ) holder( ctx context.Context , tree map[ string ]Collection , parent string , create bool ) ( holder lockHolder , err error ) {
	if parent == "" {
		if client.key == nil {
			err = errOutOfScope
			return
		}
		holder = client.key
		return
	}
	if key := client.cached( parent ); key != nil {
		holder = key
		return
	}
	if tree == nil {
		if tree , err = client.tree( ctx ); err != nil { return }
	}
	key , err := client.resolve( ctx , tree , parent , create )
	if err != nil { return }
	holder = key
	return
}

// createTopLevel makes the top-level collection id with fresh keys, named
// after the id, or "id (2)" and so on when that name is taken.
func ( client *Client ) createTopLevel( ctx context.Context , id string ) ( key *CollectionKey , err error ) {
	if key , err = generateCollectionKey( id ); err != nil { return }
	lock , err := sealLock( key , client.key , client.ownTag( key ) )
	if err != nil { return }
	name := id
	for n := 2 ; ; n++ {
		err = client.call( ctx , http.MethodPost , "/api/collections" , map[string]any{ "id": id , "name": name , "lock": lock } , nil )
		var refused *APIError
		if errors.As( err , &refused ) && refused.Message == "name_taken" && n < 100 {
			name = id + " (" + strconv.Itoa( n ) + ")"
			continue
		}
		break
	}
	if errors.Is( err , ErrConflict ) {
		// Made meanwhile, by someone else or by a write before keys.
		tree , tree_err := client.tree( ctx )
		if tree_err != nil { return nil , tree_err }
		if _ , found := tree[ id ]; found {
			key , err = client.resolve( ctx , tree , id , true )
		}
		return
	}
	if err == nil {
		client.remember( key , true )
	}
	return
}

// PrepareShare gets collection, and every collection under it, ready to be
// opened with the collection's own keys, and answers those keys: read-only
// unless write. Collections without keys get them, and private envelopes
// (which only the master key opens) are sealed again as collection
// envelopes. Pair the answer with a scoped API key from
// the Account screen in NewAccessToken; the browser's Share dialog does all
// of it in one step.
func ( client *Client ) PrepareShare( ctx context.Context , collection string , write bool ) ( key *CollectionKey , err error ) {
	tree , err := client.tree( ctx )
	if err != nil { return }
	if _ , found := tree[ collection ]; found == false { return nil , errOutOfScope }
	children := map[ string ][]string{}
	for _ , entry := range tree {
		children[ entry.Parent ] = append( children[ entry.Parent ] , entry.ID )
	}
	queue := []string{ collection }
	for len( queue ) > 0 {
		id := queue[ 0 ]
		queue = append( queue[ 1: ] , children[ id ]... )
		folder_key , key_err := client.resolve( ctx , tree , id , true )
		if key_err != nil { return nil , key_err }
		if err = client.sealForSharing( ctx , folder_key ); err != nil { return }
	}
	key = client.cached( collection )
	if write == false {
		key = key.ReadOnly()
	}
	return
}

// sealForSharing seals every private envelope in key's collection again as a
// collection envelope, each only if it has not changed since it was read.
func ( client *Client ) sealForSharing( ctx context.Context , key *CollectionKey ) ( err error ) {
	offset := 0
	for offset >= 0 {
		var reply struct {
			Docs []struct {
				Meta
				Body string `json:"body"`
			} `json:"docs"`
			Next *int `json:"next"`
		}
		path := "/api/collections/" + url.PathEscape( key.collection ) + "/docs?include_body=true&" + pageQuery( offset , 200 )
		if err = client.call( ctx , http.MethodGet , path , nil , &reply ); err != nil { return }
		for _ , row := range reply.Docs {
			envelope , decode_err := b64.DecodeString( row.Body )
			if decode_err != nil { return ErrCorrupt }
			if EnvelopeKind( envelope ) != EnvelopeMaster { continue }
			if client.key == nil { return errNoMaster }
			// Only ever this collection's documents: a server listing one
			// from elsewhere would otherwise get it sealed again under the
			// keys being shared.
			if row.Collection != key.collection { return ErrCorrupt }
			plaintext , open_err := client.key.Open( key.collection , row.ID , envelope )
			if open_err != nil { return open_err }
			sealed , seal_err := key.Seal( row.ID , plaintext )
			if seal_err != nil { return seal_err }
			request := map[string]any{ "body": b64.EncodeToString( sealed ) , "if_version": row.Version }
			if err = client.call( ctx , http.MethodPost , docPath( key.collection , row.ID ) , request , nil ); err != nil {
				if errors.Is( err , ErrConflict ) {
					// Written meanwhile, as a collection envelope.
					err = nil
					continue
				}
				return
			}
		}
		offset = -1
		if reply.Next != nil { offset = *reply.Next }
	}
	return
}
