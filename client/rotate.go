package client

// Rotating a collection's keys (README.md, "Rotating keys"): every
// collection in a subtree gets new keys, and every collection envelope in
// them is sealed again under those, so someone who kept the old keys (a
// revoked access token) can neither read what is written from then on nor
// sign anything the account's clients will accept.

import (
	context "context"
	errors "errors"
	fmt "fmt"
	http "net/http"
	url "net/url"
)

// Rotation is what RotateKeys did.
type Rotation struct {
	// Collections is every collection now on new keys, parents first.
	Collections []string
	// Docs is how many documents were sealed again.
	Docs int
	// Revoked is the ids of the access keys (scoped API keys) the server
	// revoked: they reached a collection whose keys changed, and what their
	// tokens carry no longer opens it. Share again to give access back.
	Revoked []string
}

// rotateBatch is how many lockboxes go in one rotate call.
const rotateBatch = 200

// RotateKeys gives collection, and every collection under it, new keys, and
// seals every collection envelope in them again under those. Private
// envelopes stay as they are: only the master key opens them. It needs the
// master key.
//
// Every access key scoped to a collection in the subtree is revoked when it
// starts: their tokens hold the old keys. Access keys for a collection above
// it keep working, since they open the new keys the same way they opened the
// old.
//
// It is safe to stop half way: the server keeps both lockboxes until it is
// done, documents open with either meanwhile, and calling RotateKeys on the
// same collection again finishes it.
func ( client *Client ) RotateKeys( ctx context.Context , collection string ) ( rotation Rotation , err error ) {
	if client.key == nil { return rotation , errNoMaster }
	client.forget()
	tree , err := client.tree( ctx )
	if err != nil { return }
	if _ , found := tree[ collection ]; found == false { return rotation , errOutOfScope }
	order := subtreeOf( tree , collection )

	// The keys each one has now, to open what they sealed, and its new ones:
	// made here, or opened from a rotation already under way (resuming).
	olds := map[ string ]*CollectionKey{}
	news := map[ string ]*CollectionKey{}
	locks := []string{}
	staged := map[ string ]string{}
	for _ , id := range order {
		entry := tree[ id ]
		if entry.Lock != "" {
			if olds[ id ] , err = client.resolve( ctx , tree , id , false ); err != nil { return }
		}
		if entry.NextLock != "" {
			if news[ id ] , err = client.resolveNext( ctx , tree , id ); err != nil { return }
			continue
		}
		var holder lockHolder
		if id == collection {
			if holder , err = client.holder( ctx , tree , entry.Parent , false ); err != nil { return }
		} else {
			holder = news[ entry.Parent ]
		}
		key , key_err := generateCollectionKey( id )
		if key_err != nil { return rotation , key_err }
		// The owner tag stays as it was: keys a sharee made are not the
		// account's, rotated or not. A folder with no keys yet gets the tag
		// only at the top level, as when it is first given keys.
		own := ""
		if ( entry.Lock != "" && client.key.owns( entry.Lock , id ) ) || ( entry.Lock == "" && entry.Parent == "" ) {
			own = client.ownTag( key )
		}
		lock , lock_err := sealLock( key , holder , own )
		if lock_err != nil { return rotation , lock_err }
		news[ id ] = key
		locks = append( locks , id )
		staged[ id ] = lock
	}

	// The new lockboxes, parents first.
	for start := 0 ; start < len( locks ) ; start += rotateBatch {
		end := min( start + rotateBatch , len( locks ) )
		batch := map[ string ]string{}
		for _ , id := range locks[ start:end ] { batch[ id ] = staged[ id ] }
		var reply struct {
			Revoked []string `json:"revoked"`
		}
		if err = client.call( ctx , http.MethodPost , collectionPath( collection ) + "/rotate" , map[string]any{ "locks": batch } , &reply ); err != nil { return }
		rotation.Revoked = append( rotation.Revoked , reply.Revoked... )
	}
	for _ , id := range order {
		client.rememberNext( news[ id ] , lockOf( staged[ id ] , tree[ id ].NextLock ) )
	}

	// Every collection envelope sealed again, then the switch. A document
	// written meanwhile by another of the account's clients is already
	// under the new keys (the server takes no other), and one that changed
	// under this pass is picked up by the next.
	for pass := 0 ; ; pass++ {
		for _ , id := range order {
			count , reseal_err := client.reseal( ctx , id , olds[ id ] , news[ id ] )
			rotation.Docs += count
			if reseal_err != nil { return rotation , reseal_err }
		}
		var reply struct {
			Collections []string `json:"collections"`
		}
		err = client.call( ctx , http.MethodPost , collectionPath( collection ) + "/rotate/commit" , map[string]any{} , &reply )
		var refused *APIError
		if errors.As( err , &refused ) && refused.Message == "rotate_incomplete" && pass < 3 { continue }
		if err != nil { return }
		rotation.Collections = reply.Collections
		break
	}
	client.forget()
	return
}

// lockOf is the lockbox text that holds a collection's new keys: the one
// just staged, or the one already there.
func lockOf( staged string , existing string ) string {
	if staged != "" { return staged }
	return existing
}

// subtreeOf is root and every collection under it in tree, parents first.
func subtreeOf( tree map[ string ]Collection , root string ) ( order []string ) {
	children := map[ string ][]string{}
	for _ , entry := range tree {
		children[ entry.Parent ] = append( children[ entry.Parent ] , entry.ID )
	}
	queue := []string{ root }
	for len( queue ) > 0 {
		id := queue[ 0 ]
		queue = append( queue[ 1: ] , children[ id ]... )
		order = append( order , id )
	}
	return
}

// reseal seals every collection envelope in collection that next did not
// seal again with next, each only if it has not changed since it was read,
// and answers how many it wrote. One sealed with neither old nor next is
// ErrWrongKey: it cannot be opened, so it cannot be moved to the new keys.
func ( client *Client ) reseal( ctx context.Context , collection string , old *CollectionKey , next *CollectionKey ) ( count int , err error ) {
	offset := 0
	for offset >= 0 {
		var reply struct {
			Docs []struct {
				Meta
				Body string `json:"body"`
			} `json:"docs"`
			Next *int `json:"next"`
		}
		path := "/api/collections/" + url.PathEscape( collection ) + "/docs?include_body=true&" + pageQuery( offset , 200 )
		if err = client.call( ctx , http.MethodGet , path , nil , &reply ); err != nil { return }
		for _ , row := range reply.Docs {
			envelope , decode_err := b64.DecodeString( row.Body )
			if decode_err != nil || row.Collection != collection { return count , ErrCorrupt }
			if EnvelopeKind( envelope ) != EnvelopeCollection || len( envelope ) < headerSize { continue }
			named := string( envelope[ 1:headerSize ] )
			if named == string( next.id[ : ] ) { continue }
			if old == nil || named != string( old.id[ : ] ) {
				return count , fmt.Errorf( "%w: %s/%s is sealed with keys %s does not have" , ErrWrongKey , collection , row.ID , collection )
			}
			plaintext , open_err := old.Open( row.ID , envelope )
			if open_err != nil { return count , open_err }
			sealed , seal_err := next.Seal( row.ID , plaintext )
			if seal_err != nil { return count , seal_err }
			request := map[string]any{ "body": b64.EncodeToString( sealed ) , "if_version": row.Version }
			if err = client.call( ctx , http.MethodPost , docPath( collection , row.ID ) , request , nil ); err != nil {
				if errors.Is( err , ErrConflict ) || errors.Is( err , ErrNotFound ) {
					// Changed or deleted meanwhile: the next pass looks again.
					err = nil
					continue
				}
				return
			}
			count++
		}
		offset = -1
		if reply.Next != nil { offset = *reply.Next }
	}
	return
}
