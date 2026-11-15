package docstore

import (
	bytes "bytes"
	sql "database/sql"
	base64 "encoding/base64"
	json "encoding/json"
	errors "errors"
	time "time"
)

// Rotating a folder's keys (README.md, "Rotating keys"). The client gives
// every folder in a subtree new keys and seals every collection envelope in
// it again under them. That is too much for one request, so it happens in
// three steps, and the folders hold both lockboxes in between:
//
//  1. StageRotation sets next_lock (the new keys' lockbox) on the root, then
//     on the folders under it, parents first, in as many calls as it takes.
//  2. The client re-seals each document with an ordinary write. While a
//     folder has a next_lock, a collection envelope written into it must
//     be sealed with those new keys; one under the old keys is refused.
//  3. CommitRotation, once every folder has a next_lock and every collection
//     envelope in them is sealed under it, makes next_lock the lock.
//
// Nothing here can open a lockbox: the server reads only the key_id a
// lockbox names, and the 16-byte key id after an envelope's first byte, so
// it can refuse writes sealed with keys a folder no longer uses. That keeps
// an honest server's data consistent; a dishonest one is the client's
// problem, as everywhere else.

// Errors about rotations a caller tells apart.
var (
	// ErrRotating: the folder, or one above it, is in a rotation, and what
	// was asked would be wrapped for keys that are about to go; or a
	// rotation was started inside or above one already under way.
	ErrRotating = errors.New( "rotating" )
	// ErrNotRotating: commit (or a later stage) asked of a folder with no
	// rotation under way.
	ErrNotRotating = errors.New( "not_rotating" )
	// ErrRotateParentFirst: a folder's next lockbox was sent before its
	// parent's.
	ErrRotateParentFirst = errors.New( "rotate_parent_first" )
	// ErrStaleKey: a collection envelope sealed with keys its folder no
	// longer uses (or not yet: the new keys, mid-rotation, are the only
	// ones it takes).
	ErrStaleKey = errors.New( "stale_key" )
)

// RotateIncomplete is CommitRotation refusing: folders still without new
// keys, and collection envelopes still sealed under old ones.
type RotateIncomplete struct {
	Collections int
	Docs        int
}

func ( incomplete *RotateIncomplete ) Error() string { return "rotate_incomplete" }

// Rotation is what StageRotation did.
type Rotation struct {
	// Started: this call began the rotation (it carried the root's lockbox).
	Started bool
	// Subtree is the root and every folder under it, parents first.
	Subtree []string
	// Pending is the folders that still have no next lockbox.
	Pending []string
}

// lockKeyID is the key id a lockbox names (its key_id), nil when it names
// none the server can read.
func lockKeyID( lock string ) ( key_id []byte ) {
	var box struct {
		KeyID string `json:"key_id"`
	}
	if lock == "" || json.Unmarshal( []byte( lock ) , &box ) != nil { return }
	decoded , err := base64.StdEncoding.DecodeString( box.KeyID )
	if err == nil && len( decoded ) == 16 { key_id = decoded }
	return
}

// rotatingAt is the folder at or above id that has a next lockbox, "" when
// none does.
func rotatingAt( tx *sql.Tx , user_id uint64 , id string ) ( at string , err error ) {
	for steps := 0 ; id != "" && steps < 1000 ; steps++ {
		var parent , next string
		err = tx.QueryRow( `SELECT parent , next_lock FROM collections WHERE user_id = ? AND id = ?` , user_id , id ).Scan( &parent , &next )
		if errors.Is( err , sql.ErrNoRows ) {
			err = nil
			return
		}
		if err != nil { return }
		if next != "" {
			at = id
			return
		}
		id = parent
	}
	return
}

// refuseRotating is ErrRotating when id, or a folder above it, is in a
// rotation.
func refuseRotating( tx *sql.Tx , user_id uint64 , id string ) ( err error ) {
	at , err := rotatingAt( tx , user_id , id )
	if err == nil && at != "" { err = ErrRotating }
	return
}

// checkEnvelopeKey refuses a collection envelope written into collection
// that its keys did not seal: the next keys while a rotation is under way,
// otherwise the ones its lockbox names. A private envelope, and a folder
// with no lockbox yet, are not checked.
func checkEnvelopeKey( tx *sql.Tx , user_id uint64 , collection string , body []byte ) ( err error ) {
	if len( body ) < 17 || body[ 0 ] != EnvelopeCollection { return }
	entry , found , err := readCollection( tx , user_id , collection )
	if err != nil || found == false { return }
	var want []byte
	switch {
	case entry.NextLock != "":
		want = lockKeyID( entry.NextLock )
	default:
		// Inside a rotation, but this folder has no new keys yet: nothing it
		// could be sealed with now will still open once it does.
		if err = refuseRotating( tx , user_id , entry.Parent ); err != nil { return }
		want = lockKeyID( entry.Lock )
	}
	if want != nil && bytes.Equal( body[ 1:17 ] , want ) == false { err = ErrStaleKey }
	return
}

// InRotation is whether id, or a folder above it, has a rotation under way.
func ( store *Store ) InRotation( user_id uint64 , id string ) ( rotating bool , err error ) {
	tx , err := store.db.Begin()
	if err != nil { return }
	defer tx.Rollback()
	at , err := rotatingAt( tx , user_id , id )
	rotating = at != ""
	return
}

// StageRotation sets next lockboxes on root's subtree: locks maps folder ids
// to lockboxes, each one set once (ErrLockExists after). The first call must
// carry root's own, which starts the rotation; it is refused (ErrRotating)
// when a folder above root, or one under it, is already in one. After that,
// each folder's parent must have its next lockbox first
// (ErrRotateParentFirst). A folder outside root's subtree is ErrNoCollection.
func ( store *Store ) StageRotation( user_id uint64 , root string , locks map[ string ]string ) ( rotation Rotation , err error ) {
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		entry , found , tx_err := readCollection( tx , user_id , root )
		if tx_err != nil { return }
		if found == false {
			tx_err = ErrNoCollection
			return
		}
		if tx_err = refuseRotating( tx , user_id , entry.Parent ); tx_err != nil { return }
		ids , tx_err := subtree( tx , user_id , root )
		if tx_err != nil { return }
		next := map[ string ]string{}
		parents := map[ string ]string{}
		for _ , id := range ids {
			row , _ , read_err := readCollection( tx , user_id , id )
			if read_err != nil {
				tx_err = read_err
				return
			}
			next[ id ] = row.NextLock
			parents[ id ] = row.Parent
		}
		for id := range locks {
			if _ , inside := next[ id ]; inside == false {
				tx_err = ErrNoCollection
				return
			}
		}
		if entry.NextLock == "" {
			if _ , starting := locks[ root ]; starting == false {
				tx_err = ErrNotRotating
				return
			}
			for _ , id := range ids {
				if next[ id ] != "" {
					tx_err = ErrRotating
					return
				}
			}
			rotation.Started = true
		}
		for id := range locks {
			if next[ id ] != "" {
				tx_err = ErrLockExists
				return
			}
		}
		var seq int64
		if len( locks ) > 0 {
			if seq , tx_err = touchTree( tx , user_id ); tx_err != nil { return }
		}
		for _ , id := range ids {
			lock , given := locks[ id ]
			if given == false { continue }
			if id != root && next[ parents[ id ] ] == "" {
				tx_err = ErrRotateParentFirst
				return
			}
			if _ , tx_err = tx.Exec( `UPDATE collections SET next_lock = ? , version = version + 1 , seq = ? , updated_at = ? WHERE user_id = ? AND id = ?` ,
				lock , seq , millis( now ) , user_id , id ); tx_err != nil { return }
			next[ id ] = lock
		}
		rotation.Subtree = ids
		rotation.Pending = []string{}
		for _ , id := range ids {
			if next[ id ] == "" { rotation.Pending = append( rotation.Pending , id ) }
		}
		return
	} )
	return
}

// CommitRotation ends root's rotation: once every folder in its subtree has
// a next lockbox and every live collection envelope in them is sealed with
// those keys, each next lockbox becomes the folder's lockbox, all at once.
// Otherwise it is a *RotateIncomplete saying what is left. It answers the
// folders, parents first.
func ( store *Store ) CommitRotation( user_id uint64 , root string ) ( ids []string , err error ) {
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		entry , found , tx_err := readCollection( tx , user_id , root )
		if tx_err != nil { return }
		if found == false {
			tx_err = ErrNoCollection
			return
		}
		if entry.NextLock == "" {
			tx_err = ErrNotRotating
			return
		}
		// Only the rotation's root commits it.
		if tx_err = refuseRotating( tx , user_id , entry.Parent ); tx_err != nil { return }
		if ids , tx_err = subtree( tx , user_id , root ); tx_err != nil { return }
		incomplete := RotateIncomplete{}
		for _ , id := range ids {
			row , _ , read_err := readCollection( tx , user_id , id )
			if read_err != nil {
				tx_err = read_err
				return
			}
			want := lockKeyID( row.NextLock )
			if want == nil {
				incomplete.Collections++
				continue
			}
			var stale int
			tx_err = tx.QueryRow( `SELECT COUNT(*) FROM docs WHERE user_id = ? AND collection = ? AND deleted = 0
				AND substr( body , 1 , 1 ) = x'02' AND substr( body , 2 , 16 ) != ?` , user_id , id , want ).Scan( &stale )
			if tx_err != nil { return }
			incomplete.Docs += stale
		}
		if incomplete.Collections > 0 || incomplete.Docs > 0 {
			tx_err = &incomplete
			return
		}
		seq , tx_err := touchTree( tx , user_id )
		if tx_err != nil { return }
		for _ , id := range ids {
			if _ , tx_err = tx.Exec( `UPDATE collections SET lock = next_lock , next_lock = '' , version = version + 1 , seq = ? , updated_at = ?
				WHERE user_id = ? AND id = ?` , seq , millis( now ) , user_id , id ); tx_err != nil { return }
		}
		return
	} )
	return
}
