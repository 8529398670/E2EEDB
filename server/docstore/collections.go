package docstore

import (
	rand "crypto/rand"
	sql "database/sql"
	binary "encoding/binary"
	errors "errors"
	strconv "strconv"
	strings "strings"
	time "time"
	unicode "unicode"
	utf8 "unicode/utf8"
)

// Collections form a tree of folders. A collection's id is what its documents
// are filed under (docs.collection) and what their encryption is bound to, so
// it never changes. Its name, its parent and its place among its siblings live
// in the collections table and change freely: renaming, moving or reordering
// a folder touches no document and re-encrypts nothing.
//
// parent "" is the top level. Names are unique among siblings, ignoring case.
// Every change to an account's tree moves that account's tree number on
// (trees.seq, from the same counter as documents), so a client can tell
// whether the tree it holds is still current.

// Errors about folders a caller tells apart.
var (
	ErrNoCollection = errors.New( "no such collection" )
	ErrNameTaken    = errors.New( "name_taken" )
	ErrCycle        = errors.New( "collection_cycle" )
	ErrTooDeep      = errors.New( "too_deep" )
	ErrTooMany      = errors.New( "too_many_collections" )
	// ErrShareTooMany: a scoped key's folder already holds as many folders
	// as a share may (Limits.ShareMaxCollections).
	ErrShareTooMany = errors.New( "share_too_many_collections" )
	ErrSamePlace    = errors.New( "same_place" )
	// ErrLockRequired: a folder with a lockbox moved to a new parent needs
	// its lockbox wrapped again for that parent, sent with the move.
	ErrLockRequired = errors.New( "lock_required" )
	// ErrLockExists: a folder's lockbox is set once, or replaced with a move.
	ErrLockExists = errors.New( "lock_exists" )
)

// LockMaxBytes bounds a lockbox; a real one is about 400 bytes.
const LockMaxBytes = 2048

// CollectionNameMax is the longest a folder name may be, in characters.
const CollectionNameMax = 128

// ValidCollectionName is whether name may name a folder: 1-128 characters,
// no control characters, no space at either end.
func ValidCollectionName( name string ) bool {
	if utf8.ValidString( name ) == false || name != strings.TrimSpace( name ) { return false }
	count := utf8.RuneCountInString( name )
	if count < 1 || count > CollectionNameMax { return false }
	for _ , r := range name {
		if unicode.IsControl( r ) { return false }
	}
	return true
}

// Collection is one folder, with its own live documents summed (not its
// subfolders'). UpdatedAt is the later of its own last change and its
// documents' (deletes included).
type Collection struct {
	ID        string
	Name      string
	Parent    string
	Position  int
	Version   int64
	// Lock is the folder's lockbox: its keys, wrapped by the client for its
	// parent (or the master key). The server stores it and cannot open it.
	Lock      string
	// NextLock is the lockbox of the keys a rotation under way is moving
	// the folder to (StageRotation), "" when none is.
	NextLock  string
	// ByKey is the scoped API key that made the folder, "" when the
	// account itself did.
	ByKey     string
	// Born is random, set when the folder is made and never changed: a
	// later folder with the same id has another.
	Born      int64
	Count     int
	Bytes     int64
	// Tombstones are its documents' deletes not yet purged.
	Tombstones int
	UpdatedAt time.Time
}

// CollectionChange is what CreateCollection or UpdateCollection asks for. A
// nil field is left as it is (on create: Name defaults to the id, Parent to
// the top level). Before is the sibling to go in front of; "" is the end.
// Before is only read when Parent or Before is set.
type CollectionChange struct {
	Name      *string
	Parent    *string
	Before    *string
	IfVersion *int64
	// Lock sets the lockbox: on create; on a folder that has none; or with
	// a move to a new parent, when it is required.
	Lock      *string
	// ByKey records the scoped API key making the folder (create only).
	ByKey     string
}

// ErrDeleteTooLarge: the folders hold more live documents than one delete
// may tombstone (DeleteOptions.MaxDocs). Errors carry a *DeleteTooLarge.
var ErrDeleteTooLarge = errors.New( "delete_too_large" )

// DeleteTooLarge is ErrDeleteTooLarge with how many live documents there are.
type DeleteTooLarge struct{ Docs int }

func ( large *DeleteTooLarge ) Error() string { return ErrDeleteTooLarge.Error() }
func ( large *DeleteTooLarge ) Unwrap() error { return ErrDeleteTooLarge }

// DeleteOptions shape a DeleteCollection.
type DeleteOptions struct {
	// IfVersion, when set, is the version the folder must be at.
	IfVersion *int64
	// MaxDocs caps the live documents one call tombstones (0: no cap). Past
	// it the call is ErrDeleteTooLarge, or with Partial a page of the
	// documents is tombstoned and the folders stay.
	MaxDocs int
	Partial bool
}

// DeletedTree is what DeleteCollection removed.
type DeletedTree struct {
	// Collections is every folder removed, the one asked for first; none
	// when Done is false.
	Collections []string
	// Docs is how many tombstones it left. The change feed lists them.
	Docs int
	// Done is false when a Partial call only tombstoned a page of the
	// documents: call again.
	Done bool
}

// Collections is one page of an account's folders, each parent's children
// together in their order, and how many there are in all.
func ( store *Store ) Collections( user_id uint64 , offset int , limit int ) ( result []Collection , total int , err error ) {
	err = store.db.QueryRow( `SELECT COUNT(*) FROM collections WHERE user_id = ?` , user_id ).Scan( &total )
	if err != nil { return }
	result , err = scanCounted( store.db.Query( `SELECT `+ countedColumns +` FROM collections c
		LEFT JOIN usage u ON u.user_id = c.user_id AND u.collection = c.id
		WHERE c.user_id = ? ORDER BY c.parent , c.position , c.id LIMIT ? OFFSET ?` ,
		user_id , limit , offset ) )
	return
}

// CollectionsIn is root and every folder under it, with their counts, in
// the order Collections gives; empty when root does not exist.
func ( store *Store ) CollectionsIn( user_id uint64 , root string ) ( result []Collection , err error ) {
	result , err = scanCounted( store.db.Query( shareSub + `SELECT `+ countedColumns +` FROM collections c
		LEFT JOIN usage u ON u.user_id = c.user_id AND u.collection = c.id
		WHERE c.user_id = ? AND c.id IN ( SELECT id FROM sub ) ORDER BY c.parent , c.position , c.id` ,
		user_id , root , user_id , user_id ) )
	return
}

// countedColumns are what scanCounted reads: a folder (c) and its running
// totals (u, absent for a folder no document was ever written to).
const countedColumns = `c.id , c.name , c.parent , c.position , c.version , c.lock , c.next_lock , c.by_key , c.born ,
	COALESCE( u.docs , 0 ) , COALESCE( u.bytes , 0 ) , COALESCE( u.tombs , 0 ) , MAX( c.updated_at , COALESCE( u.updated_at , 0 ) )`

func scanCounted( rows *sql.Rows , query_err error ) ( result []Collection , err error ) {
	if err = query_err; err != nil { return }
	defer rows.Close()
	result = []Collection{}
	for rows.Next() {
		var entry Collection
		var updated int64
		if err = rows.Scan( &entry.ID , &entry.Name , &entry.Parent , &entry.Position , &entry.Version , &entry.Lock , &entry.NextLock , &entry.ByKey , &entry.Born ,
			&entry.Count , &entry.Bytes , &entry.Tombstones , &updated ); err != nil { return }
		entry.UpdatedAt = fromMillis( updated )
		result = append( result , entry )
	}
	err = rows.Err()
	return
}

// TreeSeq is the change number of the last change to an account's folders;
// 0 when they never changed (folders carried over from before there were
// folders count as unchanged).
func ( store *Store ) TreeSeq( user_id uint64 ) ( seq int64 , err error ) {
	err = store.db.QueryRow( `SELECT seq FROM trees WHERE user_id = ?` , user_id ).Scan( &seq )
	if errors.Is( err , sql.ErrNoRows ) { err = nil }
	return
}

// GetCollection is one folder, without its counts.
func ( store *Store ) GetCollection( user_id uint64 , id string ) ( entry Collection , err error ) {
	var updated int64
	err = store.db.QueryRow( `SELECT id , name , parent , position , version , lock , next_lock , by_key , born , updated_at FROM collections WHERE user_id = ? AND id = ?` ,
		user_id , id ).Scan( &entry.ID , &entry.Name , &entry.Parent , &entry.Position , &entry.Version , &entry.Lock , &entry.NextLock , &entry.ByKey , &entry.Born , &updated )
	if errors.Is( err , sql.ErrNoRows ) {
		err = ErrNoCollection
		return
	}
	entry.UpdatedAt = fromMillis( updated )
	return
}

// CreateCollection makes a folder with id, which must not be one the account
// already has. change.IfVersion is ignored.
func ( store *Store ) CreateCollection( user_id uint64 , id string , change CollectionChange , limits Limits ) ( entry Collection , err error ) {
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		if _ , found , read_err := readCollection( tx , user_id , id ); read_err != nil || found {
			tx_err = read_err
			if found { tx_err = &ConflictError{ Current: 1 , Live: true } }
			return
		}
		if tx_err = checkCount( tx , user_id , limits ); tx_err != nil { return }
		name := id
		if change.Name != nil { name = *change.Name }
		parent := ""
		if change.Parent != nil { parent = *change.Parent }
		before := ""
		if change.Before != nil { before = *change.Before }
		if parent != "" {
			if _ , found , read_err := readCollection( tx , user_id , parent ); read_err != nil || found == false {
				tx_err = read_err
				if found == false { tx_err = ErrNoCollection }
				return
			}
			depth , depth_err := depthOf( tx , user_id , parent )
			if depth_err != nil {
				tx_err = depth_err
				return
			}
			if depth + 1 > limits.maxDepth() {
				tx_err = ErrTooDeep
				return
			}
			// A folder made inside one whose keys are being rotated would
			// get a lockbox wrapped for keys that are about to go.
			if tx_err = refuseRotating( tx , user_id , parent ); tx_err != nil { return }
		}
		if tx_err = checkName( tx , user_id , parent , name , "" ); tx_err != nil { return }
		seq , tx_err := touchTree( tx , user_id )
		if tx_err != nil { return }
		lock := ""
		if change.Lock != nil { lock = *change.Lock }
		_ , tx_err = tx.Exec( `INSERT INTO collections ( user_id , id , name , parent , position , version , seq , updated_at , lock , by_key , born )
			VALUES ( ? , ? , ? , ? , 0 , 1 , ? , ? , ? , ? , ? )` , user_id , id , name , parent , seq , millis( now ) , lock , change.ByKey , newBorn() )
		if tx_err != nil { return }
		if tx_err = place( tx , user_id , id , parent , before ); tx_err != nil { return }
		entry , _ , tx_err = readCollection( tx , user_id , id )
		return
	} )
	return
}

// UpdateCollection renames, moves or reorders a folder. Moving refuses to put
// a folder inside itself (ErrCycle) or deeper than limits allow (ErrTooDeep).
func ( store *Store ) UpdateCollection( user_id uint64 , id string , change CollectionChange , limits Limits ) ( entry Collection , err error ) {
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		current , found , tx_err := readCollection( tx , user_id , id )
		if tx_err != nil { return }
		if found == false {
			tx_err = ErrNoCollection
			return
		}
		if change.IfVersion != nil && *change.IfVersion != current.Version {
			tx_err = &ConflictError{ Current: current.Version , Live: true }
			return
		}
		name := current.Name
		if change.Name != nil { name = *change.Name }
		parent := current.Parent
		if change.Parent != nil { parent = *change.Parent }
		moving := change.Parent != nil || change.Before != nil
		if parent != current.Parent {
			if tx_err = checkMove( tx , user_id , id , parent , limits ); tx_err != nil { return }
		}
		// While keys are being rotated, the folders involved keep their
		// place and their lockboxes: a move or a new lockbox would be
		// wrapped for keys that are about to go.
		if parent != current.Parent || change.Lock != nil {
			if tx_err = refuseRotating( tx , user_id , id ); tx_err != nil { return }
			if parent != "" {
				if tx_err = refuseRotating( tx , user_id , parent ); tx_err != nil { return }
			}
		}
		lock := current.Lock
		switch {
		case parent != current.Parent && current.Lock != "" && change.Lock == nil:
			tx_err = ErrLockRequired
			return
		case change.Lock != nil && parent == current.Parent && current.Lock != "" && *change.Lock != current.Lock:
			tx_err = ErrLockExists
			return
		case change.Lock != nil:
			lock = *change.Lock
		}
		if name != current.Name || parent != current.Parent {
			if tx_err = checkName( tx , user_id , parent , name , id ); tx_err != nil { return }
		}
		seq , tx_err := touchTree( tx , user_id )
		if tx_err != nil { return }
		_ , tx_err = tx.Exec( `UPDATE collections SET name = ? , parent = ? , lock = ? , version = version + 1 , seq = ? , updated_at = ?
			WHERE user_id = ? AND id = ?` , name , parent , lock , seq , millis( now ) , user_id , id )
		if tx_err != nil { return }
		if moving {
			before := ""
			if change.Before != nil { before = *change.Before }
			if tx_err = place( tx , user_id , id , parent , before ); tx_err != nil { return }
			if parent != current.Parent {
				// Close the gap it left.
				if tx_err = place( tx , user_id , "" , current.Parent , "" ); tx_err != nil { return }
			}
		}
		entry , _ , tx_err = readCollection( tx , user_id , id )
		return
	} )
	return
}

// DeleteCollection removes a folder, every folder under it, and every live
// document in them (each one a tombstone, so syncing clients hear of it).
// The documents go in one statement, so even a big folder holds the write
// lock briefly; options.MaxDocs caps how many one call may take (see
// DeleteOptions).
func ( store *Store ) DeleteCollection( user_id uint64 , id string , options DeleteOptions ) ( deleted DeletedTree , err error ) {
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		current , found , tx_err := readCollection( tx , user_id , id )
		if tx_err != nil { return }
		if found == false {
			tx_err = ErrNoCollection
			return
		}
		if options.IfVersion != nil && *options.IfVersion != current.Version {
			tx_err = &ConflictError{ Current: current.Version , Live: true }
			return
		}
		var live int
		tx_err = tx.QueryRow( shareSub + `SELECT COALESCE( SUM( docs ) , 0 ) FROM usage WHERE user_id = ? AND collection IN ( SELECT id FROM sub )` ,
			user_id , id , user_id , user_id ).Scan( &live )
		if tx_err != nil { return }
		page := live
		if options.MaxDocs > 0 && live > options.MaxDocs {
			if options.Partial == false {
				tx_err = &DeleteTooLarge{ Docs: live }
				return
			}
			page = options.MaxDocs
		}
		if deleted.Docs , tx_err = tombstoneIn( tx , user_id , id , page , now ); tx_err != nil { return }
		// Fewer than a page means none are left, whatever the totals said.
		if page < live && deleted.Docs == page {
			return
		}
		deleted.Done = true
		if deleted.Collections , tx_err = subtree( tx , user_id , id ); tx_err != nil { return }
		_ , tx_err = tx.Exec( shareSub + `DELETE FROM collections WHERE user_id = ? AND id IN ( SELECT id FROM sub )` ,
			user_id , id , user_id , user_id )
		if tx_err != nil { return }
		if _ , tx_err = touchTree( tx , user_id ); tx_err != nil { return }
		tx_err = place( tx , user_id , "" , current.Parent , "" )
		return
	} )
	return
}

// tombstoneIn turns up to limit live documents in root and the folders
// under it into tombstones, in one statement, each with its own change
// number, and answers how many it did.
func tombstoneIn( tx *sql.Tx , user_id uint64 , root string , limit int , now time.Time ) ( count int , err error ) {
	if limit <= 0 { return }
	var base int64
	err = tx.QueryRow( `SELECT seq FROM counters WHERE user_id = ?` , user_id ).Scan( &base )
	if errors.Is( err , sql.ErrNoRows ) { err = nil }
	if err != nil { return }
	result , err := tx.Exec( shareSub + `, pick ( collection , doc_id , n ) AS (
			SELECT collection , doc_id , ROW_NUMBER() OVER ( ORDER BY collection , doc_id ) FROM docs
			WHERE user_id = ? AND deleted = 0 AND collection IN ( SELECT id FROM sub ) ORDER BY collection , doc_id LIMIT ?
		) UPDATE docs SET version = docs.version + 1 , seq = ? + pick.n , updated_at = ? , deleted = 1 , size = 0 , body = NULL
		FROM pick WHERE docs.user_id = ? AND docs.collection = pick.collection AND docs.doc_id = pick.doc_id` ,
		user_id , root , user_id , user_id , limit , base , millis( now ) , user_id )
	if err != nil { return }
	affected , err := result.RowsAffected()
	if err != nil || affected == 0 { return }
	count = int( affected )
	_ , err = tx.Exec( `INSERT INTO counters ( user_id , seq ) VALUES ( ? , ? )
		ON CONFLICT ( user_id ) DO UPDATE SET seq = excluded.seq` , user_id , base + affected )
	return
}

// MoveDoc moves a document to another folder, or another id, in one step: the
// new one is written with body (which the client sealed for its new place;
// the old ciphertext would not open there) and the old one becomes a
// tombstone. if_version is the source's version. A live document already at
// the destination is a ConflictError.
func ( store *Store ) MoveDoc( user_id uint64 , from string , id string , to string , to_id string , body []byte , if_version *int64 , limits Limits ) ( moved Doc , gone Doc , err error ) {
	if from == to && id == to_id {
		err = ErrSamePlace
		return
	}
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		if _ , found , read_err := readCollection( tx , user_id , to ); read_err != nil || found == false {
			tx_err = read_err
			if found == false { tx_err = ErrNoCollection }
			return
		}
		source , tx_err := readExisting( tx , user_id , from , id )
		if tx_err != nil { return }
		if source.found == false || source.deleted {
			tx_err = ErrNotFound
			return
		}
		if tx_err = checkVersion( if_version , true , source.version ); tx_err != nil { return }
		target , tx_err := readExisting( tx , user_id , to , to_id )
		if tx_err != nil { return }
		if target.found && target.deleted == false {
			tx_err = &ConflictError{ Current: target.version , Live: true }
			return
		}
		if tx_err = checkEnvelopeKey( tx , user_id , to , body ); tx_err != nil { return }
		if gone , tx_err = deleteTx( tx , user_id , from , id , nil , now ); tx_err != nil { return }
		moved , tx_err = setTx( tx , user_id , to , to_id , body , version0() , limits , now )
		return
	} )
	return
}

// newBorn is a folder's born value: random, never 0.
func newBorn() int64 {
	var raw [8]byte
	if _ , err := rand.Read( raw[ : ] ); err != nil { panic( err ) }
	return int64( binary.BigEndian.Uint64( raw[ : ] ) >> 1 ) | 1
}

func version0() *int64 {
	zero := int64( 0 )
	return &zero
}

// ensureCollection makes a top-level folder for id when the account has none,
// named after the id (or "id (2)" and so on when a top-level folder already
// has that name), and says whether it did. It takes no change number of its
// own: the caller marks it with its document's (see markTree), so a write
// that makes a folder still uses one number.
func ensureCollection( tx *sql.Tx , user_id uint64 , id string , limits Limits , now time.Time ) ( created bool , err error ) {
	_ , found , err := readCollection( tx , user_id , id )
	if err != nil || found { return }
	if limits.NoAutoCreate {
		err = ErrNoCollection
		return
	}
	if err = checkCount( tx , user_id , limits ); err != nil { return }
	names , err := siblingNames( tx , user_id , "" , "" )
	if err != nil { return }
	name := id
	for n := 2 ; taken( names , name ) ; n++ {
		name = id + " (" + strconv.Itoa( n ) + ")"
	}
	var position int
	err = tx.QueryRow( `SELECT COALESCE( MAX( position ) + 1 , 0 ) FROM collections WHERE user_id = ? AND parent = ''` , user_id ).Scan( &position )
	if err != nil { return }
	_ , err = tx.Exec( `INSERT INTO collections ( user_id , id , name , parent , position , version , seq , updated_at , born )
		VALUES ( ? , ? , ? , '' , ? , 1 , 0 , ? , ? )` , user_id , id , name , position , millis( now ) , newBorn() )
	created = err == nil
	return
}

// markTree records seq as the account's latest tree change, and as the
// folder's own.
func markTree( tx *sql.Tx , user_id uint64 , id string , seq int64 ) ( err error ) {
	if _ , err = tx.Exec( `UPDATE collections SET seq = ? WHERE user_id = ? AND id = ?` , seq , user_id , id ); err != nil { return }
	_ , err = tx.Exec( `INSERT INTO trees ( user_id , seq ) VALUES ( ? , ? ) ON CONFLICT ( user_id ) DO UPDATE SET seq = excluded.seq` , user_id , seq )
	return
}

func readCollection( tx *sql.Tx , user_id uint64 , id string ) ( entry Collection , found bool , err error ) {
	var updated int64
	err = tx.QueryRow( `SELECT id , name , parent , position , version , lock , next_lock , by_key , born , updated_at FROM collections WHERE user_id = ? AND id = ?` ,
		user_id , id ).Scan( &entry.ID , &entry.Name , &entry.Parent , &entry.Position , &entry.Version , &entry.Lock , &entry.NextLock , &entry.ByKey , &entry.Born , &updated )
	if errors.Is( err , sql.ErrNoRows ) {
		err = nil
		return
	}
	found = err == nil
	entry.UpdatedAt = fromMillis( updated )
	return
}

func checkCount( tx *sql.Tx , user_id uint64 , limits Limits ) ( err error ) {
	var count int
	if err = tx.QueryRow( `SELECT COUNT(*) FROM collections WHERE user_id = ?` , user_id ).Scan( &count ); err != nil { return }
	if count >= limits.maxCollections() {
		err = ErrTooMany
		if limits.Share != "" { err = ErrShareTooMany }
		return
	}
	if limits.Share != "" && limits.ShareMaxCollections > 0 {
		err = tx.QueryRow( shareSub + `SELECT COUNT(*) FROM sub` , user_id , limits.Share , user_id ).Scan( &count )
		if err == nil && count >= limits.ShareMaxCollections { err = ErrShareTooMany }
	}
	return
}

// siblingNames is the names of parent's children, but for except.
func siblingNames( tx *sql.Tx , user_id uint64 , parent string , except string ) ( names []string , err error ) {
	rows , err := tx.Query( `SELECT name FROM collections WHERE user_id = ? AND parent = ? AND id != ?` , user_id , parent , except )
	if err != nil { return }
	defer rows.Close()
	for rows.Next() {
		var name string
		if err = rows.Scan( &name ); err != nil { return }
		names = append( names , name )
	}
	err = rows.Err()
	return
}

func taken( names []string , name string ) bool {
	for _ , other := range names {
		if strings.EqualFold( other , name ) { return true }
	}
	return false
}

// checkName is ErrNameTaken when another child of parent (not id) has name.
func checkName( tx *sql.Tx , user_id uint64 , parent string , name string , id string ) ( err error ) {
	names , err := siblingNames( tx , user_id , parent , id )
	if err == nil && taken( names , name ) { err = ErrNameTaken }
	return
}

// depthOf is how deep id is: 1 for a top-level folder.
func depthOf( tx *sql.Tx , user_id uint64 , id string ) ( depth int , err error ) {
	for id != "" && depth < 1000 {
		depth++
		if err = tx.QueryRow( `SELECT parent FROM collections WHERE user_id = ? AND id = ?` , user_id , id ).Scan( &id ); err != nil {
			if errors.Is( err , sql.ErrNoRows ) { err = ErrNoCollection }
			return
		}
	}
	return
}

// checkMove is whether id may go under parent: parent exists, is not id or
// under it, and the deepest folder in id's subtree stays within the limit.
func checkMove( tx *sql.Tx , user_id uint64 , id string , parent string , limits Limits ) ( err error ) {
	parent_depth := 0
	if parent != "" {
		for at := parent ; at != "" ; {
			if at == id {
				err = ErrCycle
				return
			}
			parent_depth++
			if err = tx.QueryRow( `SELECT parent FROM collections WHERE user_id = ? AND id = ?` , user_id , at ).Scan( &at ); err != nil {
				if errors.Is( err , sql.ErrNoRows ) { err = ErrNoCollection }
				return
			}
		}
	}
	var height int
	err = tx.QueryRow( `WITH RECURSIVE sub ( id , depth ) AS (
			SELECT id , 1 FROM collections WHERE user_id = ? AND id = ?
			UNION ALL SELECT c.id , sub.depth + 1 FROM collections c JOIN sub ON c.parent = sub.id WHERE c.user_id = ?
		) SELECT MAX( depth ) FROM sub` , user_id , id , user_id ).Scan( &height )
	if err != nil { return }
	if parent_depth + height > limits.maxDepth() { err = ErrTooDeep }
	return
}

// subtree is id and every folder under it, id first, parents before children.
func subtree( tx *sql.Tx , user_id uint64 , id string ) ( ids []string , err error ) {
	rows , err := tx.Query( `WITH RECURSIVE sub ( id , depth ) AS (
			SELECT id , 0 FROM collections WHERE user_id = ? AND id = ?
			UNION ALL SELECT c.id , sub.depth + 1 FROM collections c JOIN sub ON c.parent = sub.id WHERE c.user_id = ?
		) SELECT id FROM sub ORDER BY depth , id` , user_id , id , user_id )
	if err != nil { return }
	defer rows.Close()
	for rows.Next() {
		var entry string
		if err = rows.Scan( &entry ); err != nil { return }
		ids = append( ids , entry )
	}
	err = rows.Err()
	return
}

// Within is whether id is root or a folder under root.
func ( store *Store ) Within( user_id uint64 , root string , id string ) ( inside bool , err error ) {
	for at , steps := id , 0 ; at != "" && steps < 1000 ; steps++ {
		if at == root {
			inside = true
			return
		}
		if err = store.db.QueryRow( `SELECT parent FROM collections WHERE user_id = ? AND id = ?` , user_id , at ).Scan( &at ); err != nil {
			if errors.Is( err , sql.ErrNoRows ) { err = nil }
			return
		}
	}
	return
}

// Subtree is root and every folder under it, parents before children; empty
// when root does not exist.
func ( store *Store ) Subtree( user_id uint64 , root string ) ( ids []string , err error ) {
	tx , err := store.db.Begin()
	if err != nil { return }
	defer tx.Rollback()
	ids , err = subtree( tx , user_id , root )
	return
}

// place puts id among parent's children in front of before ("" or not one of
// them: at the end), and numbers them all 0..n. id "" only renumbers.
func place( tx *sql.Tx , user_id uint64 , id string , parent string , before string ) ( err error ) {
	rows , err := tx.Query( `SELECT id FROM collections WHERE user_id = ? AND parent = ? AND id != ? ORDER BY position , id` , user_id , parent , id )
	if err != nil { return }
	order := []string{}
	for rows.Next() {
		var sibling string
		if err = rows.Scan( &sibling ); err != nil {
			rows.Close()
			return
		}
		order = append( order , sibling )
	}
	rows.Close()
	if err = rows.Err(); err != nil { return }
	if id != "" {
		at := len( order )
		for index , sibling := range order {
			if sibling == before { at = index }
		}
		order = append( order[ :at ] , append( []string{ id } , order[ at: ]... )... )
	}
	for index , sibling := range order {
		if _ , err = tx.Exec( `UPDATE collections SET position = ? WHERE user_id = ? AND id = ? AND position != ?` , index , user_id , sibling , index ); err != nil { return }
	}
	return
}

// touchTree takes a change number for a change to the account's folders.
func touchTree( tx *sql.Tx , user_id uint64 ) ( seq int64 , err error ) {
	if seq , err = nextSeq( tx , user_id ); err != nil { return }
	err = markTree( tx , user_id , "" , seq )
	return
}
