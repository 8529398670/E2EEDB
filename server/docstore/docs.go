package docstore

import (
	sql "database/sql"
	errors "errors"
	regexp "regexp"
	time "time"
)

// Envelope kind: the first byte of every document body. The rest of the
// body is the client's business (see README.md, "Crypto format"); the server
// only checks this byte and the minimum length, so a client sending
// something that is plainly not an envelope (plaintext JSON, say) is refused
// rather than stored.
const (
	// EnvelopeMaster is a private envelope, sealed by the account's master
	// key alone.
	EnvelopeMaster = 0x01
	// EnvelopeMasterMin is the smallest private envelope: kind byte, 16-byte
	// key id, 24-byte nonce, 16-byte tag around an empty plaintext.
	EnvelopeMasterMin = 1 + 16 + 24 + 16
	// EnvelopeCollection is a collection envelope, sealed with its
	// collection's own keys and signed: the same shape plus a 64-byte
	// Ed25519 signature.
	EnvelopeCollection    = 0x02
	EnvelopeCollectionMin = EnvelopeMasterMin + 64
)

var (
	collectionPattern = regexp.MustCompile( `^[A-Za-z0-9_-]{1,64}$` )
	docIDPattern      = regexp.MustCompile( `^[A-Za-z0-9_.-]{1,128}$` )
)

// ValidCollection is whether name may name a collection.
func ValidCollection( name string ) bool { return collectionPattern.MatchString( name ) }

// randomIDPattern is client.NewID's shape: 16 random bytes, unpadded
// URL-safe base64.
var randomIDPattern = regexp.MustCompile( `^[A-Za-z0-9_-]{22}$` )

// ValidRandomID is whether id has the shape of a random id (client.NewID,
// the browser's DocsCrypto.newId). A scoped key may only make folders with
// such ids, so it cannot take an id the account's own code writes to by name
// ("invoices") before that code makes it.
func ValidRandomID( id string ) bool { return randomIDPattern.MatchString( id ) }

// ValidDocID is whether id may name a document. "." and ".." are refused so
// an id is never a path segment with a meaning of its own.
func ValidDocID( id string ) bool {
	return docIDPattern.MatchString( id ) && id != "." && id != ".."
}

// ValidEnvelope is whether body looks like a private or a collection
// envelope.
func ValidEnvelope( body []byte ) bool {
	switch {
	case len( body ) >= EnvelopeMasterMin && body[ 0 ] == EnvelopeMaster:
		return true
	case len( body ) >= EnvelopeCollectionMin && body[ 0 ] == EnvelopeCollection:
		return true
	}
	return false
}

// Doc is one document, live or deleted. Body is nil for a tombstone, and for
// a listing that did not ask for bodies.
type Doc struct {
	Collection string
	ID         string
	Version    int64
	Seq        int64
	UpdatedAt  time.Time
	Deleted    bool
	Size       int
	Body       []byte
}

// Limits are what a write is checked against. QuotaBytes 0 is no quota.
// MaxCollections and MaxDepth 0 mean DefaultMaxCollections and
// DefaultMaxDepth.
type Limits struct {
	MaxDocBytes    int
	QuotaBytes     int64
	MaxCollections int
	MaxDepth       int
	// NoAutoCreate makes a write into a collection id with no folder
	// ErrNoCollection instead of making one at the top level. A scoped key's
	// writes set it: its scope was checked before the write's transaction,
	// and a folder deleted in between must not come back outside it.
	NoAutoCreate bool
	// Share is a scoped key's folder: its writes may not take that folder's
	// subtree past ShareQuotaBytes of live documents (0: no limit) or
	// ShareMaxCollections folders (0: no limit), so someone it was shared
	// with cannot use up the account's quota or folder limit. A scoped
	// write that the account's own limits refuse is answered with the share
	// errors too, so it does not learn the account is full.
	Share               string
	ShareQuotaBytes     int64
	ShareMaxCollections int
}

// shareSub is a WITH clause naming sub: the share's folder and every folder
// under it. It takes user_id , root , user_id.
const shareSub = `WITH RECURSIVE sub ( id ) AS (
		SELECT id FROM collections WHERE user_id = ? AND id = ?
		UNION ALL SELECT c.id FROM collections c JOIN sub ON c.parent = sub.id WHERE c.user_id = ?
	) `

// Defaults for the folder limits left at zero.
const (
	DefaultMaxCollections = 2000
	DefaultMaxDepth       = 16
)

func ( limits Limits ) maxCollections() int {
	if limits.MaxCollections > 0 { return limits.MaxCollections }
	return DefaultMaxCollections
}

func ( limits Limits ) maxDepth() int {
	if limits.MaxDepth > 0 { return limits.MaxDepth }
	return DefaultMaxDepth
}

func millis( at time.Time ) int64 { return at.UnixMilli() }
func fromMillis( ms int64 ) time.Time { return time.UnixMilli( ms ).UTC() }

// checkVersion applies a write's condition. if_version nil: unconditional. 0:
// there must be no live document. n: the live document must be at n.
func checkVersion( if_version *int64 , live bool , current int64 ) ( err error ) {
	if if_version == nil { return }
	want := *if_version
	ok := ( want == 0 && live == false ) || ( want > 0 && live && current == want )
	if ok == false {
		shown := current
		if live == false { shown = 0 }
		err = &ConflictError{ Current: shown , Live: live }
	}
	return
}

// existing is the row a write is about to replace, if any.
type existing struct {
	found   bool
	version int64
	deleted bool
	size    int
}

func readExisting( tx *sql.Tx , user_id uint64 , collection string , id string ) ( row existing , err error ) {
	var deleted int
	err = tx.QueryRow( `SELECT version , deleted , size FROM docs WHERE user_id = ? AND collection = ? AND doc_id = ?` ,
		user_id , collection , id ).Scan( &row.version , &deleted , &row.size )
	if errors.Is( err , sql.ErrNoRows ) {
		err = nil
		return
	}
	row.found = err == nil
	row.deleted = deleted != 0
	return
}

// Set writes a document, creating or replacing it, and returns its new
// metadata. The new version is one past the last, counting deletes, so a
// version number is never reused for a different ciphertext. Writing into a
// collection id the account has no folder for yet makes one at the top level,
// named after the id, so a service that never touches folders keeps working.
func ( store *Store ) Set( user_id uint64 , collection string , id string , body []byte , if_version *int64 , limits Limits ) ( doc Doc , err error ) {
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		created , tx_err := ensureCollection( tx , user_id , collection , limits , now )
		if tx_err != nil { return }
		if tx_err = checkEnvelopeKey( tx , user_id , collection , body ); tx_err != nil { return }
		if doc , tx_err = setTx( tx , user_id , collection , id , body , if_version , limits , now ); tx_err != nil { return }
		if created { tx_err = markTree( tx , user_id , collection , doc.Seq ) }
		return
	} )
	return
}

// setTx is Set's write, inside a transaction the caller holds.
func setTx( tx *sql.Tx , user_id uint64 , collection string , id string , body []byte , if_version *int64 , limits Limits , now time.Time ) ( doc Doc , err error ) {
	if len( body ) > limits.MaxDocBytes {
		err = ErrTooLarge
		return
	}
	row , err := readExisting( tx , user_id , collection , id )
	if err != nil { return }
	live := row.found && row.deleted == false
	if err = checkVersion( if_version , live , row.version ); err != nil { return }
	// What the write frees: the live document it replaces, or the
	// tombstone it overwrites.
	var freed int64
	switch {
	case live: freed = int64( row.size )
	case row.found: freed = TombstoneBytes
	}
	if limits.QuotaBytes > 0 {
		var usage Usage
		if usage , err = readUsage( tx , user_id ); err != nil { return }
		if usage.Charged() - freed + int64( len( body ) ) > limits.QuotaBytes {
			err = ErrQuota
			if limits.Share != "" { err = ErrShareQuota }
			return
		}
	}
	if limits.Share != "" && limits.ShareQuotaBytes > 0 {
		var used int64
		err = tx.QueryRow( shareSub + `SELECT COALESCE( SUM( bytes + tombs * ? ) , 0 ) FROM usage WHERE user_id = ? AND collection IN ( SELECT id FROM sub )` ,
			user_id , limits.Share , user_id , TombstoneBytes , user_id ).Scan( &used )
		if err != nil { return }
		if used - freed + int64( len( body ) ) > limits.ShareQuotaBytes {
			err = ErrShareQuota
			return
		}
	}
	seq , err := nextSeq( tx , user_id )
	if err != nil { return }
	doc = Doc{ Collection: collection , ID: id , Version: row.version + 1 , Seq: seq , UpdatedAt: fromMillis( millis( now ) ) , Size: len( body ) }
	_ , err = tx.Exec( `INSERT INTO docs ( user_id , collection , doc_id , version , seq , updated_at , deleted , size , body )
		VALUES ( ? , ? , ? , ? , ? , ? , 0 , ? , ? )
		ON CONFLICT ( user_id , collection , doc_id ) DO UPDATE SET
			version = excluded.version , seq = excluded.seq , updated_at = excluded.updated_at ,
			deleted = 0 , size = excluded.size , body = excluded.body` ,
		user_id , collection , id , doc.Version , seq , millis( now ) , len( body ) , body )
	return
}

// Delete leaves a tombstone: no body, the next version, a new change number,
// so a syncing client hears about it. It is purged after tombstone_days (see
// Sweep). Deleting a document that is not live is ErrNotFound.
func ( store *Store ) Delete( user_id uint64 , collection string , id string , if_version *int64 ) ( doc Doc , err error ) {
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		doc , tx_err = deleteTx( tx , user_id , collection , id , if_version , now )
		return
	} )
	return
}

// deleteTx is Delete's write, inside a transaction the caller holds.
func deleteTx( tx *sql.Tx , user_id uint64 , collection string , id string , if_version *int64 , now time.Time ) ( doc Doc , err error ) {
	row , err := readExisting( tx , user_id , collection , id )
	if err != nil { return }
	if row.found == false || row.deleted {
		err = ErrNotFound
		return
	}
	if err = checkVersion( if_version , true , row.version ); err != nil { return }
	seq , err := nextSeq( tx , user_id )
	if err != nil { return }
	doc = Doc{ Collection: collection , ID: id , Version: row.version + 1 , Seq: seq , UpdatedAt: fromMillis( millis( now ) ) , Deleted: true }
	_ , err = tx.Exec( `UPDATE docs SET version = ? , seq = ? , updated_at = ? , deleted = 1 , size = 0 , body = NULL
		WHERE user_id = ? AND collection = ? AND doc_id = ?` ,
		doc.Version , seq , millis( now ) , user_id , collection , id )
	return
}

// Get is one live document, body included.
func ( store *Store ) Get( user_id uint64 , collection string , id string ) ( doc Doc , err error ) {
	var updated int64
	err = store.db.QueryRow( `SELECT version , seq , updated_at , size , body FROM docs
		WHERE user_id = ? AND collection = ? AND doc_id = ? AND deleted = 0` ,
		user_id , collection , id ).Scan( &doc.Version , &doc.Seq , &updated , &doc.Size , &doc.Body )
	if errors.Is( err , sql.ErrNoRows ) {
		err = ErrNotFound
		return
	}
	doc.Collection = collection
	doc.ID = id
	doc.UpdatedAt = fromMillis( updated )
	return
}

// List is one page of a collection's live documents, by id, and how many
// there are in all. with_bodies includes the ciphertext. max_bytes, when
// above zero, ends the page early once its bodies add up to that much (it
// always holds at least one document), so one request cannot pull limit
// times the largest document into memory; the caller's next page carries on
// from where it stopped.
func ( store *Store ) List( user_id uint64 , collection string , offset int , limit int , with_bodies bool , max_bytes int ) ( docs []Doc , total int , err error ) {
	err = store.db.QueryRow( `SELECT COUNT(*) FROM docs WHERE user_id = ? AND collection = ? AND deleted = 0` ,
		user_id , collection ).Scan( &total )
	if err != nil { return }
	body_column := "NULL"
	if with_bodies { body_column = "body" }
	rows , err := store.db.Query( `SELECT doc_id , version , seq , updated_at , size , `+ body_column +` FROM docs
		WHERE user_id = ? AND collection = ? AND deleted = 0 ORDER BY doc_id LIMIT ? OFFSET ?` ,
		user_id , collection , limit , offset )
	if err != nil { return }
	defer rows.Close()
	docs = []Doc{}
	used := 0
	for rows.Next() {
		doc := Doc{ Collection: collection }
		var updated int64
		if err = rows.Scan( &doc.ID , &doc.Version , &doc.Seq , &updated , &doc.Size , &doc.Body ); err != nil { return }
		if with_bodies && max_bytes > 0 && len( docs ) > 0 && used + doc.Size > max_bytes { break }
		used += doc.Size
		doc.UpdatedAt = fromMillis( updated )
		docs = append( docs , doc )
	}
	err = rows.Err()
	return
}

// TombstoneBytes is what a tombstone counts against the quota until it is
// purged, so writing and deleting over and over cannot grow an account
// without limit.
const TombstoneBytes = 128

// Usage is what an account's (or a folder's) documents add up to.
type Usage struct {
	// Bytes and Docs are the live documents.
	Bytes int64
	Docs  int
	// Tombstones are the deletes not yet purged.
	Tombstones int
}

// Charged is what counts against a quota: the live documents and
// TombstoneBytes for each tombstone.
func ( usage Usage ) Charged() int64 { return usage.Bytes + int64( usage.Tombstones ) * TombstoneBytes }

// Usage is what the account's documents add up to, from the running totals
// (one row, however many documents there are).
func ( store *Store ) Usage( user_id uint64 ) ( usage Usage , err error ) {
	usage , err = scanUsage( store.db.QueryRow( usageQuery , user_id ) )
	return
}

const usageQuery = `SELECT bytes , docs , tombs FROM usage WHERE user_id = ? AND collection = ''`

func readUsage( tx *sql.Tx , user_id uint64 ) ( usage Usage , err error ) {
	usage , err = scanUsage( tx.QueryRow( usageQuery , user_id ) )
	return
}

func scanUsage( row *sql.Row ) ( usage Usage , err error ) {
	err = row.Scan( &usage.Bytes , &usage.Docs , &usage.Tombstones )
	if errors.Is( err , sql.ErrNoRows ) { err = nil }
	return
}

// Changes is what changed in an account after change number since, oldest
// first, deletes included, without bodies; more says another page follows.
// A client that last synced before tombstones it never saw were purged gets
// ErrSyncExpired and has to start again from 0 (a client starting from 0 has
// nothing that a missed delete could leave behind).
func ( store *Store ) Changes( user_id uint64 , since int64 , limit int ) ( docs []Doc , more bool , err error ) {
	docs , more , err = store.ChangesIn( user_id , "" , since , limit )
	return
}

// ChangesIn is Changes limited to the folder root and every folder under it
// as they are now; root "" is the whole account. A document moved out of the
// subtree drops out of it without a tombstone.
func ( store *Store ) ChangesIn( user_id uint64 , root string , since int64 , limit int ) ( docs []Doc , more bool , err error ) {
	if since > 0 {
		var horizon int64
		err = store.db.QueryRow( `SELECT horizon FROM counters WHERE user_id = ?` , user_id ).Scan( &horizon )
		if errors.Is( err , sql.ErrNoRows ) { err = nil }
		if err != nil { return }
		if since < horizon {
			err = ErrSyncExpired
			return
		}
	}
	query := `SELECT collection , doc_id , version , seq , updated_at , deleted , size FROM docs
		WHERE user_id = ? AND seq > ? ORDER BY seq LIMIT ?`
	arguments := []any{ user_id , since , limit + 1 }
	if root != "" {
		query = `WITH RECURSIVE sub ( id ) AS (
				SELECT id FROM collections WHERE user_id = ? AND id = ?
				UNION ALL SELECT c.id FROM collections c JOIN sub ON c.parent = sub.id WHERE c.user_id = ?
			) SELECT collection , doc_id , version , seq , updated_at , deleted , size FROM docs
			WHERE user_id = ? AND seq > ? AND collection IN ( SELECT id FROM sub ) ORDER BY seq LIMIT ?`
		arguments = []any{ user_id , root , user_id , user_id , since , limit + 1 }
	}
	rows , err := store.db.Query( query , arguments... )
	if err != nil { return }
	defer rows.Close()
	docs = []Doc{}
	for rows.Next() {
		var doc Doc
		var updated int64
		var deleted int
		if err = rows.Scan( &doc.Collection , &doc.ID , &doc.Version , &doc.Seq , &updated , &deleted , &doc.Size ); err != nil { return }
		doc.UpdatedAt = fromMillis( updated )
		doc.Deleted = deleted != 0
		docs = append( docs , doc )
	}
	if err = rows.Err(); err != nil { return }
	if len( docs ) > limit {
		docs = docs[ :limit ]
		more = true
	}
	return
}
