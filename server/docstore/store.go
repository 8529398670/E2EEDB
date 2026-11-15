// Package docstore is the end-to-end encrypted document store: a SQLite file
// (<app dir>/docs.db) apart from the bolt database, holding documents clients
// encrypted with keys this server never sees.
//
// What it stores per document is only what routing and sync need: the account
// it belongs to, its collection id and its own id, a version, a change sequence
// number, when it last changed, its size, and the ciphertext. It never parses
// the ciphertext beyond checking its first byte names the envelope kind (see
// ValidEnvelope), and it has no key that could open it. That is why this
// package imports no crypto: the server's own key (server/encryption) has
// nothing to do here, and rotating it leaves docs.db alone.
//
// SQLite runs in WAL mode, so readers never wait on the writer. Every write is
// one IMMEDIATE transaction, which takes the write lock up front: the checks a
// write makes (its expected version, the account's quota) and the write itself
// see the same state. Lookups that write nothing go through a second,
// read-only handle whose transactions are deferred, so they never queue
// behind a writer.
package docstore

import (
	sql "database/sql"
	errors "errors"
	fmt "fmt"
	os "os"
	strings "strings"

	_ "modernc.org/sqlite"
)

// Store is one open docs.db.
type Store struct {
	// db is for writes: its transactions take the write lock at once.
	db   *sql.DB
	// read is read-only, with deferred transactions, for every lookup.
	read *sql.DB
	path string
}

// querier is a *sql.DB or a *sql.Tx, for lookups that run either inside a
// write or on their own.
type querier interface {
	Query( query string , arguments ...any ) ( *sql.Rows , error )
	QueryRow( query string , arguments ...any ) *sql.Row
}

// Errors a caller tells apart.
var (
	ErrNotFound    = errors.New( "no such document" )
	ErrConflict    = errors.New( "version_conflict" )
	ErrTooLarge    = errors.New( "doc_too_large" )
	ErrQuota       = errors.New( "quota_exceeded" )
	// ErrShareQuota: a scoped key's write would take its folder past what a
	// share may hold (Limits.ShareQuotaBytes).
	ErrShareQuota  = errors.New( "share_quota_exceeded" )
	ErrSyncExpired = errors.New( "sync_expired" )
)

// ConflictError is ErrConflict with what is there now, so a client can show it
// or retry. Current is 0 and Live false when there is no live document.
type ConflictError struct {
	Current int64
	Live    bool
}

func ( conflict *ConflictError ) Error() string { return ErrConflict.Error() }
func ( conflict *ConflictError ) Unwrap() error { return ErrConflict }

// dsn opens path in WAL mode. busy_timeout lets a second writer wait for the
// first rather than fail. For the write handle, _txlock=immediate makes
// BeginTx take the write lock at once; the read-only handle keeps SQLite's
// deferred transactions, which in WAL mode read a snapshot and wait on no
// one.
func dsn( path string , read_only bool ) ( result string ) {
	result = "file:" + path +
		"?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)"
	if read_only {
		result += "&mode=ro"
	} else {
		result += "&_txlock=immediate"
	}
	return
}

// Open opens or creates the store at path and brings its schema up to date.
// The file is created 0600, like the bolt database beside it.
func Open( path string ) ( store *Store , err error ) {
	file , err := os.OpenFile( path , os.O_RDWR | os.O_CREATE , 0o600 )
	if err != nil { return }
	file.Close()
	handle , err := sql.Open( "sqlite" , dsn( path , false ) )
	if err != nil { return }
	store = &Store{ db: handle , path: path }
	if err = store.migrate(); err != nil {
		handle.Close()
		store = nil
		return
	}
	// Opened after the migrations, so the file is already in WAL mode.
	if store.read , err = sql.Open( "sqlite" , dsn( path , true ) ); err != nil {
		handle.Close()
		store = nil
	}
	return
}

// Close closes the store.
func ( store *Store ) Close() ( err error ) {
	err = errors.Join( store.read.Close() , store.db.Close() )
	return
}

// Ping is whether the store answers, for /api/ready.
func ( store *Store ) Ping() ( err error ) {
	var version int
	err = store.db.QueryRow( "PRAGMA user_version" ).Scan( &version )
	if err == nil && version != len( migrations ) {
		err = fmt.Errorf( "docs.db is at schema %d, this build expects %d" , version , len( migrations ) )
	}
	return
}

// Snapshot writes a consistent copy of the store at path to out, whether or
// not a server has it open: VACUUM INTO reads one snapshot of the database,
// WAL included, and writes a self-contained file. out must not exist. A store
// that was never created (no docs.db yet) answers os.ErrNotExist.
func Snapshot( path string , out string ) ( err error ) {
	if _ , err = os.Stat( path ); err != nil { return }
	handle , err := sql.Open( "sqlite" , dsn( path , true ) )
	if err != nil { return }
	defer handle.Close()
	_ , err = handle.Exec( "VACUUM INTO '" + strings.ReplaceAll( out , "'" , "''" ) + "'" )
	if err == nil {
		err = os.Chmod( out , 0o600 )
	}
	return
}

// migrations are the schema, one step per version: PRAGMA user_version is how
// many have run. Append; never edit one that has shipped.
var migrations = []string{
	// docs: every document and tombstone. keyrings: each account's wrapped
	// master key. counters: each account's change numbers and purge horizon
	// (one counter per account, so nobody's numbers show another account's
	// writes). collections: the folder tree. lock is a folder's lockbox,
	// opaque text the client wraps (README.md, "Crypto format"), "" for none
	// yet. by_key is the id of the scoped API key that made it ("" when the
	// account itself did), so a client can refuse to write into a folder
	// someone it shared with made. born is random and never changes: it
	// tells a folder from a later one that reuses its id, so a scoped key
	// minted for one never reaches the other. next_lock is the lockbox of
	// the keys a rotation (StageRotation) is moving the folder to, "" when
	// none is under way.
	//
	// graves: the folders deleted lately, each with the folders it was in
	// then (above: " id:born " for itself and each one over it), so a
	// scoped key may make one again under its old id (undo) only when it
	// was inside that key's folder. Swept with the tombstones, and capped
	// with them (max_tombstones per account, oldest first). Making the id
	// again removes its grave.
	//
	// usage: running totals of each account's documents, per collection and
	// (collection "") for the whole account, kept by the triggers below so
	// every statement that touches docs keeps them right. bytes and docs
	// count the live documents, tombs the tombstones not yet purged,
	// updated_at is the last time a document there changed, deletes
	// included. graves (the account's row only) counts its graves, which
	// the quota charges like tombstones. A quota check reads one row instead
	// of summing the account.
	`CREATE TABLE docs (
		user_id    INTEGER NOT NULL,
		collection TEXT    NOT NULL,
		doc_id     TEXT    NOT NULL,
		version    INTEGER NOT NULL,
		seq        INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		deleted    INTEGER NOT NULL DEFAULT 0,
		size       INTEGER NOT NULL,
		body       BLOB,
		PRIMARY KEY ( user_id , collection , doc_id )
	) WITHOUT ROWID;
	CREATE INDEX docs_by_seq ON docs ( user_id , seq );
	CREATE TABLE keyrings (
		user_id    INTEGER PRIMARY KEY,
		body       TEXT    NOT NULL,
		version    INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE counters (
		user_id INTEGER PRIMARY KEY,
		seq     INTEGER NOT NULL DEFAULT 0,
		horizon INTEGER NOT NULL DEFAULT 0
	);
	CREATE TABLE collections (
		user_id    INTEGER NOT NULL,
		id         TEXT    NOT NULL,
		name       TEXT    NOT NULL,
		parent     TEXT    NOT NULL DEFAULT '',
		position   INTEGER NOT NULL,
		version    INTEGER NOT NULL,
		seq        INTEGER NOT NULL,
		updated_at INTEGER NOT NULL,
		lock       TEXT    NOT NULL DEFAULT '',
		next_lock  TEXT    NOT NULL DEFAULT '',
		by_key     TEXT    NOT NULL DEFAULT '',
		born       INTEGER NOT NULL,
		PRIMARY KEY ( user_id , id )
	) WITHOUT ROWID;
	CREATE INDEX collections_by_parent ON collections ( user_id , parent , position );
	CREATE TABLE trees (
		user_id INTEGER PRIMARY KEY,
		seq     INTEGER NOT NULL
	);
	CREATE TABLE graves (
		user_id    INTEGER NOT NULL,
		id         TEXT    NOT NULL,
		above      TEXT    NOT NULL,
		deleted_at INTEGER NOT NULL,
		PRIMARY KEY ( user_id , id )
	) WITHOUT ROWID;
	CREATE TABLE usage (
		user_id    INTEGER NOT NULL,
		collection TEXT    NOT NULL,
		bytes      INTEGER NOT NULL DEFAULT 0,
		docs       INTEGER NOT NULL DEFAULT 0,
		tombs      INTEGER NOT NULL DEFAULT 0,
		graves     INTEGER NOT NULL DEFAULT 0,
		updated_at INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY ( user_id , collection )
	) WITHOUT ROWID;
	CREATE TRIGGER docs_stay_put BEFORE UPDATE OF user_id , collection , doc_id ON docs
	WHEN OLD.user_id != NEW.user_id OR OLD.collection != NEW.collection OR OLD.doc_id != NEW.doc_id BEGIN
		SELECT RAISE( ABORT , 'a document row never moves: write the new place and delete the old' );
	END;
	CREATE TRIGGER docs_usage_insert AFTER INSERT ON docs BEGIN
		INSERT INTO usage ( user_id , collection , bytes , docs , tombs , updated_at ) VALUES
			( NEW.user_id , NEW.collection , NEW.size * ( NEW.deleted = 0 ) , NEW.deleted = 0 , NEW.deleted != 0 , NEW.updated_at ),
			( NEW.user_id , '' , NEW.size * ( NEW.deleted = 0 ) , NEW.deleted = 0 , NEW.deleted != 0 , NEW.updated_at )
		ON CONFLICT ( user_id , collection ) DO UPDATE SET bytes = bytes + excluded.bytes , docs = docs + excluded.docs ,
			tombs = tombs + excluded.tombs , updated_at = MAX( updated_at , excluded.updated_at );
	END;
	CREATE TRIGGER docs_usage_update AFTER UPDATE ON docs BEGIN
		INSERT INTO usage ( user_id , collection , bytes , docs , tombs , updated_at ) VALUES
			( NEW.user_id , NEW.collection , NEW.size * ( NEW.deleted = 0 ) - OLD.size * ( OLD.deleted = 0 ) ,
				( NEW.deleted = 0 ) - ( OLD.deleted = 0 ) , ( NEW.deleted != 0 ) - ( OLD.deleted != 0 ) , NEW.updated_at ),
			( NEW.user_id , '' , NEW.size * ( NEW.deleted = 0 ) - OLD.size * ( OLD.deleted = 0 ) ,
				( NEW.deleted = 0 ) - ( OLD.deleted = 0 ) , ( NEW.deleted != 0 ) - ( OLD.deleted != 0 ) , NEW.updated_at )
		ON CONFLICT ( user_id , collection ) DO UPDATE SET bytes = bytes + excluded.bytes , docs = docs + excluded.docs ,
			tombs = tombs + excluded.tombs , updated_at = MAX( updated_at , excluded.updated_at );
	END;
	CREATE TRIGGER graves_usage_insert AFTER INSERT ON graves BEGIN
		INSERT INTO usage ( user_id , collection , graves ) VALUES ( NEW.user_id , '' , 1 )
		ON CONFLICT ( user_id , collection ) DO UPDATE SET graves = graves + 1;
	END;
	CREATE TRIGGER graves_usage_delete AFTER DELETE ON graves BEGIN
		UPDATE usage SET graves = graves - 1 WHERE user_id = OLD.user_id AND collection = '';
	END;
	CREATE TRIGGER docs_usage_delete AFTER DELETE ON docs BEGIN
		UPDATE usage SET bytes = bytes - OLD.size * ( OLD.deleted = 0 ) , docs = docs - ( OLD.deleted = 0 ) , tombs = tombs - ( OLD.deleted != 0 )
			WHERE user_id = OLD.user_id AND collection IN ( OLD.collection , '' );
	END;`,
}

func ( store *Store ) migrate() ( err error ) {
	var version int
	if err = store.db.QueryRow( "PRAGMA user_version" ).Scan( &version ); err != nil { return }
	if version > len( migrations ) {
		err = fmt.Errorf( "docs.db is at schema %d, newer than this build (%d)" , version , len( migrations ) )
		return
	}
	for ; version < len( migrations ) ; version++ {
		err = store.write( func( tx *sql.Tx ) ( step_err error ) {
			if _ , step_err = tx.Exec( migrations[ version ] ); step_err != nil { return }
			_ , step_err = tx.Exec( fmt.Sprintf( "PRAGMA user_version = %d" , version + 1 ) )
			return
		} )
		if err != nil {
			err = fmt.Errorf( "docs.db migration %d: %w" , version + 1 , err )
			return
		}
	}
	return
}

// write runs fn in one IMMEDIATE transaction, committed when fn returns nil.
func ( store *Store ) write( fn func( tx *sql.Tx ) error ) ( err error ) {
	tx , err := store.db.Begin()
	if err != nil { return }
	if err = fn( tx ); err != nil {
		tx.Rollback()
		return
	}
	err = tx.Commit()
	return
}

// nextSeq is the account's next change number. Each account has its own
// counter: one shared by all would let anyone who syncs see, from the gaps,
// how much everyone else writes.
func nextSeq( tx *sql.Tx , user_id uint64 ) ( seq int64 , err error ) {
	err = tx.QueryRow( `INSERT INTO counters ( user_id , seq ) VALUES ( ? , 1 )
		ON CONFLICT ( user_id ) DO UPDATE SET seq = seq + 1 RETURNING seq` , user_id ).Scan( &seq )
	return
}
