package docstore

import (
	sql "database/sql"
	errors "errors"
	time "time"
)

// The keyring is an account's master key, wrapped under a key derived from a
// passphrase (see README.md, "Keyring"). The server stores it as opaque text:
// it holds nothing that could unwrap it, and offering it to anyone signed in
// as the account is the point -- it is how the viewer unlocks with a
// passphrase instead of the raw key.

// KeyringMaxBytes bounds the stored text; a real keyring is a few hundred.
const KeyringMaxBytes = 4096

// Keyring is the stored text and its version.
type Keyring struct {
	Body      string
	Version   int64
	UpdatedAt time.Time
}

// GetKeyring is the account's keyring, or ErrNotFound.
func ( store *Store ) GetKeyring( user_id uint64 ) ( keyring Keyring , err error ) {
	var updated int64
	err = store.db.QueryRow( `SELECT body , version , updated_at FROM keyrings WHERE user_id = ?` , user_id ).
		Scan( &keyring.Body , &keyring.Version , &updated )
	if errors.Is( err , sql.ErrNoRows ) {
		err = ErrNotFound
		return
	}
	keyring.UpdatedAt = fromMillis( updated )
	return
}

// SetKeyring replaces the keyring, under the same if_version rule as a
// document (nil unconditional, 0 none yet, n at n).
func ( store *Store ) SetKeyring( user_id uint64 , body string , if_version *int64 ) ( keyring Keyring , err error ) {
	if len( body ) == 0 || len( body ) > KeyringMaxBytes {
		err = ErrTooLarge
		return
	}
	now := time.Now()
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		var current int64
		tx_err = tx.QueryRow( `SELECT version FROM keyrings WHERE user_id = ?` , user_id ).Scan( &current )
		found := tx_err == nil
		if errors.Is( tx_err , sql.ErrNoRows ) { tx_err = nil }
		if tx_err != nil { return }
		if tx_err = checkVersion( if_version , found , current ); tx_err != nil { return }
		keyring = Keyring{ Body: body , Version: current + 1 , UpdatedAt: fromMillis( millis( now ) ) }
		_ , tx_err = tx.Exec( `INSERT INTO keyrings ( user_id , body , version , updated_at ) VALUES ( ? , ? , ? , ? )
			ON CONFLICT ( user_id ) DO UPDATE SET body = excluded.body , version = excluded.version , updated_at = excluded.updated_at` ,
			user_id , body , keyring.Version , millis( now ) )
		return
	} )
	return
}
