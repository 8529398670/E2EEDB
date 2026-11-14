package docstore

import (
	sql "database/sql"
	time "time"
)

// Swept is what one Sweep removed.
type Swept struct {
	Tombstones int64
	// Accounts is how many accounts that no longer exist had documents or a
	// keyring here, now removed.
	Accounts int
}

// Sweep is the hourly "docs" job:
//
//   - Tombstones older than tombstone_days are purged, and the purge horizon
//     moves past them, so a client that synced before them is told to start
//     again (ErrSyncExpired) instead of silently missing a delete.
//   - Documents, folders and keyrings of accounts that no longer exist are removed.
//     Deleting an account (from the web, the control socket or `manage`) only
//     touches the bolt database; this is where its documents go, within the
//     hour, the same way the template sweeps a deleted account's files.
//
// exists says whether an account is still there.
func ( store *Store ) Sweep( now time.Time , tombstone_days int , exists func( user_id uint64 ) bool ) ( swept Swept , err error ) {
	cutoff := millis( now.Add( -time.Duration( tombstone_days ) * 24 * time.Hour ) )
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		var newest sql.NullInt64
		tx_err = tx.QueryRow( `SELECT MAX( seq ) FROM docs WHERE deleted = 1 AND updated_at < ?` , cutoff ).Scan( &newest )
		if tx_err != nil || newest.Valid == false { return }
		result , tx_err := tx.Exec( `DELETE FROM docs WHERE deleted = 1 AND updated_at < ?` , cutoff )
		if tx_err != nil { return }
		swept.Tombstones , _ = result.RowsAffected()
		_ , tx_err = tx.Exec( `UPDATE meta SET value = MAX( value , ? ) WHERE key = 'horizon'` , newest.Int64 )
		return
	} )
	if err != nil { return }

	owners , err := store.owners()
	if err != nil { return }
	for _ , user_id := range owners {
		if exists( user_id ) { continue }
		err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
			for _ , table := range []string{ "docs" , "collections" , "trees" , "keyrings" } {
				if _ , tx_err = tx.Exec( `DELETE FROM `+ table +` WHERE user_id = ?` , user_id ); tx_err != nil { return }
			}
			return
		} )
		if err != nil { return }
		swept.Accounts++
	}
	return
}

// owners is every account with a document or a keyring here.
func ( store *Store ) owners() ( result []uint64 , err error ) {
	rows , err := store.db.Query( `SELECT DISTINCT user_id FROM docs UNION SELECT user_id FROM collections UNION SELECT user_id FROM keyrings` )
	if err != nil { return }
	defer rows.Close()
	for rows.Next() {
		var user_id uint64
		if err = rows.Scan( &user_id ); err != nil { return }
		result = append( result , user_id )
	}
	err = rows.Err()
	return
}
