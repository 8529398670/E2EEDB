package docstore

import (
	sql "database/sql"
	errors "errors"
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
//   - An account with more than max_tombstones tombstones (0: no cap) loses
//     its oldest ones early, the same way.
//   - Documents, folders and keyrings of accounts that no longer exist are removed.
//     Deleting an account (from the web, the control socket or `manage`) only
//     touches the bolt database; this is where its documents go, within the
//     hour, the same way the template sweeps a deleted account's files.
//
// exists says whether an account is still there.
func ( store *Store ) Sweep( now time.Time , tombstone_days int , max_tombstones int , exists func( user_id uint64 ) bool ) ( swept Swept , err error ) {
	cutoff := millis( now.Add( -time.Duration( tombstone_days ) * 24 * time.Hour ) )
	err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
		// Each account's horizon moves past its own newest purged tombstone.
		_ , tx_err = tx.Exec( `UPDATE counters SET horizon = MAX( horizon , (
				SELECT MAX( seq ) FROM docs WHERE docs.user_id = counters.user_id AND deleted = 1 AND updated_at < ? ) )
			WHERE EXISTS ( SELECT 1 FROM docs WHERE docs.user_id = counters.user_id AND deleted = 1 AND updated_at < ? )` , cutoff , cutoff )
		if tx_err != nil { return }
		result , tx_err := tx.Exec( `DELETE FROM docs WHERE deleted = 1 AND updated_at < ?` , cutoff )
		if tx_err != nil { return }
		swept.Tombstones , _ = result.RowsAffected()
		// A deleted folder's id stays reusable by a scoped key (undo) as
		// long as its documents' tombstones last.
		_ , tx_err = tx.Exec( `DELETE FROM graves WHERE deleted_at < ?` , cutoff )
		return
	} )
	if err != nil { return }
	if max_tombstones > 0 {
		var purged int64
		if purged , err = store.capTombstones( max_tombstones ); err != nil { return }
		swept.Tombstones += purged
	}
	// A folder's totals go once nothing of it is left.
	if _ , err = store.db.Exec( `DELETE FROM usage WHERE collection != '' AND docs = 0 AND tombs = 0` ); err != nil { return }

	owners , err := store.owners()
	if err != nil { return }
	for _ , user_id := range owners {
		if exists( user_id ) { continue }
		err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
			for _ , table := range accountTables {
				if _ , tx_err = tx.Exec( `DELETE FROM `+ table +` WHERE user_id = ?` , user_id ); tx_err != nil { return }
			}
			return
		} )
		if err != nil { return }
		swept.Accounts++
	}
	return
}

// capTombstones purges the oldest tombstones of each account holding more
// than limit, one account per transaction, moving its horizon past them.
func ( store *Store ) capTombstones( limit int ) ( purged int64 , err error ) {
	rows , err := store.read.Query( `SELECT user_id FROM usage WHERE collection = '' AND tombs > ?` , limit )
	if err != nil { return }
	over := []uint64{}
	for rows.Next() {
		var user_id uint64
		if err = rows.Scan( &user_id ); err != nil {
			rows.Close()
			return
		}
		over = append( over , user_id )
	}
	rows.Close()
	if err = rows.Err(); err != nil { return }
	for _ , user_id := range over {
		err = store.write( func( tx *sql.Tx ) ( tx_err error ) {
			// The newest tombstone to go: the limit newest stay.
			var cutoff int64
			tx_err = tx.QueryRow( `SELECT seq FROM docs WHERE user_id = ? AND deleted = 1 ORDER BY seq DESC LIMIT 1 OFFSET ?` ,
				user_id , limit ).Scan( &cutoff )
			if errors.Is( tx_err , sql.ErrNoRows ) { tx_err = nil; return }
			if tx_err != nil { return }
			_ , tx_err = tx.Exec( `UPDATE counters SET horizon = MAX( horizon , ? ) WHERE user_id = ?` , cutoff , user_id )
			if tx_err != nil { return }
			result , tx_err := tx.Exec( `DELETE FROM docs WHERE user_id = ? AND deleted = 1 AND seq <= ?` , user_id , cutoff )
			if tx_err != nil { return }
			gone , _ := result.RowsAffected()
			purged += gone
			return
		} )
		if err != nil { return }
	}
	return
}

// accountTables are the tables with rows of each account.
var accountTables = []string{ "docs" , "usage" , "collections" , "graves" , "trees" , "keyrings" , "counters" }

// owners is every account with a row in any of accountTables.
func ( store *Store ) owners() ( result []uint64 , err error ) {
	query := ""
	for index , table := range accountTables {
		if index > 0 { query += " UNION " }
		query += "SELECT user_id FROM " + table
	}
	rows , err := store.read.Query( query )
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
