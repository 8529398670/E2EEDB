package docstore

import (
	testing "testing"
	time "time"
)

// Lookups use the read-only handle, so a writer holding the write lock
// does not hold them up: a scoped key's GET /api/collections, and the
// rotation check before minting a key, answer at once.
func TestLookupsDoNotWaitOnAWriter( t *testing.T ) {
	store , _ := open( t )
	for _ , id := range []string{ "a" , "b" } {
		parent := ""
		if id == "b" { parent = "a" }
		if _ , err := store.CreateCollection( 1 , id , CollectionChange{ Parent: &parent } , limits ); err != nil { t.Fatal( err ) }
	}
	tx , err := store.db.Begin()
	if err != nil { t.Fatal( err ) }
	defer tx.Rollback()
	if _ , err = tx.Exec( `UPDATE counters SET seq = seq + 1 WHERE user_id = 1` ); err != nil { t.Fatal( err ) }

	done := make( chan error , 1 )
	go func() {
		ids , err := store.Subtree( 1 , "a" )
		if err == nil && same( ids , "a" , "b" ) == false { t.Errorf( "subtree %v" , ids ) }
		if err == nil { _ , err = store.InRotation( 1 , "b" ) }
		if err == nil {
			var inside bool
			inside , err = store.Within( 1 , "a" , "b" )
			if inside == false { t.Error( "b is not within a" ) }
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil { t.Fatal( err ) }
	case <-time.After( 2 * time.Second ):
		t.Fatal( "lookups waited on the open write transaction" )
	}
}

// A deleted account's rows go from every table, even when all that is left
// of it is its counters, its tree number or a grave.
func TestSweepTakesEveryTableOfAGoneAccount( t *testing.T ) {
	store , _ := open( t )
	for _ , statement := range []string{
		`INSERT INTO counters ( user_id , seq ) VALUES ( 9 , 3 )`,
		`INSERT INTO trees ( user_id , seq ) VALUES ( 9 , 3 )`,
		`INSERT INTO graves ( user_id , id , above , deleted_at ) VALUES ( 9 , 'x' , ' x:1 ' , 0 )`,
	} {
		if _ , err := store.db.Exec( statement ); err != nil { t.Fatal( err ) }
	}
	swept , err := store.Sweep( time.Now() , 30 , 0 , func( user_id uint64 ) bool { return user_id != 9 } )
	if err != nil || swept.Accounts != 1 { t.Fatalf( "sweep: %+v %v" , swept , err ) }
	for _ , table := range accountTables {
		var left int
		store.db.QueryRow( `SELECT COUNT(*) FROM ` + table + ` WHERE user_id = 9` ).Scan( &left )
		if left != 0 { t.Errorf( "%s kept %d rows" , table , left ) }
	}
}
