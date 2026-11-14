package docstore

import (
	bytes "bytes"
	errors "errors"
	filepath "path/filepath"
	testing "testing"
	time "time"
)

var limits = Limits{ MaxDocBytes: 1024 , QuotaBytes: 0 }

func open( t *testing.T ) ( store *Store , path string ) {
	t.Helper()
	path = filepath.Join( t.TempDir() , "docs.db" )
	store , err := Open( path )
	if err != nil { t.Fatal( err ) }
	t.Cleanup( func() { store.Close() } )
	return
}

// envelope is a body the store accepts: right first byte, right length.
func envelope( fill byte , size int ) ( body []byte ) {
	body = bytes.Repeat( []byte{ fill } , size )
	body[ 0 ] = EnvelopeMaster
	return
}

func version( n int64 ) *int64 { return &n }

func TestSetGetVersions( t *testing.T ) {
	store , _ := open( t )
	first , err := store.Set( 1 , "notes" , "a" , envelope( 1 , 60 ) , nil , limits )
	if err != nil || first.Version != 1 || first.Seq != 1 { t.Fatalf( "first write: %+v %v" , first , err ) }
	second , err := store.Set( 1 , "notes" , "a" , envelope( 2 , 70 ) , version( 1 ) , limits )
	if err != nil || second.Version != 2 || second.Seq != 2 { t.Fatalf( "second write: %+v %v" , second , err ) }
	got , err := store.Get( 1 , "notes" , "a" )
	if err != nil || got.Version != 2 || got.Size != 70 || got.Body[ 1 ] != 2 { t.Fatalf( "get: %+v %v" , got , err ) }

	_ , err = store.Set( 1 , "notes" , "a" , envelope( 3 , 60 ) , version( 1 ) , limits )
	var conflict *ConflictError
	if errors.As( err , &conflict ) == false || conflict.Current != 2 || conflict.Live == false {
		t.Fatalf( "stale write should conflict at 2, got %v" , err )
	}
	if _ , err = store.Set( 1 , "notes" , "a" , envelope( 3 , 60 ) , version( 0 ) , limits ); errors.Is( err , ErrConflict ) == false {
		t.Fatalf( "if_version 0 on a live doc should conflict, got %v" , err )
	}
	if _ , err = store.Set( 1 , "notes" , "b" , envelope( 3 , 60 ) , version( 5 ) , limits ); errors.Is( err , ErrConflict ) == false {
		t.Fatalf( "if_version 5 on a missing doc should conflict, got %v" , err )
	}
}

func TestDeleteTombstoneAndRecreate( t *testing.T ) {
	store , _ := open( t )
	store.Set( 1 , "notes" , "a" , envelope( 1 , 60 ) , nil , limits )
	if _ , err := store.Delete( 1 , "notes" , "a" , version( 9 ) ); errors.Is( err , ErrConflict ) == false {
		t.Fatalf( "delete at the wrong version should conflict, got %v" , err )
	}
	gone , err := store.Delete( 1 , "notes" , "a" , version( 1 ) )
	if err != nil || gone.Version != 2 || gone.Deleted == false { t.Fatalf( "delete: %+v %v" , gone , err ) }
	if _ , err = store.Get( 1 , "notes" , "a" ); errors.Is( err , ErrNotFound ) == false { t.Fatalf( "get after delete: %v" , err ) }
	if _ , err = store.Delete( 1 , "notes" , "a" , nil ); errors.Is( err , ErrNotFound ) == false { t.Fatalf( "second delete: %v" , err ) }
	// Undoing a delete is writing it again with if_version 0.
	back , err := store.Set( 1 , "notes" , "a" , envelope( 1 , 60 ) , version( 0 ) , limits )
	if err != nil || back.Version != 3 { t.Fatalf( "recreate: %+v %v" , back , err ) }
}

func TestUsersAreApart( t *testing.T ) {
	store , _ := open( t )
	store.Set( 1 , "notes" , "a" , envelope( 1 , 60 ) , nil , limits )
	if _ , err := store.Get( 2 , "notes" , "a" ); errors.Is( err , ErrNotFound ) == false { t.Fatalf( "user 2 read user 1's doc: %v" , err ) }
	if _ , err := store.Delete( 2 , "notes" , "a" , nil ); errors.Is( err , ErrNotFound ) == false { t.Fatalf( "user 2 deleted user 1's doc: %v" , err ) }
	collections , total , _ := store.Collections( 2 , 0 , 10 )
	if total != 0 || len( collections ) != 0 { t.Fatalf( "user 2 sees collections: %+v" , collections ) }
	changes , _ , _ := store.Changes( 2 , 0 , 10 )
	if len( changes ) != 0 { t.Fatalf( "user 2 sees changes: %+v" , changes ) }
}

func TestListCollectionsAndChanges( t *testing.T ) {
	store , _ := open( t )
	for _ , id := range []string{ "c" , "a" , "b" } {
		store.Set( 1 , "notes" , id , envelope( 1 , 60 ) , nil , limits )
	}
	store.Set( 1 , "tasks" , "x" , envelope( 1 , 100 ) , nil , limits )
	store.Delete( 1 , "notes" , "b" , nil )

	docs , total , err := store.List( 1 , "notes" , 0 , 1 , false )
	if err != nil || total != 2 || len( docs ) != 1 || docs[ 0 ].ID != "a" || docs[ 0 ].Body != nil {
		t.Fatalf( "list page 1: %+v total %d %v" , docs , total , err )
	}
	docs , _ , _ = store.List( 1 , "notes" , 1 , 1 , true )
	if len( docs ) != 1 || docs[ 0 ].ID != "c" || len( docs[ 0 ].Body ) != 60 { t.Fatalf( "list page 2 with bodies: %+v" , docs ) }

	collections , total , _ := store.Collections( 1 , 0 , 10 )
	if total != 2 || collections[ 0 ].Name != "notes" || collections[ 0 ].Count != 2 || collections[ 1 ].Bytes != 100 {
		t.Fatalf( "collections: %+v" , collections )
	}
	bytes_used , count , _ := store.Usage( 1 )
	if bytes_used != 220 || count != 3 { t.Fatalf( "usage: %d bytes %d docs" , bytes_used , count ) }

	changes , more , _ := store.Changes( 1 , 0 , 3 )
	if len( changes ) != 3 || more == false || changes[ 0 ].ID != "c" { t.Fatalf( "changes page 1: %+v more %v" , changes , more ) }
	changes , more , _ = store.Changes( 1 , changes[ 2 ].Seq , 3 )
	// b's row moved to the end when it was deleted: it is the one change left.
	if len( changes ) != 1 || more || changes[ 0 ].ID != "b" || changes[ 0 ].Deleted == false {
		t.Fatalf( "changes page 2 should end with b's tombstone: %+v more %v" , changes , more )
	}
}

func TestLimits( t *testing.T ) {
	store , _ := open( t )
	quota := Limits{ MaxDocBytes: 100 , QuotaBytes: 150 }
	if _ , err := store.Set( 1 , "n" , "big" , envelope( 1 , 101 ) , nil , quota ); errors.Is( err , ErrTooLarge ) == false { t.Fatalf( "too large: %v" , err ) }
	store.Set( 1 , "n" , "a" , envelope( 1 , 100 ) , nil , quota )
	if _ , err := store.Set( 1 , "n" , "b" , envelope( 1 , 60 ) , nil , quota ); errors.Is( err , ErrQuota ) == false { t.Fatalf( "quota: %v" , err ) }
	// Replacing a document counts its new size, not both.
	if _ , err := store.Set( 1 , "n" , "a" , envelope( 1 , 90 ) , nil , quota ); err != nil { t.Fatalf( "replace within quota: %v" , err ) }
	// Another account has its own quota.
	if _ , err := store.Set( 2 , "n" , "a" , envelope( 1 , 100 ) , nil , quota ); err != nil { t.Fatalf( "user 2: %v" , err ) }
}

func TestKeyring( t *testing.T ) {
	store , _ := open( t )
	if _ , err := store.GetKeyring( 1 ); errors.Is( err , ErrNotFound ) == false { t.Fatalf( "no keyring yet: %v" , err ) }
	first , err := store.SetKeyring( 1 , `{"v":1}` , version( 0 ) )
	if err != nil || first.Version != 1 { t.Fatalf( "set: %+v %v" , first , err ) }
	if _ , err = store.SetKeyring( 1 , `{"v":1}` , version( 0 ) ); errors.Is( err , ErrConflict ) == false { t.Fatalf( "second create should conflict: %v" , err ) }
	second , err := store.SetKeyring( 1 , `{"v":2}` , version( 1 ) )
	got , _ := store.GetKeyring( 1 )
	if err != nil || second.Version != 2 || got.Body != `{"v":2}` { t.Fatalf( "replace: %+v %+v %v" , second , got , err ) }
}

func TestSweep( t *testing.T ) {
	store , _ := open( t )
	store.Set( 1 , "n" , "a" , envelope( 1 , 60 ) , nil , limits )
	store.Set( 1 , "n" , "b" , envelope( 1 , 60 ) , nil , limits )
	gone , _ := store.Delete( 1 , "n" , "a" , nil )
	store.Set( 7 , "n" , "x" , envelope( 1 , 60 ) , nil , limits )
	store.SetKeyring( 7 , "k" , nil )

	// Nothing is old enough yet: the tombstone stays and a sync from 1 works.
	swept , err := store.Sweep( time.Now() , 30 , func( id uint64 ) bool { return true } )
	if err != nil || swept.Tombstones != 0 { t.Fatalf( "early sweep: %+v %v" , swept , err ) }
	if _ , _ , err = store.Changes( 1 , 1 , 10 ); err != nil { t.Fatalf( "sync before purge: %v" , err ) }

	// 31 days on, the tombstone goes, a client that never saw it must start
	// again, one that did may carry on, and account 7 (deleted) is cleared.
	swept , err = store.Sweep( time.Now().Add( 31 * 24 * time.Hour ) , 30 , func( id uint64 ) bool { return id == 1 } )
	if err != nil || swept.Tombstones != 1 || swept.Accounts != 1 { t.Fatalf( "sweep: %+v %v" , swept , err ) }
	if _ , _ , err = store.Changes( 1 , 1 , 10 ); errors.Is( err , ErrSyncExpired ) == false { t.Fatalf( "sync from before the purge: %v" , err ) }
	if _ , _ , err = store.Changes( 1 , gone.Seq , 10 ); err != nil { t.Fatalf( "sync from the purged tombstone itself: %v" , err ) }
	if _ , _ , err = store.Changes( 1 , 0 , 10 ); err != nil { t.Fatalf( "a fresh sync is never expired: %v" , err ) }
	if _ , err = store.Get( 1 , "n" , "b" ); err != nil { t.Fatalf( "live doc swept: %v" , err ) }
	if _ , err = store.Get( 7 , "n" , "x" ); errors.Is( err , ErrNotFound ) == false { t.Fatalf( "deleted account's doc kept: %v" , err ) }
	if _ , err = store.GetKeyring( 7 ); errors.Is( err , ErrNotFound ) == false { t.Fatalf( "deleted account's keyring kept: %v" , err ) }
}

func TestSnapshotAndReopen( t *testing.T ) {
	store , path := open( t )
	store.Set( 1 , "n" , "a" , envelope( 4 , 60 ) , nil , limits )
	out := filepath.Join( t.TempDir() , "copy.db" )
	if err := Snapshot( path , out ); err != nil { t.Fatal( err ) }
	copy , err := Open( out )
	if err != nil { t.Fatal( err ) }
	defer copy.Close()
	got , err := copy.Get( 1 , "n" , "a" )
	if err != nil || got.Body[ 1 ] != 4 { t.Fatalf( "snapshot lost the doc: %+v %v" , got , err ) }
	if err = copy.Ping(); err != nil { t.Fatal( err ) }
}

func TestValidation( t *testing.T ) {
	for _ , name := range []string{ "notes" , "a_b-C9" } {
		if ValidCollection( name ) == false { t.Errorf( "%q should be a valid collection" , name ) }
	}
	for _ , name := range []string{ "" , "a/b" , "a.b" , "é" } {
		if ValidCollection( name ) { t.Errorf( "%q should not be a valid collection" , name ) }
	}
	for _ , id := range []string{ "." , ".." , "a/b" , "" } {
		if ValidDocID( id ) { t.Errorf( "%q should not be a valid id" , id ) }
	}
	if ValidEnvelope( []byte( `{"plain":"json","that":"is long enough to pass a length check alone"}` ) ) {
		t.Error( "plaintext JSON must not pass as an envelope" )
	}
}
