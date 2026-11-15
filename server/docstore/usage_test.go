package docstore

import (
	sql "database/sql"
	errors "errors"
	fmt "fmt"
	rand "math/rand"
	testing "testing"
	time "time"
)

// fill writes n documents of size bytes into collection, in one transaction
// through the real write path, so a test can have a big account quickly.
func fill( t *testing.T , store *Store , user_id uint64 , collection string , n int , size int ) {
	t.Helper()
	now := time.Now()
	err := store.write( func( tx *sql.Tx ) ( tx_err error ) {
		if _ , tx_err = ensureCollection( tx , user_id , collection , Limits{ MaxCollections: 100000 } , now ); tx_err != nil { return }
		body := envelope( 1 , size )
		for index := 0 ; index < n ; index++ {
			if _ , tx_err = setTx( tx , user_id , collection , fmt.Sprintf( "d%07d" , index ) , body , nil , Limits{ MaxDocBytes: size } , now ); tx_err != nil { return }
		}
		return
	} )
	if err != nil { t.Fatal( err ) }
}

// checkTotals is whether the running totals say what summing docs says.
func checkTotals( t *testing.T , store *Store ) {
	t.Helper()
	rows , err := store.db.Query( `SELECT user_id , collection , SUM( size * ( deleted = 0 ) ) , SUM( deleted = 0 ) , SUM( deleted != 0 ) FROM docs GROUP BY user_id , collection
		UNION ALL SELECT user_id , '' , SUM( size * ( deleted = 0 ) ) , SUM( deleted = 0 ) , SUM( deleted != 0 ) FROM docs GROUP BY user_id` )
	if err != nil { t.Fatal( err ) }
	defer rows.Close()
	for rows.Next() {
		var user_id uint64
		var collection string
		var bytes , docs , tombs int64
		if err = rows.Scan( &user_id , &collection , &bytes , &docs , &tombs ); err != nil { t.Fatal( err ) }
		var got_bytes , got_docs , got_tombs int64
		err = store.db.QueryRow( `SELECT bytes , docs , tombs FROM usage WHERE user_id = ? AND collection = ?` , user_id , collection ).Scan( &got_bytes , &got_docs , &got_tombs )
		if err != nil { t.Fatalf( "%d/%q: %v" , user_id , collection , err ) }
		if got_bytes != bytes || got_docs != docs || got_tombs != tombs {
			t.Fatalf( "%d/%q: totals %d bytes %d docs %d tombs, docs say %d %d %d" , user_id , collection , got_bytes , got_docs , got_tombs , bytes , docs , tombs )
		}
	}
	if err = rows.Err(); err != nil { t.Fatal( err ) }
}

func TestDeleteBigCollectionIsQuickAndBlocksNobody( t *testing.T ) {
	store , _ := open( t )
	fill( t , store , 1 , "big" , 20000 , 100 )
	if _ , err := store.Set( 2 , "other" , "a" , envelope( 1 , 60 ) , nil , limits ); err != nil { t.Fatal( err ) }

	other := make( chan error , 1 )
	started := time.Now()
	go func() {
		_ , err := store.Set( 2 , "other" , "b" , envelope( 1 , 60 ) , nil , limits )
		other <- err
	}()
	deleted , err := store.DeleteCollection( 1 , "big" , DeleteOptions{ MaxDocs: 50000 } )
	took := time.Since( started )
	if err != nil { t.Fatal( err ) }
	if err = <-other; err != nil { t.Fatalf( "another account's write failed: %v" , err ) }
	if took > time.Second { t.Fatalf( "deleting 20k documents took %v" , took ) }
	if deleted.Done == false || deleted.Docs != 20000 || len( deleted.Collections ) != 1 { t.Fatalf( "deleted: %+v" , deleted ) }

	// Every tombstone is in the feed, each with its own number.
	seen := map[ int64 ]bool{}
	for since , more := int64( 0 ) , true ; more ; {
		var page []Doc
		if page , more , err = store.Changes( 1 , since , 5000 ); err != nil { t.Fatal( err ) }
		for _ , change := range page {
			if change.Deleted == false || seen[ change.Seq ] { t.Fatalf( "change %+v" , change ) }
			seen[ change.Seq ] = true
			since = change.Seq
		}
	}
	if len( seen ) != 20000 { t.Fatalf( "feed shows %d deletes" , len( seen ) ) }
	// The counter carries on past them.
	next , err := store.Set( 1 , "fresh" , "a" , envelope( 1 , 60 ) , nil , limits )
	if err != nil { t.Fatal( err ) }
	for seq := range seen {
		if seq >= next.Seq { t.Fatalf( "a tombstone's number %d is not below the next write's %d" , seq , next.Seq ) }
	}
	checkTotals( t , store )
}

func TestDeleteCollectionCapAndPages( t *testing.T ) {
	store , _ := open( t )
	store.CreateCollection( 1 , "top" , CollectionChange{} , limits )
	store.CreateCollection( 1 , "sub" , CollectionChange{ Parent: name( "top" ) } , limits )
	fill( t , store , 1 , "top" , 15 , 60 )
	fill( t , store , 1 , "sub" , 10 , 60 )

	_ , err := store.DeleteCollection( 1 , "top" , DeleteOptions{ MaxDocs: 10 } )
	var large *DeleteTooLarge
	if errors.As( err , &large ) == false || large.Docs != 25 { t.Fatalf( "over the cap: %v" , err ) }
	if usage , _ := store.Usage( 1 ); usage.Docs != 25 { t.Fatalf( "a refused delete took documents: %+v" , usage ) }

	pages := []int{}
	for {
		deleted , err := store.DeleteCollection( 1 , "top" , DeleteOptions{ IfVersion: version( 1 ) , MaxDocs: 10 , Partial: true } )
		if err != nil { t.Fatal( err ) }
		pages = append( pages , deleted.Docs )
		if deleted.Done {
			if same( deleted.Collections , "top" , "sub" ) == false { t.Fatalf( "folders: %v" , deleted.Collections ) }
			break
		}
		if len( deleted.Collections ) != 0 { t.Fatalf( "a partial delete removed folders: %+v" , deleted ) }
		if _ , err = store.GetCollection( 1 , "top" ); err != nil { t.Fatalf( "folder gone early: %v" , err ) }
		if len( pages ) > 5 { t.Fatalf( "no end: %v" , pages ) }
	}
	if fmt.Sprint( pages ) != "[10 10 5]" { t.Fatalf( "pages %v" , pages ) }
	checkTotals( t , store )
}

func TestTombstonesCountTowardTheQuota( t *testing.T ) {
	store , _ := open( t )
	quota := Limits{ MaxDocBytes: 1024 , QuotaBytes: 1024 }
	cycles := 0
	for ; cycles < 100 ; cycles++ {
		id := fmt.Sprintf( "d%d" , cycles )
		if _ , err := store.Set( 1 , "notes" , id , envelope( 1 , 100 ) , nil , quota ); err != nil {
			if errors.Is( err , ErrQuota ) == false { t.Fatal( err ) }
			break
		}
		if _ , err := store.Delete( 1 , "notes" , id , nil , nil ); err != nil { t.Fatal( err ) }
	}
	// Eight tombstones are 1024 bytes: the ninth write does not fit.
	if cycles != 8 { t.Fatalf( "%d write+delete cycles fit in a 1 KiB quota" , cycles ) }
	usage , _ := store.Usage( 1 )
	if usage.Tombstones != 8 || usage.Charged() != 8 * TombstoneBytes { t.Fatalf( "usage: %+v" , usage ) }
	// Writing over a tombstone frees its charge.
	if _ , err := store.Set( 1 , "notes" , "d0" , envelope( 1 , 128 ) , nil , quota ); err != nil { t.Fatalf( "over a tombstone: %v" , err ) }

	// A share's quota counts its tombstones too.
	share := Limits{ MaxDocBytes: 1024 , Share: "shared" , ShareQuotaBytes: 3 * TombstoneBytes }
	store.CreateCollection( 1 , "shared" , CollectionChange{} , limits )
	for index := 0 ; index < 3 ; index++ {
		id := fmt.Sprintf( "s%d" , index )
		if _ , err := store.Set( 1 , "shared" , id , envelope( 1 , 60 ) , nil , share ); err != nil { t.Fatal( err ) }
		store.Delete( 1 , "shared" , id , nil , nil )
	}
	if _ , err := store.Set( 1 , "shared" , "s9" , envelope( 1 , 60 ) , nil , share ); errors.Is( err , ErrShareQuota ) == false {
		t.Fatalf( "share full of tombstones: %v" , err )
	}
	checkTotals( t , store )
}

func TestTotalsStayExact( t *testing.T ) {
	store , _ := open( t )
	random := rand.New( rand.NewSource( 7 ) )
	folders := []string{ "a" , "b" , "c" }
	for _ , folder := range folders { store.CreateCollection( 1 , folder , CollectionChange{} , limits ) }
	store.CreateCollection( 1 , "a2" , CollectionChange{ Parent: name( "a" ) } , limits )
	folders = append( folders , "a2" )
	for step := 0 ; step < 2000 ; step++ {
		user_id := uint64( 1 + random.Intn( 2 ) )
		folder := folders[ random.Intn( len( folders ) ) ]
		id := fmt.Sprintf( "d%d" , random.Intn( 30 ) )
		switch random.Intn( 10 ) {
		case 0, 1, 2, 3:
			store.Set( user_id , folder , id , envelope( 1 , 60 + random.Intn( 400 ) ) , nil , limits )
		case 4, 5:
			store.Delete( user_id , folder , id , nil , nil )
		case 6:
			store.MoveDoc( user_id , folder , id , folders[ random.Intn( len( folders ) ) ] , id , envelope( 2 , 80 ) , nil , limits )
		case 7:
			if step % 50 == 0 {
				store.DeleteCollection( user_id , folder , DeleteOptions{ MaxDocs: 5 , Partial: random.Intn( 2 ) == 0 } )
				store.CreateCollection( user_id , folder , CollectionChange{} , limits )
			}
		case 8:
			if step % 100 == 0 { store.Sweep( time.Now() , 30 , 1000 + random.Intn( 3 ) , func( uint64 ) bool { return true } ) }
		}
	}
	checkTotals( t , store )
	store.Sweep( time.Now().Add( 31 * 24 * time.Hour ) , 30 , 0 , func( user_id uint64 ) bool { return user_id == 1 } )
	checkTotals( t , store )
	var left int
	store.db.QueryRow( `SELECT COUNT(*) FROM usage WHERE user_id = 2` ).Scan( &left )
	if left != 0 { t.Fatalf( "a removed account kept %d totals rows" , left ) }
}

func TestWriteTimeDoesNotGrowWithTheAccount( t *testing.T ) {
	if testing.Short() { t.Skip( "fills an account with 100k documents" ) }
	store , _ := open( t )
	quota := Limits{ MaxDocBytes: 1024 , QuotaBytes: 1 << 30 , MaxCollections: 100 }
	// The best of a few rounds of writes, so a checkpoint in one does not count.
	timeWrites := func( round string ) ( best time.Duration ) {
		for attempt := 0 ; attempt < 3 ; attempt++ {
			started := time.Now()
			for index := 0 ; index < 200 ; index++ {
				if _ , err := store.Set( 1 , "hot" , fmt.Sprintf( "%s%d" , round , index % 20 ) , envelope( 1 , 100 ) , nil , quota ); err != nil { t.Fatal( err ) }
			}
			if took := time.Since( started ); attempt == 0 || took < best { best = took }
		}
		return
	}
	fill( t , store , 1 , "bulk" , 1000 , 100 )
	small := timeWrites( "s" )
	fill( t , store , 1 , "bulk2" , 99000 , 100 )
	big := timeWrites( "b" )
	t.Logf( "200 writes: %v at 1k documents, %v at 100k" , small , big )
	if big > 2 * small + 20 * time.Millisecond { t.Fatalf( "writes slowed from %v at 1k documents to %v at 100k" , small , big ) }
}

func TestSweepCapsTombstones( t *testing.T ) {
	store , _ := open( t )
	for index := 0 ; index < 12 ; index++ {
		id := fmt.Sprintf( "d%02d" , index )
		store.Set( 1 , "notes" , id , envelope( 1 , 60 ) , nil , limits )
		store.Delete( 1 , "notes" , id , nil , nil )
	}
	store.Set( 1 , "notes" , "live" , envelope( 1 , 60 ) , nil , limits )
	all , _ , _ := store.Changes( 1 , 0 , 100 )
	swept , err := store.Sweep( time.Now() , 30 , 5 , func( uint64 ) bool { return true } )
	if err != nil || swept.Tombstones != 7 { t.Fatalf( "swept %+v %v" , swept , err ) }
	usage , _ := store.Usage( 1 )
	if usage.Tombstones != 5 || usage.Docs != 1 { t.Fatalf( "usage after: %+v" , usage ) }
	// A client that synced before the purged ones has to start again; one
	// that saw them carries on.
	if _ , _ , err = store.Changes( 1 , all[ 0 ].Seq , 100 ); errors.Is( err , ErrSyncExpired ) == false { t.Fatalf( "old sync: %v" , err ) }
	if _ , _ , err = store.Changes( 1 , all[ 6 ].Seq , 100 ); err != nil { t.Fatalf( "sync past the purge: %v" , err ) }
	checkTotals( t , store )
}

// Each deleted folder leaves a grave (for undo). The quota charges graves
// like tombstones, the sweep keeps at most max_tombstones of them, and
// making an id again removes its grave (PLAN H6).
func TestGravesAreChargedAndCapped( t *testing.T ) {
	store , _ := open( t )
	for _ , id := range []string{ "a" , "b" , "c" , "d" , "e" } {
		if _ , err := store.CreateCollection( 1 , id , CollectionChange{} , limits ); err != nil { t.Fatal( err ) }
		if _ , err := store.DeleteCollection( 1 , id , DeleteOptions{} ); err != nil { t.Fatal( err ) }
		time.Sleep( 2 * time.Millisecond )
	}
	usage , _ := store.Usage( 1 )
	if usage.Graves != 5 || usage.Charged() != 5 * TombstoneBytes { t.Fatalf( "after 5 deletes: %+v charged %d" , usage , usage.Charged() ) }
	if _ , err := store.CreateCollection( 1 , "e" , CollectionChange{} , limits ); err != nil { t.Fatal( err ) }
	if usage , _ = store.Usage( 1 ); usage.Graves != 4 { t.Fatalf( "made again, its grave stays: %+v" , usage ) }
	if _ , err := store.Sweep( time.Now() , 30 , 2 , func( uint64 ) bool { return true } ); err != nil { t.Fatal( err ) }
	if usage , _ = store.Usage( 1 ); usage.Graves != 2 { t.Fatalf( "past the cap: %+v" , usage ) }
	var kept []string
	rows , _ := store.read.Query( `SELECT id FROM graves WHERE user_id = 1 ORDER BY id` )
	for rows.Next() { var id string; rows.Scan( &id ); kept = append( kept , id ) }
	rows.Close()
	if len( kept ) != 2 || kept[ 0 ] != "c" || kept[ 1 ] != "d" { t.Fatalf( "kept %v, want the newest: c d" , kept ) }
}
