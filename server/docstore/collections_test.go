package docstore

import (
	errors "errors"
	testing "testing"
)

func name( text string ) *string { return &text }

// tree is the account's folders as id -> entry.
func tree( t *testing.T , store *Store , user_id uint64 ) ( result map[ string ]Collection ) {
	t.Helper()
	entries , _ , err := store.Collections( user_id , 0 , 1000 )
	if err != nil { t.Fatal( err ) }
	result = map[ string ]Collection{}
	for _ , entry := range entries { result[ entry.ID ] = entry }
	return
}

// children is parent's children's ids, in order.
func children( t *testing.T , store *Store , user_id uint64 , parent string ) ( ids []string ) {
	t.Helper()
	entries , _ , err := store.Collections( user_id , 0 , 1000 )
	if err != nil { t.Fatal( err ) }
	ids = []string{}
	for _ , entry := range entries {
		if entry.Parent == parent { ids = append( ids , entry.ID ) }
	}
	return
}

func same( a []string , b ...string ) bool {
	if len( a ) != len( b ) { return false }
	for index := range a {
		if a[ index ] != b[ index ] { return false }
	}
	return true
}

// A lockbox is set once: replacing it in place is refused, so nobody (a
// read-only key included) can swap a folder's keys under its readers.
func TestLockIsSetOnce( t *testing.T ) {
	store , _ := open( t )
	if _ , err := store.CreateCollection( 1 , "notes" , CollectionChange{ Lock: name( shapedLock( "" , 1 ) ) } , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.UpdateCollection( 1 , "notes" , CollectionChange{ Lock: name( shapedLock( "" , 1 ) ) } , limits ); err != nil { t.Fatalf( "same lockbox again: %v" , err ) }
	if _ , err := store.UpdateCollection( 1 , "notes" , CollectionChange{ Lock: name( shapedLock( "" , 2 ) ) } , limits ); errors.Is( err , ErrLockExists ) == false { t.Fatalf( "replaced in place: %v" , err ) }
}

func TestSetMakesAFolder( t *testing.T ) {
	store , _ := open( t )
	doc , err := store.Set( 1 , "notes" , "a" , envelope( 1 , 60 ) , nil , limits )
	if err != nil { t.Fatal( err ) }
	notes := tree( t , store , 1 )[ "notes" ]
	if notes.Name != "notes" || notes.Parent != "" || notes.Count != 1 { t.Fatalf( "auto folder: %+v" , notes ) }
	if seq , _ := store.TreeSeq( 1 ); seq != doc.Seq { t.Fatalf( "tree seq %d, want the write's %d" , seq , doc.Seq ) }
	// A top-level folder already named like the id: the new one gets "(2)".
	store.CreateCollection( 1 , "f1" , CollectionChange{ Name: name( "Tasks" ) } , limits )
	store.Set( 1 , "tasks" , "a" , envelope( 1 , 60 ) , nil , limits )
	if got := tree( t , store , 1 )[ "tasks" ].Name; got != "tasks (2)" { t.Fatalf( "clashing auto name: %q" , got ) }
	// A failed write makes no folder.
	store.Set( 1 , "big" , "a" , envelope( 1 , 5000 ) , nil , limits )
	if _ , found := tree( t , store , 1 )[ "big" ]; found { t.Fatal( "a refused write left a folder" ) }
}

func TestCreateRenameAndNames( t *testing.T ) {
	store , _ := open( t )
	if _ , err := store.CreateCollection( 1 , "work" , CollectionChange{ Name: name( "Work" ) } , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.CreateCollection( 1 , "work" , CollectionChange{ Name: name( "Other" ) } , limits ); errors.Is( err , ErrConflict ) == false {
		t.Fatalf( "an id in use should conflict, got %v" , err )
	}
	if _ , err := store.CreateCollection( 1 , "w2" , CollectionChange{ Name: name( "WORK" ) } , limits ); errors.Is( err , ErrNameTaken ) == false {
		t.Fatalf( "a sibling's name in another case should be taken, got %v" , err )
	}
	if _ , err := store.CreateCollection( 1 , "w3" , CollectionChange{ Name: name( "Work" ) , Parent: name( "work" ) } , limits ); err != nil {
		t.Fatalf( "the same name under another parent is fine: %v" , err )
	}
	if _ , err := store.CreateCollection( 1 , "w4" , CollectionChange{ Parent: name( "nope" ) } , limits ); errors.Is( err , ErrNoCollection ) == false {
		t.Fatalf( "a missing parent: %v" , err )
	}
	renamed , err := store.UpdateCollection( 1 , "work" , CollectionChange{ Name: name( "Job" ) , IfVersion: version( 1 ) } , limits )
	if err != nil || renamed.Name != "Job" || renamed.Version != 2 { t.Fatalf( "rename: %+v %v" , renamed , err ) }
	if _ , err = store.UpdateCollection( 1 , "work" , CollectionChange{ Name: name( "X" ) , IfVersion: version( 1 ) } , limits ); errors.Is( err , ErrConflict ) == false {
		t.Fatalf( "a stale rename should conflict, got %v" , err )
	}
	// Nothing that does not show (PLAN H9): zero-width characters and the
	// marks that turn text right to left, a joiner anywhere but in an emoji.
	for _ , bad := range []string{ "" , " lead" , "trail " , "tab\there" , "X\u200b" , "invoices\u202efdp.exe" , "a\u2066b" ,
		"\ufeffX" , "X\u200d" , "a\u200db" , "\u200d\U0001F600" , "a\u2060b" , "tag\U000E0041" } {
		if ValidCollectionName( bad ) { t.Errorf( "%q should not be a valid name" , bad ) }
	}
	for _ , good := range []string{ "Invoices 2026" , "Ünïcødé / slashes too" , "Family \U0001F468\u200d\U0001F469\u200d\U0001F467" ,
		"Pride \U0001F3F3\ufe0f\u200d\U0001F308" , "عربي" } {
		if ValidCollectionName( good ) == false { t.Errorf( "%q should be a valid name" , good ) }
	}
}

func TestMoveReorderCycleDepth( t *testing.T ) {
	store , _ := open( t )
	for _ , id := range []string{ "a" , "b" , "c" } {
		if _ , err := store.CreateCollection( 1 , id , CollectionChange{} , limits ); err != nil { t.Fatal( err ) }
	}
	store.CreateCollection( 1 , "first" , CollectionChange{ Before: name( "a" ) } , limits )
	if ids := children( t , store , 1 , "" ); same( ids , "first" , "a" , "b" , "c" ) == false { t.Fatalf( "create before: %v" , ids ) }
	// Reorder: c in front of a.
	store.UpdateCollection( 1 , "c" , CollectionChange{ Before: name( "a" ) } , limits )
	if ids := children( t , store , 1 , "" ); same( ids , "first" , "c" , "a" , "b" ) == false { t.Fatalf( "reorder: %v" , ids ) }
	// Nest b in a, then a in c; the top level closes up.
	store.UpdateCollection( 1 , "b" , CollectionChange{ Parent: name( "a" ) } , limits )
	store.UpdateCollection( 1 , "a" , CollectionChange{ Parent: name( "c" ) } , limits )
	if ids := children( t , store , 1 , "" ); same( ids , "first" , "c" ) == false { t.Fatalf( "top after nesting: %v" , ids ) }
	if got := tree( t , store , 1 )[ "c" ].Position; got != 1 { t.Fatalf( "c's position %d, want 1" , got ) }
	// c -> a -> b: putting c under b, or under itself, is a cycle.
	if _ , err := store.UpdateCollection( 1 , "c" , CollectionChange{ Parent: name( "b" ) } , limits ); errors.Is( err , ErrCycle ) == false { t.Fatalf( "cycle: %v" , err ) }
	if _ , err := store.UpdateCollection( 1 , "c" , CollectionChange{ Parent: name( "c" ) } , limits ); errors.Is( err , ErrCycle ) == false { t.Fatalf( "self: %v" , err ) }
	// Depth: c (1) -> a (2) -> b (3). With a limit of 3, c cannot go under first.
	shallow := limits
	shallow.MaxDepth = 3
	if _ , err := store.UpdateCollection( 1 , "c" , CollectionChange{ Parent: name( "first" ) } , shallow ); errors.Is( err , ErrTooDeep ) == false { t.Fatalf( "too deep: %v" , err ) }
	if _ , err := store.CreateCollection( 1 , "d" , CollectionChange{ Parent: name( "b" ) } , shallow ); errors.Is( err , ErrTooDeep ) == false { t.Fatalf( "create too deep: %v" , err ) }
	// Back to the top level, at the end.
	if _ , err := store.UpdateCollection( 1 , "b" , CollectionChange{ Parent: name( "" ) } , limits ); err != nil { t.Fatal( err ) }
	if ids := children( t , store , 1 , "" ); same( ids , "first" , "c" , "b" ) == false { t.Fatalf( "back to top: %v" , ids ) }
	// Moving next to a sibling with the same name is refused.
	store.CreateCollection( 1 , "b2" , CollectionChange{ Name: name( "b" ) , Parent: name( "c" ) } , limits )
	if _ , err := store.UpdateCollection( 1 , "b2" , CollectionChange{ Parent: name( "" ) } , limits ); errors.Is( err , ErrNameTaken ) == false { t.Fatalf( "name clash on move: %v" , err ) }
}

func TestDeleteSubtree( t *testing.T ) {
	store , _ := open( t )
	store.CreateCollection( 1 , "top" , CollectionChange{} , limits )
	store.CreateCollection( 1 , "mid" , CollectionChange{ Parent: name( "top" ) } , limits )
	store.CreateCollection( 1 , "leaf" , CollectionChange{ Parent: name( "mid" ) } , limits )
	store.CreateCollection( 1 , "keep" , CollectionChange{} , limits )
	store.Set( 1 , "top" , "a" , envelope( 1 , 60 ) , nil , limits )
	store.Set( 1 , "leaf" , "b" , envelope( 1 , 60 ) , nil , limits )
	store.Set( 1 , "leaf" , "c" , envelope( 1 , 60 ) , nil , limits )
	store.Set( 1 , "keep" , "d" , envelope( 1 , 60 ) , nil , limits )
	before , _ := store.TreeSeq( 1 )

	deleted , err := store.DeleteCollection( 1 , "top" , DeleteOptions{ IfVersion: version( 1 ) } )
	if err != nil { t.Fatal( err ) }
	if same( deleted.Collections , "top" , "mid" , "leaf" ) == false || deleted.Docs != 3 || deleted.Done == false { t.Fatalf( "deleted: %+v" , deleted ) }
	if ids := children( t , store , 1 , "" ); same( ids , "keep" ) == false { t.Fatalf( "left: %v" , ids ) }
	if got := tree( t , store , 1 )[ "keep" ].Position; got != 0 { t.Fatalf( "keep's position %d" , got ) }
	if after , _ := store.TreeSeq( 1 ); after <= before { t.Fatalf( "tree seq did not move: %d -> %d" , before , after ) }
	// Every document became a tombstone the feed reports, each with its own number.
	changes , _ , _ := store.Changes( 1 , 0 , 100 )
	gone := 0
	for _ , change := range changes {
		if change.Deleted { gone++ }
	}
	if gone != 3 { t.Fatalf( "feed shows %d deletes: %+v" , gone , changes ) }
	if _ , err = store.Get( 1 , "keep" , "d" ); err != nil { t.Fatalf( "a document outside was touched: %v" , err ) }
	// Undo: the folders again with the same ids, then the same bytes.
	store.CreateCollection( 1 , "top" , CollectionChange{} , limits )
	store.CreateCollection( 1 , "mid" , CollectionChange{ Parent: name( "top" ) } , limits )
	store.CreateCollection( 1 , "leaf" , CollectionChange{ Parent: name( "mid" ) } , limits )
	if _ , err = store.Set( 1 , "leaf" , "b" , envelope( 1 , 60 ) , version( 0 ) , limits ); err != nil { t.Fatalf( "restore: %v" , err ) }
	if _ , err = store.DeleteCollection( 1 , "nope" , DeleteOptions{} ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "missing: %v" , err ) }
}

func TestMoveDoc( t *testing.T ) {
	store , _ := open( t )
	store.Set( 1 , "inbox" , "a" , envelope( 1 , 60 ) , nil , limits )
	store.Set( 1 , "inbox" , "b" , envelope( 1 , 60 ) , nil , limits )
	store.CreateCollection( 1 , "archive" , CollectionChange{} , limits )
	store.Set( 1 , "archive" , "b" , envelope( 1 , 60 ) , nil , limits )

	moved , gone , err := store.MoveDoc( 1 , "inbox" , "a" , "archive" , "a" , envelope( 7 , 70 ) , version( 1 ) , limits )
	if err != nil || moved.Collection != "archive" || moved.Version != moved.Seq || gone.Deleted == false { t.Fatalf( "move: %+v %+v %v" , moved , gone , err ) }
	got , err := store.Get( 1 , "archive" , "a" )
	if err != nil || got.Body[ 1 ] != 7 { t.Fatalf( "moved doc: %+v %v" , got , err ) }
	if _ , err = store.Get( 1 , "inbox" , "a" ); errors.Is( err , ErrNotFound ) == false { t.Fatalf( "source still there: %v" , err ) }

	// The destination is taken: nothing changes.
	_ , _ , err = store.MoveDoc( 1 , "inbox" , "b" , "archive" , "b" , envelope( 7 , 70 ) , nil , limits )
	if errors.Is( err , ErrConflict ) == false { t.Fatalf( "taken destination: %v" , err ) }
	if _ , err = store.Get( 1 , "inbox" , "b" ); err != nil { t.Fatalf( "a refused move removed the source: %v" , err ) }
	if _ , _ , err = store.MoveDoc( 1 , "inbox" , "b" , "nope" , "b" , envelope( 7 , 70 ) , nil , limits ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "missing folder: %v" , err ) }
	if _ , _ , err = store.MoveDoc( 1 , "inbox" , "b" , "inbox" , "b" , envelope( 7 , 70 ) , nil , limits ); errors.Is( err , ErrSamePlace ) == false { t.Fatalf( "same place: %v" , err ) }
	if _ , _ , err = store.MoveDoc( 1 , "inbox" , "b" , "archive" , "c" , envelope( 7 , 70 ) , version( 9 ) , limits ); errors.Is( err , ErrConflict ) == false { t.Fatalf( "stale source: %v" , err ) }
}

func TestFoldersAreApartAndCapped( t *testing.T ) {
	store , _ := open( t )
	store.CreateCollection( 1 , "mine" , CollectionChange{} , limits )
	if len( tree( t , store , 2 ) ) != 0 { t.Fatal( "user 2 sees user 1's folders" ) }
	if _ , err := store.UpdateCollection( 2 , "mine" , CollectionChange{ Name: name( "x" ) } , limits ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "rename another's: %v" , err ) }
	if _ , err := store.DeleteCollection( 2 , "mine" , DeleteOptions{} ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "delete another's: %v" , err ) }
	few := limits
	few.MaxCollections = 2
	store.CreateCollection( 1 , "two" , CollectionChange{} , few )
	if _ , err := store.CreateCollection( 1 , "three" , CollectionChange{} , few ); errors.Is( err , ErrTooMany ) == false { t.Fatalf( "cap: %v" , err ) }
	if _ , err := store.Set( 1 , "three" , "a" , envelope( 1 , 60 ) , nil , few ); errors.Is( err , ErrTooMany ) == false { t.Fatalf( "cap on auto folder: %v" , err ) }
}

// A scoped key's write (NoAutoCreate) into a folder that is gone -- deleted
// between its scope check and its write -- must not make it again at the top
// level, where the key could never have made it.
func TestNoAutoCreate( t *testing.T ) {
	store , _ := open( t )
	scoped := limits
	scoped.NoAutoCreate = true
	if _ , err := store.Set( 1 , "reports" , "x" , envelope( 1 , 60 ) , nil , scoped ); errors.Is( err , ErrNoCollection ) == false {
		t.Fatalf( "scoped write into a missing folder: %v" , err )
	}
	if _ , err := store.GetCollection( 1 , "reports" ); err == nil {
		t.Fatal( "the folder was made anyway" )
	}
	if _ , err := store.Set( 1 , "reports" , "x" , envelope( 1 , 60 ) , nil , limits ); err != nil {
		t.Fatalf( "an unscoped write still makes it: %v" , err )
	}
	if _ , err := store.Set( 1 , "reports" , "y" , envelope( 1 , 60 ) , nil , scoped ); err != nil {
		t.Fatalf( "a scoped write into an existing folder: %v" , err )
	}
}
