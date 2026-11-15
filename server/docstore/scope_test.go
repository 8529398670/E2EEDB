package docstore

import (
	errors "errors"
	testing "testing"
)

// A scoped key's folder is checked again inside each write's transaction
// (PLAN H3): the route checks first, and the owner may move a folder out of
// the shared one, or a rotation give it a new born, before the write runs.
// Here the write runs with the key's view of its scope after that happened.
func TestScopeIsCheckedInsideTheWrite( t *testing.T ) {
	store , _ := open( t )
	shared , inner , other := "S" , "X" , "P"
	for _ , folder := range []struct{ id string ; parent *string }{ { shared , nil } , { inner , &shared } , { other , nil } } {
		parent := ""
		if folder.parent != nil { parent = *folder.parent }
		if _ , err := store.CreateCollection( 1 , folder.id , CollectionChange{ Parent: folder.parent , Lock: name( shapedLock( parent , 1 ) ) } , limits ); err != nil { t.Fatal( err ) }
	}
	if _ , err := store.Set( 1 , inner , "d" , sealedWith( 1 ) , nil , limits ); err != nil { t.Fatal( err ) }
	root , _ := store.GetCollection( 1 , shared )
	scoped := limits
	scoped.Share , scoped.NoAutoCreate = shared , true
	scoped.Scope = &ScopeRoot{ Root: shared , Born: root.Born }
	if _ , err := store.Set( 1 , inner , "e" , sealedWith( 1 ) , nil , scoped ); err != nil { t.Fatalf( "write in scope: %v" , err ) }

	// The owner moves X out of S.
	if _ , err := store.UpdateCollection( 1 , inner , CollectionChange{ Parent: &other , Lock: name( shapedLock( other , 1 ) ) } , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.Set( 1 , inner , "f" , sealedWith( 1 ) , nil , scoped ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "write after the move: %v" , err ) }
	if _ , err := store.Delete( 1 , inner , "d" , nil , scoped.Scope ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "delete after the move: %v" , err ) }
	if _ , _ , err := store.MoveDoc( 1 , inner , "d" , shared , "d" , sealedWith( 1 ) , nil , scoped ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "move a document out of the moved folder: %v" , err ) }
	if _ , err := store.UpdateCollection( 1 , inner , CollectionChange{ Name: name( "mine" ) } , scoped ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "rename after the move: %v" , err ) }
	if _ , err := store.DeleteCollection( 1 , inner , DeleteOptions{ Scope: scoped.Scope } ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "folder delete after the move: %v" , err ) }
	if _ , err := store.CreateCollection( 1 , "Y" , CollectionChange{ Parent: &inner } , scoped ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "create under the moved folder: %v" , err ) }
	if _ , err := store.UpdateCollection( 1 , "Y" , CollectionChange{ Parent: &other } , scoped ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "move to outside: %v" , err ) }

	// A rotation of S starts: S gets a new born, and the key is cut off.
	if _ , err := store.Set( 1 , shared , "g" , sealedWith( 1 ) , nil , scoped ); err != nil { t.Fatalf( "write in S before the rotation: %v" , err ) }
	if _ , err := store.StageRotation( 1 , shared , map[ string ]string{ shared: shapedLock( "" , 2 ) } ); err != nil { t.Fatal( err ) }
	if _ , err := store.Delete( 1 , shared , "g" , nil , scoped.Scope ); errors.Is( err , ErrNoCollection ) == false { t.Fatalf( "delete after the rotation started: %v" , err ) }
	if _ , err := store.Delete( 1 , shared , "g" , nil , nil ); err != nil { t.Fatalf( "the owner's delete: %v" , err ) }
}

// A share's cap keeps counting what its deleted folders hold until it is
// purged (PLAN H7): writing up to the cap and deleting the folder, over and
// over, used to charge the account many times the cap.
func TestShareCapCountsDeletedFolders( t *testing.T ) {
	store , _ := open( t )
	shared := "S"
	if _ , err := store.CreateCollection( 1 , shared , CollectionChange{ Lock: name( shapedLock( "" , 1 ) ) } , limits ); err != nil { t.Fatal( err ) }
	root , _ := store.GetCollection( 1 , shared )
	scoped := limits
	scoped.Share , scoped.NoAutoCreate , scoped.ShareQuotaBytes = shared , true , 2000
	scoped.Scope = &ScopeRoot{ Root: shared , Born: root.Born }
	for round := 0 ; round < 10 ; round++ {
		id := "r" + string( rune( 'a' + round ) )
		if _ , err := store.CreateCollection( 1 , id , CollectionChange{ Parent: &shared } , scoped ); err != nil {
			// Full: no more folders either, since each leaves a grave.
			if errors.Is( err , ErrShareQuota ) == false || round == 0 { t.Fatalf( "round %d: %v" , round , err ) }
			break
		}
		for n := 0 ; n < 100 ; n++ {
			if _ , err := store.Set( 1 , id , "d" + string( rune( 'a' + n ) ) , sealedWith( 1 ) , nil , scoped ); err != nil {
				if errors.Is( err , ErrShareQuota ) == false { t.Fatal( err ) }
				break
			}
		}
		if _ , err := store.DeleteCollection( 1 , id , DeleteOptions{ Scope: scoped.Scope } ); err != nil { t.Fatal( err ) }
	}
	usage , _ := store.Usage( 1 )
	if usage.Charged() > scoped.ShareQuotaBytes + 2 * TombstoneBytes { t.Fatalf( "share cap 2000, account charged %d (%+v)" , usage.Charged() , usage ) }
}
