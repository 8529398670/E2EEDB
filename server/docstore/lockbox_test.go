package docstore

import (
	bytes "bytes"
	base64 "encoding/base64"
	json "encoding/json"
	errors "errors"
	strings "strings"
	testing "testing"
	time "time"
)

// shapedLock is lockbox text the server takes: every field the right size,
// for parent, naming key id fill (16 bytes of it). Nothing here opens it.
func shapedLock( parent string , fill byte ) string {
	field := func( size int ) string { return base64.StdEncoding.EncodeToString( bytes.Repeat( []byte{ fill } , size ) ) }
	text , _ := json.Marshal( map[ string ]any{
		"parent": parent , "by": field( 16 ) , "key_id": field( 16 ) , "epoch": 1 ,
		"nonce_r": field( 24 ) , "read": field( 80 ) , "nonce_w": field( 24 ) , "write": field( 48 ) , "sig": field( 64 ) ,
	} )
	return string( text )
}

// sealedWith is a collection envelope naming key id fill.
func sealedWith( fill byte ) ( body []byte ) {
	body = bytes.Repeat( []byte{ fill } , EnvelopeCollectionMin )
	body[ 0 ] = EnvelopeCollection
	return
}

func TestCheckLock( t *testing.T ) {
	good := shapedLock( "p" , 1 )
	if err := checkLock( good , "p" ); err != nil { t.Fatalf( "good lockbox: %v" , err ) }
	var box map[ string ]any
	json.Unmarshal( []byte( good ) , &box )
	with := func( key string , value any ) string {
		copy := map[ string ]any{}
		for k , v := range box { copy[ k ] = v }
		if value == nil { delete( copy , key ) } else { copy[ key ] = value }
		text , _ := json.Marshal( copy )
		return string( text )
	}
	short := base64.StdEncoding.EncodeToString( make( []byte , 15 ) )
	for label , lock := range map[ string ]string{
		"not json":      "not json",
		"trailing":      good + "{}",
		"other parent":  shapedLock( "q" , 1 ),
		"no parent":     with( "parent" , nil ),
		"no key_id":     with( "key_id" , nil ),
		"short key_id":  with( "key_id" , short ),
		"no sig":        with( "sig" , nil ),
		"epoch 0":       with( "epoch" , 0 ),
		"epoch too big": with( "epoch" , float64( 1 << 54 ) ),
		"extra field":   with( "extra" , "x" ),
		"bad own":       with( "own" , short ),
		"not base64":    with( "read" , "!!" ),
		// A sharee's folder at the last epoch could never be rotated.
		"epoch far ahead": with( "epoch" , float64( time.Now().Unix() + 1 << 33 ) ),
		// Go reads a name in any case, a browser only as written (H4).
		"repeated name":  strings.Replace( good , `"key_id":` , `"key_id":"` + short + `","key_id":` , 1 ),
		"other case":     strings.Replace( good , `"key_id":` , `"KEY_ID":` , 1 ),
		"both cases":     strings.Replace( good , `"key_id":` , `"key_id":"` + short + `","Key_Id":` , 1 ),
	} {
		if err := checkLock( lock , "p" ); errors.Is( err , ErrBadLock ) == false { t.Errorf( "%s: %v" , label , err ) }
	}
	if err := checkLock( with( "epoch" , float64( time.Now().Unix() + 1000 ) ) , "p" ); err != nil { t.Errorf( "epoch a little ahead: %v" , err ) }
	if err := checkLock( with( "own" , base64.StdEncoding.EncodeToString( make( []byte , 32 ) ) ) , "p" ); err != nil { t.Errorf( "with own: %v" , err ) }
}

// A malformed lockbox is refused wherever one goes in: on create, on giving
// a folder keys, on a move, and on staging a rotation.
func TestBadLockIsRefusedEverywhere( t *testing.T ) {
	store , _ := open( t )
	bad := `{"key_id":"x"}`
	if _ , err := store.CreateCollection( 1 , "a" , CollectionChange{ Lock: &bad } , limits ); errors.Is( err , ErrBadLock ) == false { t.Fatalf( "create: %v" , err ) }
	// Wrapped for another parent than the one it goes under.
	elsewhere := shapedLock( "z" , 1 )
	if _ , err := store.CreateCollection( 1 , "a" , CollectionChange{ Lock: &elsewhere } , limits ); errors.Is( err , ErrBadLock ) == false { t.Fatalf( "create for another parent: %v" , err ) }
	if _ , err := store.CreateCollection( 1 , "a" , CollectionChange{} , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.UpdateCollection( 1 , "a" , CollectionChange{ Lock: &bad } , limits ); errors.Is( err , ErrBadLock ) == false { t.Fatalf( "give keys: %v" , err ) }
	top := shapedLock( "" , 1 )
	if _ , err := store.UpdateCollection( 1 , "a" , CollectionChange{ Lock: &top } , limits ); err != nil { t.Fatal( err ) }
	parent := "b"
	if _ , err := store.CreateCollection( 1 , "b" , CollectionChange{ Lock: name( shapedLock( "" , 2 ) ) } , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.UpdateCollection( 1 , "a" , CollectionChange{ Parent: &parent , Lock: &bad } , limits ); errors.Is( err , ErrBadLock ) == false { t.Fatalf( "move: %v" , err ) }
	if _ , err := store.UpdateCollection( 1 , "a" , CollectionChange{ Parent: &parent , Lock: &top } , limits ); errors.Is( err , ErrBadLock ) == false { t.Fatalf( "move with the old parent's: %v" , err ) }
	if _ , err := store.StageRotation( 1 , "a" , map[ string ]string{ "a": bad } ) ; errors.Is( err , ErrBadLock ) == false { t.Fatalf( "stage: %v" , err ) }
	if _ , err := store.StageRotation( 1 , "a" , map[ string ]string{ "a": "not json" } ) ; errors.Is( err , ErrBadLock ) == false { t.Fatalf( "stage not json: %v" , err ) }
	if entry , _ := store.GetCollection( 1 , "a" ); entry.NextLock != "" { t.Fatal( "a refused stage left a next lockbox" ) }
}

// A staged lockbox can be sent again, which replaces it, and a rotation can
// be called off until something is sealed with its new keys.
func TestRestageAndAbort( t *testing.T ) {
	store , _ := open( t )
	if _ , err := store.CreateCollection( 1 , "r" , CollectionChange{ Lock: name( shapedLock( "" , 1 ) ) } , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.Set( 1 , "r" , "d" , sealedWith( 1 ) , nil , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.StageRotation( 1 , "r" , map[ string ]string{ "r": shapedLock( "" , 2 ) } ); err != nil { t.Fatal( err ) }
	if _ , err := store.StageRotation( 1 , "r" , map[ string ]string{ "r": shapedLock( "" , 3 ) } ); err != nil { t.Fatalf( "restage: %v" , err ) }
	if entry , _ := store.GetCollection( 1 , "r" ); entry.NextLock != shapedLock( "" , 3 ) { t.Fatal( "restage kept the first next lockbox" ) }
	if _ , err := store.AbortRotation( 1 , "r" ); err != nil { t.Fatalf( "abort: %v" , err ) }
	entry , _ := store.GetCollection( 1 , "r" )
	if entry.NextLock != "" || entry.Lock != shapedLock( "" , 1 ) { t.Fatalf( "after abort: %+v" , entry ) }
	if _ , err := store.AbortRotation( 1 , "r" ); errors.Is( err , ErrNotRotating ) == false { t.Fatalf( "abort twice: %v" , err ) }
	// Old keys work again.
	if _ , err := store.Set( 1 , "r" , "d" , sealedWith( 1 ) , nil , limits ); err != nil { t.Fatalf( "write under the old keys after abort: %v" , err ) }

	// Once a document names the new keys, abort is refused.
	if _ , err := store.StageRotation( 1 , "r" , map[ string ]string{ "r": shapedLock( "" , 4 ) } ); err != nil { t.Fatal( err ) }
	if _ , err := store.Set( 1 , "r" , "d" , sealedWith( 4 ) , nil , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.AbortRotation( 1 , "r" ); errors.Is( err , ErrRotateResealed ) == false { t.Fatalf( "abort after a reseal: %v" , err ) }
	if _ , err := store.CommitRotation( 1 , "r" ); err != nil { t.Fatalf( "commit: %v" , err ) }
}

// A move re-wraps the same keys for the new parent: a lockbox naming other
// keys is refused, so a write key cannot swap a folder's keys out from
// under the folders inside it.
func TestMoveKeepsTheKeys( t *testing.T ) {
	store , _ := open( t )
	for _ , id := range []string{ "p1" , "p2" } {
		if _ , err := store.CreateCollection( 1 , id , CollectionChange{ Lock: name( shapedLock( "" , 9 ) ) } , limits ); err != nil { t.Fatal( err ) }
	}
	p1 , p2 := "p1" , "p2"
	if _ , err := store.CreateCollection( 1 , "a" , CollectionChange{ Parent: &p1 , Lock: name( shapedLock( "p1" , 1 ) ) } , limits ); err != nil { t.Fatal( err ) }
	if _ , err := store.UpdateCollection( 1 , "a" , CollectionChange{ Parent: &p2 , Lock: name( shapedLock( "p2" , 2 ) ) } , limits ); errors.Is( err , ErrLockMismatch ) == false {
		t.Fatalf( "move with other keys: %v" , err )
	}
	if _ , err := store.UpdateCollection( 1 , "a" , CollectionChange{ Parent: &p2 , Lock: name( shapedLock( "p2" , 1 ) ) } , limits ); err != nil {
		t.Fatalf( "move with the same keys: %v" , err )
	}
}
