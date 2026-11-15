package client

// The client against a dishonest server: one that answers with documents
// from somewhere other than where they were asked for.

import (
	context "context"
	json "encoding/json"
	errors "errors"
	http "net/http"
	httptest "net/http/httptest"
	strings "strings"
	testing "testing"
)

func fakeServer( t *testing.T , handler http.HandlerFunc ) ( server *httptest.Server ) {
	server = httptest.NewServer( handler )
	t.Cleanup( server.Close )
	return
}

func testKey( t *testing.T ) ( encoded string , key *Key ) {
	encoded , err := GenerateKey()
	if err != nil { t.Fatal( err ) }
	if key , err = ParseKey( encoded ); err != nil { t.Fatal( err ) }
	return
}

// Get answered with another document (other/Y for invoices/X) is ErrCorrupt,
// even though the master key opens it where it really lives.
func TestGetRefusesSubstitutedDoc( t *testing.T ) {
	encoded , key := testKey( t )
	envelope , err := key.Seal( "other" , "Y" , []byte( `{"secret":1}` ) )
	if err != nil { t.Fatal( err ) }
	server := fakeServer( t , func( w http.ResponseWriter , r *http.Request ) {
		json.NewEncoder( w ).Encode( map[string]any{ "collection": "other" , "id": "Y" , "version": 1 , "body": b64.EncodeToString( envelope ) } )
	} )
	store , _ := New( server.URL , "k" , encoded )
	var out map[string]any
	if _ , err = store.Get( context.Background() , "invoices" , "X" , &out ); errors.Is( err , ErrCorrupt ) == false {
		t.Fatalf( "Get = %v %v, want ErrCorrupt" , out , err )
	}
}

// Each over invoices refuses a row the server slipped in from another
// collection.
func TestEachRefusesForeignRow( t *testing.T ) {
	encoded , key := testKey( t )
	envelope , _ := key.Seal( "other" , "Y" , []byte( `{"secret":1}` ) )
	server := fakeServer( t , func( w http.ResponseWriter , r *http.Request ) {
		json.NewEncoder( w ).Encode( map[string]any{ "docs": []any{
			map[string]any{ "collection": "other" , "id": "Y" , "version": 1 , "body": b64.EncodeToString( envelope ) } ,
		} } )
	} )
	store , _ := New( server.URL , "k" , encoded )
	err := store.Each( context.Background() , "invoices" , func( meta Meta , data json.RawMessage ) error {
		t.Fatalf( "Each handed over %s/%s: %s" , meta.Collection , meta.ID , data )
		return nil
	} )
	if errors.Is( err , ErrCorrupt ) == false {
		t.Fatalf( "Each = %v, want ErrCorrupt" , err )
	}
}

// Sharing "shared" must never seal a private document from another
// collection again under shared's keys, which the sharee holds.
func TestPrepareShareRefusesForeignRow( t *testing.T ) {
	encoded , key := testKey( t )
	folder , _ := generateCollectionKey( "shared" , 1 )
	lock , err := sealLock( folder , key , "" )
	if err != nil { t.Fatal( err ) }
	secret , _ := key.Seal( "private" , "diary" , []byte( `{"secret":1}` ) )
	var leaked []string
	server := fakeServer( t , func( w http.ResponseWriter , r *http.Request ) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections":
			json.NewEncoder( w ).Encode( map[string]any{ "collections": []any{ map[string]any{ "id": "shared" , "name": "shared" , "lock": lock } } } )
		case r.Method == http.MethodGet && strings.HasSuffix( r.URL.Path , "/docs" ):
			json.NewEncoder( w ).Encode( map[string]any{ "docs": []any{
				map[string]any{ "collection": "private" , "id": "diary" , "version": 1 , "body": b64.EncodeToString( secret ) } ,
			} } )
		default:
			leaked = append( leaked , r.Method + " " + r.URL.Path )
			w.Write( []byte( `{}` ) )
		}
	} )
	store , _ := New( server.URL , "k" , encoded )
	if _ , err = store.PrepareShare( context.Background() , "shared" , true ); errors.Is( err , ErrCorrupt ) == false {
		t.Fatalf( "PrepareShare = %v, want ErrCorrupt" , err )
	}
	if len( leaked ) > 0 {
		t.Fatalf( "re-sealed and sent: %v" , leaked )
	}
}

// A server reporting a parent cycle (A in B in A) is ErrCorrupt, not a stack
// overflow walking up for keys.
func TestParentCycleIsCorrupt( t *testing.T ) {
	encoded , _ := testKey( t )
	server := fakeServer( t , func( w http.ResponseWriter , r *http.Request ) {
		json.NewEncoder( w ).Encode( map[string]any{ "collections": []any{
			map[string]any{ "id": "A" , "name": "A" , "parent": "B" , "version": 1 , "lock": "x" } ,
			map[string]any{ "id": "B" , "name": "B" , "parent": "A" , "version": 1 , "lock": "x" } ,
		} } )
	} )
	store , _ := New( server.URL , "k" , encoded )
	if _ , err := store.CollectionKey( context.Background() , "A" , false ); errors.Is( err , ErrCorrupt ) == false {
		t.Fatalf( "CollectionKey = %v, want ErrCorrupt" , err )
	}
}

// A server that leaves out by_key cannot hide a sharee's folder: the owner's
// client goes by the owner tag in the lockbox, which a sharee cannot make. A
// write by id into an untagged folder is refused; a tagged one is written.
func TestOwnerTagNotServerTrust( t *testing.T ) {
	encoded , key := testKey( t )
	shared , _ := generateCollectionKey( "shared" , 1 )
	shared_lock , _ := sealLock( shared , key , key.ownTag( "shared" , shared.id[ : ] ) )
	// The sharee's folder, under an id a service writes to, by_key left out.
	squat , _ := generateCollectionKey( "invoices" , 1 )
	squat_lock , _ := sealLock( squat , shared , "" )
	mine , _ := generateCollectionKey( "reports" , 1 )
	mine_lock , _ := sealLock( mine , shared , key.ownTag( "reports" , mine.id[ : ] ) )
	var wrote []string
	server := fakeServer( t , func( w http.ResponseWriter , r *http.Request ) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections":
			json.NewEncoder( w ).Encode( map[string]any{ "collections": []any{
				map[string]any{ "id": "shared" , "name": "shared" , "lock": shared_lock } ,
				map[string]any{ "id": "invoices" , "name": "invoices" , "parent": "shared" , "lock": squat_lock } ,
				map[string]any{ "id": "reports" , "name": "reports" , "parent": "shared" , "lock": mine_lock } ,
			} } )
		case r.Method == http.MethodPost && strings.Contains( r.URL.Path , "/docs/" ):
			wrote = append( wrote , r.URL.Path )
			json.NewEncoder( w ).Encode( map[string]any{ "version": 1 } )
		default:
			http.NotFound( w , r )
		}
	} )
	owner , err := New( server.URL , "kid.secret" , encoded )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()
	if _ , err = owner.Set( ctx , "invoices" , "x" , map[string]any{ "secret": 1 } ); errors.Is( err , ErrSharedCollection ) == false {
		t.Fatalf( "write into an untagged folder: %v" , err )
	}
	if len( wrote ) != 0 { t.Fatalf( "sent %v" , wrote ) }
	if _ , err = owner.Set( ctx , "reports" , "x" , map[string]any{ "n": 1 } ); err != nil { t.Fatalf( "write into a tagged folder: %v" , err ) }
	if _ , err = owner.Set( ctx , "invoices" , "y" , map[string]any{ "n": 2 } , AllowShared() ); err != nil { t.Fatalf( "AllowShared: %v" , err ) }
	if len( wrote ) != 2 { t.Fatalf( "sent %v" , wrote ) }
}

// A dishonest server that reports one of the owner's folders (diary, which
// has no keys yet and holds a private envelope) inside a shared one (S). A
// folder there would get keys wrapped for S, which S's sharee opens, so
// without AllowShared nothing gives it keys or re-seals what is in it, and
// nothing at all is sent.
func TestServerClaimedParentMintsNothing( t *testing.T ) {
	encoded , key := testKey( t )
	shared , _ := generateCollectionKey( "S" , 1 )
	shared_lock , _ := sealLock( shared , key , key.ownTag( "S" , shared.id[ : ] ) )
	secret , _ := key.Seal( "diary" , "entry" , []byte( `{"secret":1}` ) )
	var posted []string
	server := fakeServer( t , func( w http.ResponseWriter , r *http.Request ) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections":
			json.NewEncoder( w ).Encode( map[string]any{ "collections": []any{
				map[string]any{ "id": "S" , "name": "S" , "lock": shared_lock } ,
				map[string]any{ "id": "diary" , "name": "diary" , "parent": "S" } ,
			} } )
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/diary/docs":
			json.NewEncoder( w ).Encode( map[string]any{ "docs": []any{
				map[string]any{ "collection": "diary" , "id": "entry" , "version": 1 , "body": b64.EncodeToString( secret ) } ,
			} } )
		case r.Method == http.MethodGet:
			json.NewEncoder( w ).Encode( map[string]any{ "docs": []any{} } )
		default:
			posted = append( posted , r.URL.Path )
			json.NewEncoder( w ).Encode( map[string]any{ "collection": "diary" , "id": "x" , "version": 1 } )
		}
	} )
	owner , _ := New( server.URL , "k" , encoded )
	ctx := context.Background()
	if _ , err := owner.Set( ctx , "diary" , "x" , map[string]any{ "n": 1 } ); errors.Is( err , ErrSharedCollection ) == false {
		t.Fatalf( "Set = %v, want ErrSharedCollection" , err )
	}
	if _ , err := owner.CreateCollection( ctx , NewCollection{ Parent: "diary" } ); errors.Is( err , ErrSharedCollection ) == false {
		t.Fatalf( "CreateCollection under it = %v, want ErrSharedCollection" , err )
	}
	if _ , err := owner.CollectionKey( ctx , "diary" , true ); errors.Is( err , ErrSharedCollection ) == false {
		t.Fatalf( "CollectionKey = %v, want ErrSharedCollection" , err )
	}
	_ , err := owner.PrepareShare( ctx , "S" , true )
	if errors.Is( err , ErrSharedCollection ) == false || strings.Contains( err.Error() , "diary" ) == false {
		t.Fatalf( "PrepareShare = %v, want ErrSharedCollection naming diary" , err )
	}
	if len( posted ) != 0 { t.Fatalf( "sent %v" , posted ) }
	// Asked for, it is given keys there (untagged: they are S's side now).
	if _ , err = owner.Set( ctx , "diary" , "x" , map[string]any{ "n": 1 } , AllowShared() ); err != nil { t.Fatalf( "AllowShared: %v" , err ) }
	if len( posted ) != 2 || posted[ 0 ] != "/api/collections/diary" { t.Fatalf( "sent %v" , posted ) }
}

// The same folder with a lockbox planted for it under S (signed with S's
// write key, which S's sharee holds): the owner's client opens it, but it is
// not the owner's, so its private envelopes are not sealed for sharing.
func TestPrepareShareRefusesPlantedLock( t *testing.T ) {
	encoded , key := testKey( t )
	shared , _ := generateCollectionKey( "S" , 1 )
	shared_lock , _ := sealLock( shared , key , key.ownTag( "S" , shared.id[ : ] ) )
	planted , _ := generateCollectionKey( "diary" , 1 )
	planted_lock , _ := sealLock( planted , shared , "" )
	secret , _ := key.Seal( "diary" , "entry" , []byte( `{"secret":1}` ) )
	var posted []string
	server := fakeServer( t , func( w http.ResponseWriter , r *http.Request ) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections":
			json.NewEncoder( w ).Encode( map[string]any{ "collections": []any{
				map[string]any{ "id": "S" , "name": "S" , "lock": shared_lock } ,
				map[string]any{ "id": "diary" , "name": "diary" , "parent": "S" , "lock": planted_lock } ,
			} } )
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections/diary/docs":
			json.NewEncoder( w ).Encode( map[string]any{ "docs": []any{
				map[string]any{ "collection": "diary" , "id": "entry" , "version": 1 , "body": b64.EncodeToString( secret ) } ,
			} } )
		case r.Method == http.MethodGet:
			json.NewEncoder( w ).Encode( map[string]any{ "docs": []any{} } )
		default:
			posted = append( posted , r.URL.Path )
			w.Write( []byte( `{}` ) )
		}
	} )
	owner , _ := New( server.URL , "k" , encoded )
	_ , err := owner.PrepareShare( context.Background() , "S" , true )
	if errors.Is( err , ErrSharedCollection ) == false || strings.Contains( err.Error() , "diary" ) == false {
		t.Fatalf( "PrepareShare = %v, want ErrSharedCollection naming diary" , err )
	}
	if len( posted ) != 0 { t.Fatalf( "sent %v" , posted ) }
}

// Owned all the way down: a folder carrying the owner's tag under one a
// sharee made is not the owner's to write into, a folder made inside the
// sharee's gets no tag, and new keys from a next_lock are judged by their
// own lockbox, not the lock's.
func TestOwnedAllTheWayDown( t *testing.T ) {
	encoded , key := testKey( t )
	shared , _ := generateCollectionKey( "S" , 1 )
	shared_lock , _ := sealLock( shared , key , key.ownTag( "S" , shared.id[ : ] ) )
	theirs , _ := generateCollectionKey( "X" , 1 )
	theirs_lock , _ := sealLock( theirs , shared , "" )
	below , _ := generateCollectionKey( "Y" , 1 )
	below_lock , _ := sealLock( below , theirs , key.ownTag( "Y" , below.id[ : ] ) )
	// R: the owner's, with new keys staged by someone holding S's.
	mine , _ := generateCollectionKey( "R" , 1 )
	mine_lock , _ := sealLock( mine , shared , key.ownTag( "R" , mine.id[ : ] ) )
	staged , _ := generateCollectionKey( "R" , 2 )
	staged_lock , _ := sealLock( staged , shared , "" )
	var locks []string
	var wrote []string
	server := fakeServer( t , func( w http.ResponseWriter , r *http.Request ) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/collections":
			json.NewEncoder( w ).Encode( map[string]any{ "collections": []any{
				map[string]any{ "id": "S" , "name": "S" , "lock": shared_lock } ,
				map[string]any{ "id": "X" , "name": "X" , "parent": "S" , "lock": theirs_lock } ,
				map[string]any{ "id": "Y" , "name": "Y" , "parent": "X" , "lock": below_lock } ,
				map[string]any{ "id": "R" , "name": "R" , "parent": "S" , "lock": mine_lock , "next_lock": staged_lock } ,
			} } )
		case r.Method == http.MethodPost && r.URL.Path == "/api/collections":
			var body struct{ Lock string `json:"lock"` }
			json.NewDecoder( r.Body ).Decode( &body )
			locks = append( locks , body.Lock )
			json.NewEncoder( w ).Encode( map[string]any{ "id": "Z" } )
		default:
			wrote = append( wrote , r.URL.Path )
			json.NewEncoder( w ).Encode( map[string]any{ "version": 1 } )
		}
	} )
	owner , _ := New( server.URL , "k" , encoded )
	ctx := context.Background()
	if _ , err := owner.Set( ctx , "Y" , "x" , map[string]any{ "n": 1 } ); errors.Is( err , ErrSharedCollection ) == false {
		t.Fatalf( "write under a sharee's folder: %v" , err )
	}
	if _ , err := owner.Set( ctx , "R" , "x" , map[string]any{ "n": 1 } ); errors.Is( err , ErrSharedCollection ) == false {
		t.Fatalf( "write with untagged new keys: %v" , err )
	}
	if len( wrote ) != 0 { t.Fatalf( "sent %v" , wrote ) }
	if _ , err := owner.CreateCollection( ctx , NewCollection{ ID: "Z" , Parent: "X" } ); err != nil { t.Fatal( err ) }
	if len( locks ) != 1 || lockOwn( locks[ 0 ] ) != "" { t.Fatalf( "a folder inside the sharee's got the owner tag: %v" , locks ) }
}
