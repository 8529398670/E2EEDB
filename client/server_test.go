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
	folder , _ := generateCollectionKey( "shared" )
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
	shared , _ := generateCollectionKey( "shared" )
	shared_lock , _ := sealLock( shared , key , key.ownTag( "shared" , shared.id[ : ] ) )
	// The sharee's folder, under an id a service writes to, by_key left out.
	squat , _ := generateCollectionKey( "invoices" )
	squat_lock , _ := sealLock( squat , shared , "" )
	mine , _ := generateCollectionKey( "reports" )
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
