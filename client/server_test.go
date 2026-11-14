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
	lock , err := sealLock( folder , key )
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
