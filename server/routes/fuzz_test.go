package routes

import (
	bytes "bytes"
	base64 "encoding/base64"
	json "encoding/json"
	io "io"
	http "net/http"
	path "path"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	docstore "github.com/8529398670/E2EEDB/server/docstore"
	models "github.com/8529398670/E2EEDB/server/models"
)

// FuzzScopedKeyStaysInside throws made-up requests at the whole app with an
// access key's API key, read only or read and write, scoped to "shared".
// Whatever it sends:
//
//   - the server never fails (500) or panics;
//   - nothing outside "shared" changes: not the account's other folder, not
//     the folder "shared" itself, not another account;
//   - no reply carries a document from outside it;
//   - nothing but the document routes answers 2xx;
//   - the read-only key changes nothing at all.
//
//	go test ./server/routes -run '^$' -fuzz FuzzScopedKeyStaysInside -fuzztime 5m
func FuzzScopedKeyStaysInside( f *testing.F ) {
	fixture := newAuthFixture( f )
	alice , _ , err := models.IssueAPIKey( fixture.store , fixture.alice.ID , "full" , models.RoleUser , time.Hour )
	if err != nil { f.Fatal( err ) }
	bob , _ , err := models.IssueAPIKey( fixture.store , fixture.owner.ID , "full" , models.RoleAdmin , time.Hour )
	if err != nil { f.Fatal( err ) }
	setup := func( key string , route string , body fiber.Map ) {
		if status , reply := fixture.withKey( f , key , http.MethodPost , route , body ); status != 200 { f.Fatalf( "%s: %d %v" , route , status , reply ) }
	}
	setup( alice , "/api/collections" , fiber.Map{ "id": "shared" } )
	setup( alice , "/api/collections" , fiber.Map{ "id": "inner" , "parent": "shared" } )
	setup( alice , "/api/collections" , fiber.Map{ "id": "private" } )
	setup( alice , "/api/collections/shared/docs/s1" , fiber.Map{ "body": fakeEnvelope( 0x31 ) } )
	setup( alice , "/api/collections/inner/docs/i1" , fiber.Map{ "body": fakeEnvelope( 0x32 ) } )
	setup( alice , "/api/collections/private/docs/p1" , fiber.Map{ "body": fakeEnvelope( 0x51 ) } )
	setup( bob , "/api/collections/shared/docs/b1" , fiber.Map{ "body": fakeEnvelope( 0x62 ) } )

	docs := fixture.handlers.Docs
	shared , err := docs.GetCollection( fixture.alice.ID , "shared" )
	if err != nil { f.Fatal( err ) }
	private , err := docs.GetCollection( fixture.alice.ID , "private" )
	if err != nil { f.Fatal( err ) }
	scoped := [ 2 ]string{}
	for index , write := range []bool{ false , true } {
		scoped[ index ] , _ , err = models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "fuzz" , models.KeyScope{ Collection: "shared" , Write: write , Born: shared.Born } , time.Hour )
		if err != nil { f.Fatal( err ) }
	}
	// Both keys work, so the fuzzer is not just meeting 401s.
	for _ , key := range scoped {
		if status , reply := fixture.withKey( f , key , http.MethodGet , "/api/collections" , nil ); status != 200 || reply[ "total" ] != float64( 2 ) { f.Fatalf( "scoped list: %d %v" , status , reply ) }
	}
	if status , reply := fixture.withKey( f , scoped[ 1 ] , http.MethodPost , "/api/collections/inner/docs/w1" , fiber.Map{ "body": fakeCollectionEnvelope( 0x33 ) } ); status != 200 { f.Fatalf( "scoped write: %d %v" , status , reply ) }
	type secret struct{ user uint64 ; doc docstore.Doc }
	secrets := map[ string ]secret{}
	for _ , place := range []struct{ user uint64 ; collection string ; id string }{ { fixture.alice.ID , "private" , "p1" } , { fixture.owner.ID , "shared" , "b1" } } {
		doc , err := docs.Get( place.user , place.collection , place.id )
		if err != nil { f.Fatal( err ) }
		secrets[ base64.StdEncoding.EncodeToString( doc.Body ) ] = secret{ place.user , doc }
	}

	for _ , seed := range []struct{ method string ; route string ; body string }{
		{ "GET" , "collections" , `` },
		{ "GET" , "changes?since=0" , `` },
		{ "GET" , "collections/private/docs/p1" , `` },
		{ "GET" , "collections/shared/docs?include_body=true" , `` },
		{ "POST" , "collections" , `{"id":"AAAAAAAAAAAAAAAAAAAAAA","parent":"shared"}` },
		{ "POST" , "collections" , `{"id":"AAAAAAAAAAAAAAAAAAAAAB","parent":""}` },
		{ "POST" , "collections/inner" , `{"parent":"private"}` },
		{ "POST" , "collections/shared" , `{"name":"x"}` },
		{ "POST" , "collections/shared/delete" , `{}` },
		{ "POST" , "collections/inner/delete" , `{}` },
		{ "POST" , "collections/private/docs/p1" , `{"body":"` + fakeCollectionEnvelope( 9 ) + `"}` },
		{ "POST" , "collections/inner/docs/n1" , `{"body":"` + fakeCollectionEnvelope( 9 ) + `","if_version":0}` },
		{ "POST" , "collections/AAAAAAAAAAAAAAAAAAAAAC/docs/n1" , `{"body":"` + fakeCollectionEnvelope( 9 ) + `"}` },
		{ "POST" , "collections/shared/docs/s1/delete" , `{}` },
		{ "POST" , "collections/shared/docs/s1/move" , `{"to_collection":"private","body":"` + fakeCollectionEnvelope( 9 ) + `"}` },
		{ "POST" , "collections/private/docs/p1/move" , `{"to_collection":"shared","body":"` + fakeCollectionEnvelope( 9 ) + `"}` },
		{ "POST" , "collections/shared/rotate" , `{"locks":{"shared":"x"}}` },
		{ "POST" , "collections/shared/docs/..%2f..%2fprivate%2fdocs%2fp1" , `{}` },
		{ "GET" , "keyring" , `` },
		{ "POST" , "keys" , `{"name":"x"}` },
		{ "GET" , "me" , `` },
	} {
		f.Add( seed.method == "POST" , seed.route , []byte( seed.body ) , seed.route == "collections" )
	}

	allowed := func( route string ) bool {
		return route == "/api/collections" || strings.HasPrefix( route , "/api/collections/" ) || route == "/api/changes"
	}
	f.Fuzz( func( t *testing.T , post bool , route string , body []byte , write bool ) {
		method , key := http.MethodGet , scoped[ 0 ]
		if post { method = http.MethodPost }
		if write { key = scoped[ 1 ] }
		// A space or control byte would only break the request line the
		// in-process transport writes; no HTTP client sends one.
		// Nor does a request line past the transport's 8 KiB buffer reach a
		// handler: the server refuses it before routing.
		if len( route ) > 2048 || strings.IndexFunc( route , func( r rune ) bool { return r <= ' ' || r == 0x7f } ) >= 0 { return }
		request , err := http.NewRequest( method , "/api/" + route , bytes.NewReader( body ) )
		if err != nil { return }
		request.Header.Set( "Content-Type" , "application/json" )
		request.Header.Set( "Authorization" , "Bearer " + key )
		seq_before , _ := docs.TreeSeq( fixture.alice.ID )
		changes_before , _ , _ := docs.Changes( fixture.alice.ID , 0 , 100000 )

		response , err := fixture.app.Test( request , fiber.TestConfig{ Timeout: 10 * time.Second } )
		if err != nil { t.Fatalf( "%s %s: %v" , method , request.URL , err ) }
		reply , _ := io.ReadAll( response.Body )
		status := response.StatusCode

		if status >= 500 && status != 503 { t.Fatalf( "%s %s %q: %d %s" , method , request.URL , body , status , reply ) }
		if status >= 200 && status < 300 && allowed( path.Clean( request.URL.Path ) ) == false {
			t.Fatalf( "a scoped key reached %s %s: %d %s" , method , request.URL , status , reply )
		}
		for encoded := range secrets {
			if bytes.Contains( reply , []byte( encoded ) ) { t.Fatalf( "%s %s leaked a document from outside the scope: %s" , method , request.URL , reply ) }
		}
		for _ , held := range secrets {
			doc := held.doc
			now , err := docs.Get( held.user , doc.Collection , doc.ID )
			if err != nil || bytes.Equal( now.Body , doc.Body ) == false || now.Version != doc.Version {
				t.Fatalf( "%s %s %q changed %s/%s outside the scope: %v" , method , request.URL , body , doc.Collection , doc.ID , err )
			}
		}
		for _ , want := range []docstore.Collection{ shared , private } {
			now , err := docs.GetCollection( fixture.alice.ID , want.ID )
			if err != nil || now.Parent != want.Parent || now.Name != want.Name || now.Born != want.Born || now.Lock != want.Lock || now.NextLock != want.NextLock {
				t.Fatalf( "%s %s %q changed folder %s: %+v %v" , method , request.URL , body , want.ID , now , err )
			}
		}
		top , _ , _ := docs.Collections( fixture.alice.ID , 0 , 100000 )
		for _ , entry := range top {
			if entry.Parent == "" && entry.ID != "shared" && entry.ID != "private" {
				t.Fatalf( "%s %s %q made a top-level folder %s" , method , request.URL , body , entry.ID )
			}
		}
		if write == false {
			seq_after , _ := docs.TreeSeq( fixture.alice.ID )
			changes_after , _ , _ := docs.Changes( fixture.alice.ID , 0 , 100000 )
			if seq_after != seq_before || len( changes_after ) != len( changes_before ) || ( len( changes_after ) > 0 && changes_after[ len( changes_after ) - 1 ].Seq != changes_before[ len( changes_before ) - 1 ].Seq ) {
				t.Fatalf( "the read-only key changed something: %s %s %q -> %d %s" , method , request.URL , body , status , reply )
			}
		}
		if status == 200 && json.Valid( reply ) == false && strings.HasPrefix( response.Header.Get( "Content-Type" ) , "application/json" ) {
			t.Fatalf( "%s %s: invalid JSON reply %q" , method , request.URL , reply )
		}
	} )
}

// fakeCollectionEnvelope is a body the server takes from a scoped key: the
// server checks only its kind and size, never its signature.
func fakeCollectionEnvelope( fill byte ) ( encoded string ) {
	body := make( []byte , docstore.EnvelopeCollectionMin + 8 )
	for index := range body { body[ index ] = fill }
	body[ 0 ] = docstore.EnvelopeCollection
	encoded = base64.StdEncoding.EncodeToString( body )
	return
}
