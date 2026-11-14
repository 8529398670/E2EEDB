package routes

import (
	base64 "encoding/base64"
	http "net/http"
	strconv "strconv"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	docstore "github.com/8529398670/E2EEDB/server/docstore"
	models "github.com/8529398670/E2EEDB/server/models"
)

// What these pin down: an account only ever reaches its own documents, by
// key or by browser; writes are conditional on versions when asked; the
// server refuses anything that is not an envelope; and the sync feed reports
// deletes.

// fakeEnvelope is a body the server accepts (a private envelope). Its contents are never opened,
// so they need not be real ciphertext here (the client tests cover that).
func fakeEnvelope( fill byte ) ( encoded string ) {
	body := make( []byte , docstore.EnvelopeMasterMin + 8 )
	for index := range body { body[ index ] = fill }
	body[ 0 ] = docstore.EnvelopeMaster
	encoded = base64.StdEncoding.EncodeToString( body )
	return
}

func issueKey( t *testing.T , fixture *authFixture , user *models.User , role string ) ( key string ) {
	t.Helper()
	key , _ , err := models.IssueAPIKey( fixture.store , user.ID , "docs" , role , time.Hour )
	if err != nil { t.Fatal( err ) }
	return
}

func TestDocsThroughAKey( t *testing.T ) {
	fixture := newAuthFixture( t )
	key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	path := "/api/collections/notes/docs/n1"

	status , reply := fixture.withKey( t , key , http.MethodPost , path , fiber.Map{ "body": fakeEnvelope( 7 ) , "if_version": 0 } )
	if status != 200 || reply[ "version" ] != float64( 1 ) { t.Fatalf( "create: %d %v" , status , reply ) }
	status , reply = fixture.withKey( t , key , http.MethodGet , path , nil )
	if status != 200 || reply[ "body" ] != fakeEnvelope( 7 ) { t.Fatalf( "get: %d %v" , status , reply ) }

	// A stale write is refused with what is there now.
	status , reply = fixture.withKey( t , key , http.MethodPost , path , fiber.Map{ "body": fakeEnvelope( 8 ) , "if_version": 0 } )
	if status != 409 || reply[ "error" ] != "version_conflict" || reply[ "current_version" ] != float64( 1 ) { t.Fatalf( "stale create: %d %v" , status , reply ) }
	status , reply = fixture.withKey( t , key , http.MethodPost , path , fiber.Map{ "body": fakeEnvelope( 8 ) , "if_version": 1 } )
	if status != 200 || reply[ "version" ] != float64( 2 ) { t.Fatalf( "update: %d %v" , status , reply ) }

	status , reply = fixture.withKey( t , key , http.MethodGet , "/api/collections" , nil )
	if status != 200 || reply[ "total" ] != float64( 1 ) || reply[ "doc_count" ] != float64( 1 ) { t.Fatalf( "collections: %d %v" , status , reply ) }
	status , reply = fixture.withKey( t , key , http.MethodGet , "/api/collections/notes/docs?include_body=true" , nil )
	if status != 200 || reply[ "total" ] != float64( 1 ) { t.Fatalf( "list: %d %v" , status , reply ) }

	status , reply = fixture.withKey( t , key , http.MethodPost , path + "/delete" , fiber.Map{ "if_version": 2 } )
	if status != 200 || reply[ "deleted" ] != true { t.Fatalf( "delete: %d %v" , status , reply ) }
	if status , _ = fixture.withKey( t , key , http.MethodGet , path , nil ); status != 404 { t.Fatalf( "get after delete: %d" , status ) }

	status , reply = fixture.withKey( t , key , http.MethodGet , "/api/changes?since=0" , nil )
	changes , _ := reply[ "changes" ].( []any )
	if status != 200 || len( changes ) != 1 || changes[ 0 ].( map[string]any )[ "deleted" ] != true || reply[ "more" ] != false {
		t.Fatalf( "changes: %d %v" , status , reply )
	}
	since := reply[ "next_since" ].( float64 )
	status , reply = fixture.withKey( t , key , http.MethodGet , "/api/changes?since=" + strconv.FormatInt( int64( since ) , 10 ) , nil )
	if status != 200 || len( reply[ "changes" ].( []any ) ) != 0 || reply[ "next_since" ] != since { t.Fatalf( "changes after: %d %v" , status , reply ) }
}

func TestDocsBelongToOneAccount( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := issueKey( t , fixture , fixture.alice , models.RoleUser )
	// The owner's admin key gets no further than anyone else's.
	owner := issueKey( t , fixture , fixture.owner , models.RoleAdmin )
	path := "/api/collections/private/docs/secret"
	if status , reply := fixture.withKey( t , alice , http.MethodPost , path , fiber.Map{ "body": fakeEnvelope( 1 ) } ); status != 200 { t.Fatalf( "alice write: %d %v" , status , reply ) }

	if status , _ := fixture.withKey( t , owner , http.MethodGet , path , nil ); status != 404 { t.Fatalf( "owner read alice's doc: %d" , status ) }
	if status , _ := fixture.withKey( t , owner , http.MethodPost , path + "/delete" , fiber.Map{} ); status != 404 { t.Fatalf( "owner deleted alice's doc: %d" , status ) }
	if _ , reply := fixture.withKey( t , owner , http.MethodGet , "/api/collections" , nil ); reply[ "total" ] != float64( 0 ) { t.Fatalf( "owner sees alice's collections: %v" , reply ) }
	if _ , reply := fixture.withKey( t , owner , http.MethodGet , "/api/changes" , nil ); len( reply[ "changes" ].( []any ) ) != 0 { t.Fatalf( "owner sees alice's changes: %v" , reply ) }
	// The owner writing the same address makes their own document.
	if status , _ := fixture.withKey( t , owner , http.MethodPost , path , fiber.Map{ "body": fakeEnvelope( 2 ) , "if_version": 0 } ); status != 200 { t.Fatalf( "owner's own doc: %d" , status ) }
	if _ , reply := fixture.withKey( t , alice , http.MethodGet , path , nil ); reply[ "body" ] != fakeEnvelope( 1 ) { t.Fatalf( "alice's doc changed: %v" , reply ) }

	// Signed out, nothing.
	if status , _ := fixture.browser().do( t , http.MethodGet , path , nil ); status != 401 { t.Fatalf( "signed out: %d" , status ) }
}

func TestDocsRefuseWhatIsNotAnEnvelope( t *testing.T ) {
	fixture := newAuthFixture( t )
	key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	plain := base64.StdEncoding.EncodeToString( []byte( `{"name":"this is plaintext JSON, which the server must not take"}` ) )
	cases := []struct {
		path string
		body fiber.Map
	}{
		{ "/api/collections/notes/docs/a" , fiber.Map{ "body": plain } },
		{ "/api/collections/notes/docs/a" , fiber.Map{ "body": "not base64!" } },
		{ "/api/collections/bad.name/docs/a" , fiber.Map{ "body": fakeEnvelope( 1 ) } },
		{ "/api/collections/notes/docs/a%20b" , fiber.Map{ "body": fakeEnvelope( 1 ) } },
		{ "/api/collections/notes/docs/a" , fiber.Map{ "body": fakeEnvelope( 1 ) , "if_version": -1 } },
	}
	for _ , each := range cases {
		if status , reply := fixture.withKey( t , key , http.MethodPost , each.path , each.body ); status != 400 {
			t.Errorf( "%s %v: %d %v" , each.path , each.body , status , reply )
		}
	}

	fixture.cfg.Docs = fixture.cfg.Docs.Limits()
	fixture.cfg.Docs.MaxDocBytes = docstore.EnvelopeMasterMin + 4
	status , reply := fixture.withKey( t , key , http.MethodPost , "/api/collections/notes/docs/big" , fiber.Map{ "body": fakeEnvelope( 1 ) } )
	if status != 413 || reply[ "error" ] != "doc_too_large" { t.Fatalf( "too large: %d %v" , status , reply ) }
}

func TestDocsFromABrowserNeedTheCSRFToken( t *testing.T ) {
	fixture := newAuthFixture( t )
	client := fixture.signIn( t , fixture.alice.ID )
	path := "/api/collections/notes/docs/a"
	if status , _ := client.post( t , path , fiber.Map{ "body": fakeEnvelope( 1 ) } ); status != 403 { t.Fatalf( "no token: %d" , status ) }
	if status , reply := send( t , client , path , fiber.Map{ "body": fakeEnvelope( 1 ) } ); status != 200 { t.Fatalf( "with token: %d %v" , status , reply ) }
	if status , _ := client.post( t , path + "/delete" , fiber.Map{} ); status != 403 { t.Fatalf( "delete without token: %d" , status ) }
	if status , _ := client.post( t , "/api/keyring" , fiber.Map{ "keyring": "{}" } ); status != 403 { t.Fatalf( "keyring without token: %d" , status ) }
}

func TestKeyringRoutes( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	if status , _ := alice.do( t , http.MethodGet , "/api/keyring" , nil ); status != 404 { t.Fatalf( "no keyring yet: %d" , status ) }
	status , reply := send( t , alice , "/api/keyring" , fiber.Map{ "keyring": `{"v":1}` , "if_version": 0 } )
	if status != 200 || reply[ "version" ] != float64( 1 ) { t.Fatalf( "set: %d %v" , status , reply ) }
	if status , _ = send( t , alice , "/api/keyring" , fiber.Map{ "keyring": `{"v":1}` , "if_version": 0 } ); status != 409 { t.Fatalf( "second create: %d" , status ) }
	status , reply = alice.do( t , http.MethodGet , "/api/keyring" , nil )
	if status != 200 || reply[ "keyring" ] != `{"v":1}` { t.Fatalf( "get: %d %v" , status , reply ) }
	owner := fixture.signIn( t , fixture.owner.ID )
	if status , _ = owner.do( t , http.MethodGet , "/api/keyring" , nil ); status != 404 { t.Fatalf( "another account read the keyring: %d" , status ) }
}

// An API key never reaches the keyring, the account's own full key
// included: it must not take the wrapped master key away to guess the
// passphrase offline, or replace it and lock the passphrase out.
func TestKeyringRefusesAPIKeys( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	if status , reply := send( t , alice , "/api/keyring" , fiber.Map{ "keyring": `{"v":1}` , "if_version": 0 } ); status != 200 { t.Fatalf( "set: %d %v" , status , reply ) }
	key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	if status , _ := fixture.withKey( t , key , http.MethodGet , "/api/keyring" , nil ); status != 403 { t.Fatalf( "a key read the keyring: %d" , status ) }
	if status , _ := fixture.withKey( t , key , http.MethodPost , "/api/keyring" , fiber.Map{ "keyring": `{"v":2}` , "if_version": 1 } ); status != 403 { t.Fatalf( "a key replaced the keyring: %d" , status ) }
}
