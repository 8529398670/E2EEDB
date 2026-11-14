package routes

import (
	http "net/http"
	strings "strings"
	testing "testing"

	fiber "github.com/gofiber/fiber/v3"
	models "github.com/8529398670/E2EEDB/server/models"
)

// launder is a leaked key turning itself into ways in that outlive it: a
// login link signs in a session, and that session makes a second login link
// and a new API key.
func launder( t *testing.T , fixture *authFixture ) ( key_id string , session *browser , link string , successor string ) {
	leaked := issueKey( t , fixture , fixture.alice , models.RoleUser )
	key_id = strings.SplitN( leaked , "." , 2 )[ 0 ]
	status , reply := fixture.withKey( t , leaked , http.MethodPost , "/api/account/login-link" , fiber.Map{} )
	if status != 200 { t.Fatalf( "login link from key: %d %v" , status , reply ) }
	session = fixture.browser()
	if status , reply = session.post( t , "/api/login" , fiber.Map{ "credential": strings.TrimPrefix( reply[ "login_path" ].( string ) , "/login/" ) } ); status != 200 {
		t.Fatalf( "redeem: %d %v" , status , reply )
	}
	if status , reply = send( t , session , "/api/account/login-link" , fiber.Map{} ); status != 200 { t.Fatalf( "second link: %d %v" , status , reply ) }
	link = strings.TrimPrefix( reply[ "login_path" ].( string ) , "/login/" )
	if status , reply = send( t , session , "/api/keys" , fiber.Map{ "name": "successor" } ); status != 201 { t.Fatalf( "successor key: %d %v" , status , reply ) }
	successor = reply[ "credential" ].( string )
	return
}

func checkLaunderedDead( t *testing.T , fixture *authFixture , session *browser , link string , successor string ) {
	t.Helper()
	if session.signedIn( t ) { t.Error( "the key's session is still signed in" ) }
	other := fixture.browser()
	if status , _ := other.post( t , "/api/login" , fiber.Map{ "credential": link } ); status == 200 || other.signedIn( t ) {
		t.Errorf( "the session's login link still signs in (%d)" , status )
	}
	if status , _ := fixture.withKey( t , successor , http.MethodGet , "/api/collections" , nil ); status == 200 {
		t.Error( "the session's API key still works" )
	}
}

// Revoking a key ends everything that came through it.
func TestRevokedKeyTakesItsSuccessors( t *testing.T ) {
	fixture := newAuthFixture( t )
	key_id , session , link , successor := launder( t , fixture )
	if err := models.RevokeAPIKey( fixture.store , key_id ); err != nil { t.Fatal( err ) }
	checkLaunderedDead( t , fixture , session , link , successor )
	keys , err := models.ListAPIKeysForUser( fixture.store , fixture.alice.ID )
	if err != nil { t.Fatal( err ) }
	for _ , key := range keys {
		if key.Name == "successor" && key.RevokedAt == nil { t.Error( "the successor key is not shown as revoked" ) }
	}
}

// A key that is gone from the database (expired and purged, say) takes them
// too.
func TestPurgedKeyTakesItsSuccessors( t *testing.T ) {
	fixture := newAuthFixture( t )
	key_id , session , link , successor := launder( t , fixture )
	if err := models.PurgeAPIKey( fixture.store , key_id ); err != nil { t.Fatal( err ) }
	checkLaunderedDead( t , fixture , session , link , successor )
}

// Ways in a browser made on its own owe nothing to any key.
func TestSessionWithoutKeyUnaffected( t *testing.T ) {
	fixture := newAuthFixture( t )
	browser := fixture.signIn( t , fixture.alice.ID )
	status , reply := send( t , browser , "/api/keys" , fiber.Map{ "name": "mine" } )
	if status != 201 { t.Fatalf( "key: %d %v" , status , reply ) }
	if status , _ = fixture.withKey( t , reply[ "credential" ].( string ) , http.MethodGet , "/api/collections" , nil ); status != 200 {
		t.Fatalf( "own key: %d" , status )
	}
}
