package routes

import (
	http "net/http"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	models "github.com/8529398670/E2EEDB/server/models"
)

// E2EEDB H0: no API key finds a way to the keyring. A key makes no login
// link for an account that already has one (its own, or reissued), and a
// browser whose way in started with a key (a new account's link, and every
// link that session makes in turn) is kept from the keyring. A person's
// browser still reaches it, and each read is logged.
func TestNoKeyFindsAWayToTheKeyring( t *testing.T ) {
	fixture := newAuthFixture( t )
	alice := fixture.signIn( t , fixture.alice.ID )
	if status , reply := send( t , alice , "/api/keyring" , fiber.Map{ "keyring": `{"alice":"kr"}` , "if_version": 0 } ); status != 200 { t.Fatalf( "set: %d %v" , status , reply ) }
	key , _ , err := models.IssueAPIKey( fixture.store , fixture.owner.ID , "ops" , models.RoleAdmin , time.Hour )
	if err != nil { t.Fatal( err ) }
	unlimited := fiber.Map{ "max_uses": 0 , "expires_in_minutes": 0 }

	// No link for an account that has one.
	if status , _ := fixture.withKey( t , key , http.MethodPost , "/api/account/login-link" , unlimited ); status != fiber.StatusForbidden { t.Fatalf( "own link: %d" , status ) }
	for _ , target := range []*models.User{ fixture.owner , fixture.alice } {
		if status , _ := fixture.withKey( t , key , http.MethodPost , userPath( target , "reissue-login" ) , unlimited ); status != fiber.StatusForbidden { t.Fatalf( "reissue #%d: %d" , target.ID , status ) }
	}

	// The long way round: the key makes an admin account, signs in as it, and
	// that browser reissues Alice's link. Neither browser reaches a keyring.
	status , reply := fixture.withKey( t , key , http.MethodPost , "/api/admin/users" , fiber.Map{ "display_name": "Mallory" , "role": "admin" } )
	if status != fiber.StatusCreated { t.Fatalf( "create: %d %v" , status , reply ) }
	mallory := fixture.browser()
	if status , _ = mallory.post( t , "/api/login" , fiber.Map{ "credential": strings.TrimPrefix( reply[ "login_path" ].( string ) , "/login/" ) } ); status != 200 { t.Fatalf( "sign in as the new admin: %d" , status ) }
	status , reply = send( t , mallory , userPath( fixture.alice , "reissue-login" ) , fiber.Map{} )
	if status != 200 { t.Fatalf( "reissue from that browser: %d %v" , status , reply ) }
	as_alice := fixture.browser()
	if status , _ = as_alice.post( t , "/api/login" , fiber.Map{ "credential": strings.TrimPrefix( reply[ "login_path" ].( string ) , "/login/" ) } ); status != 200 { t.Fatalf( "sign in as Alice: %d" , status ) }
	for label , browser := range map[ string ]*browser{ "the new admin" : mallory , "Alice, through it": as_alice } {
		if status , reply = browser.do( t , http.MethodGet , "/api/keyring" , nil ); status != fiber.StatusForbidden || reply[ "error" ] != "key_made_session" { t.Fatalf( "%s read a keyring: %d %v" , label , status , reply ) }
		if status , _ = send( t , browser , "/api/keyring" , fiber.Map{ "keyring": `{"x":1}` } ); status != fiber.StatusForbidden { t.Fatalf( "%s replaced a keyring: %d" , label , status ) }
	}

	// A person's browser still reads it.
	if status , reply = alice.do( t , http.MethodGet , "/api/keyring" , nil ); status != 200 || reply[ "keyring" ] != `{"alice":"kr"}` { t.Fatalf( "Alice's own browser: %d %v" , status , reply ) }
}
