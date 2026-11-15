package routes

import (
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	models "github.com/8529398670/E2EEDB/server/models"
)

// The lockbox of a shared collection is the owner's to give (PLAN H5): no
// scoped key is made for a collection without one, and a scoped key cannot
// set its own root's, which would stay (lock_exists) and answer bad_lock or
// 200 to a guess at the root's parent.
func TestScopedKeyCannotGiveItsRootALockbox( t *testing.T ) {
	fixture := newAuthFixture( t )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections" , fiber.Map{ "id": "bare" } ); status != 200 { t.Fatalf( "create: %d %v" , status , reply ) }
	browser := fixture.signIn( t , fixture.alice.ID )
	if status , reply := send( t , browser , "/api/keys" , fiber.Map{ "name": "x" , "scope": fiber.Map{ "collection": "bare" , "access": "write" } } ); status != 409 || reply[ "error" ] != "lock_required" {
		t.Fatalf( "scoped key for a collection with no lockbox: %d %v" , status , reply )
	}
	// One made anyway (as before this check) still cannot set it.
	scoped , _ , err := models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "bare" , models.KeyScope{ Collection: "bare" , Write: true , Born: bornOf( t , fixture , "bare" ) } , time.Hour )
	if err != nil { t.Fatal( err ) }
	if status , reply := fixture.withKey( t , scoped , fiber.MethodPost , "/api/collections/bare" , fiber.Map{ "lock": shapedLock( "" ) } ); status != 403 {
		t.Fatalf( "scoped key set its root's lockbox: %d %v" , status , reply )
	}
	// The owner still can.
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/bare" , fiber.Map{ "lock": shapedLock( "" ) } ); status != 200 { t.Fatalf( "owner: %d %v" , status , reply ) }
}
