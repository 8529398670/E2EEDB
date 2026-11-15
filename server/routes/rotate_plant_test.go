package routes

import (
	context "context"
	base64 "encoding/base64"
	json "encoding/json"
	errors "errors"
	os "os"
	filepath "path/filepath"
	slices "slices"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	client "github.com/8529398670/E2EEDB/client"
	models "github.com/8529398670/E2EEDB/server/models"
)

// A read/write sharee who expects to be cut off cannot plant anything that
// stops the rotation meant to do it (PLAN H1, H2): a folder at the last
// epoch, a lockbox that does not open, or a document no key opens.
func TestRotationSurvivesWhatAShareePlants( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , err := client.New( base , api_key , master_text )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()
	if _ , err = owner.CreateCollection( ctx , client.NewCollection{ ID: "projects" } ); err != nil { t.Fatal( err ) }
	if _ , err = owner.Set( ctx , "projects" , "a" , invoice{ Customer: "mine" } ); err != nil { t.Fatal( err ) }
	key , err := owner.PrepareShare( ctx , "projects" , true )
	if err != nil { t.Fatal( err ) }
	api , _ , err := models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "projects" , models.KeyScope{ Collection: "projects" , Write: true , Born: bornOf( t , fixture , "projects" ) } , time.Hour )
	if err != nil { t.Fatal( err ) }
	token , _ := client.NewAccessToken( api , key )
	sharee , _ := client.NewScoped( base , token )
	newFolder := func() string {
		status , reply := fixture.withKey( t , api , fiber.MethodPost , "/api/collections" , fiber.Map{ "parent": "projects" } )
		if status != 200 { t.Fatalf( "create: %d %v" , status , reply ) }
		return reply[ "id" ].( string )
	}

	// 1. The last epoch there is: the client makes it from what its state
	// file says it has seen, and the server refuses it.
	last := newFolder()
	state := filepath.Join( t.TempDir() , "state.json" )
	seeded , _ := json.Marshal( map[ string ]map[ string ]map[ string ]uint64{ "token:" + key.ID(): { last: { "lock": 1<<53 - 2 } } } )
	if err = os.WriteFile( state , seeded , 0o600 ); err != nil { t.Fatal( err ) }
	stated , _ := client.NewScoped( base , token , client.WithState( state ) )
	var refused *client.APIError
	if _ , err = stated.Set( ctx , last , "x" , invoice{} , client.AllowShared() ); errors.As( err , &refused ) == false || refused.Message != "bad_lock" {
		t.Fatalf( "a lockbox at the last epoch: %v" , err )
	}

	// 2. A sibling's lockbox, copied as is: well formed, signed for the sibling.
	sibling , err := sharee.CreateCollection( ctx , client.NewCollection{ Parent: "projects" } )
	if err != nil { t.Fatal( err ) }
	if _ , err = sharee.Set( ctx , sibling.ID , "s" , invoice{ Customer: "theirs" } ); err != nil { t.Fatal( err ) }
	copied := newFolder()
	tree , _ := owner.Collections( ctx )
	for _ , entry := range tree {
		if entry.ID == sibling.ID {
			if status , reply := fixture.withKey( t , api , fiber.MethodPost , "/api/collections/" + copied , fiber.Map{ "lock": entry.Lock } ); status != 200 { t.Fatalf( "copy lockbox: %d %v" , status , reply ) }
		}
	}
	// ... and a document under it, sealed with the sibling's keys.
	sibling_key , _ := sharee.CollectionKey( ctx , sibling.ID , false )
	under , _ := sibling_key.Seal( "u" , []byte( `{"x":1}` ) )
	if status , reply := fixture.withKey( t , api , fiber.MethodPost , "/api/collections/" + copied + "/docs/u" , fiber.Map{ "body": base64.StdEncoding.EncodeToString( under ) } ); status != 200 { t.Fatalf( "plant under the copy: %d %v" , status , reply ) }

	// 3. A document whose header names the folder's keys and whose
	// signature is broken: the server checks only the key id.
	projects_key , _ := sharee.CollectionKey( ctx , "projects" , false )
	bad , _ := projects_key.Seal( "bad" , []byte( `{"x":1}` ) )
	bad[ len( bad ) - 1 ] ^= 1
	if status , reply := fixture.withKey( t , api , fiber.MethodPost , "/api/collections/projects/docs/bad" , fiber.Map{ "body": base64.StdEncoding.EncodeToString( bad ) } ); status != 200 { t.Fatalf( "plant: %d %v" , status , reply ) }

	rotation , err := owner.RotateKeys( ctx , "projects" )
	if err != nil { t.Fatalf( "rotation stopped: %v" , err ) }
	if len( rotation.Revoked ) != 1 { t.Fatalf( "revoked %v, want the sharee's key" , rotation.Revoked ) }
	if slices.Equal( rotation.Broken , []string{ copied } ) == false { t.Fatalf( "broken %v, want %s" , rotation.Broken , copied ) }
	want := []string{ copied + "/u" , "projects/bad" }
	slices.Sort( want )
	slices.Sort( rotation.Dropped )
	if slices.Equal( rotation.Dropped , want ) == false { t.Fatalf( "dropped %v" , rotation.Dropped ) }
	// The rest came through: the owner's document and the sharee's real one.
	fresh , _ := client.New( base , api_key , master_text )
	var back invoice
	if _ , err = fresh.Get( ctx , "projects" , "a" , &back ); err != nil || back.Customer != "mine" { t.Fatalf( "owner's document: %+v %v" , back , err ) }
	if _ , err = fresh.Get( ctx , sibling.ID , "s" , &back ); err != nil || back.Customer != "theirs" { t.Fatalf( "sharee's document: %+v %v" , back , err ) }
	if _ , err = fresh.Get( ctx , "projects" , "bad" , &back ); errors.Is( err , client.ErrNotFound ) == false { t.Fatalf( "planted document: %v" , err ) }
	// The copied folder has keys of its own now, under the new ones.
	if _ , err = fresh.Set( ctx , copied , "n" , invoice{ Customer: "new" } , client.AllowShared() ); err != nil { t.Fatalf( "write into the repaired folder: %v" , err ) }
}
