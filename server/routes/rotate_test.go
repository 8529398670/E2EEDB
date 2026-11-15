package routes

import (
	context "context"
	base64 "encoding/base64"
	errors "errors"
	http "net/http"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	client "github.com/8529398670/E2EEDB/client"
	models "github.com/8529398670/E2EEDB/server/models"
)

// Rotating a collection's keys end to end: new keys for the subtree, every
// collection envelope sealed again, access keys into it revoked, and old
// keys useless from then on, while keys for a collection above it, and the
// account's other clients, carry on.

// failCommit fails the first rotate commit it sees, as a dropped connection
// would: the rotation is left half done.
type failCommit struct {
	failed bool
}

func ( fail *failCommit ) RoundTrip( request *http.Request ) ( *http.Response , error ) {
	if fail.failed == false && strings.HasSuffix( request.URL.Path , "/rotate/commit" ) {
		fail.failed = true
		return nil , errors.New( "connection dropped" )
	}
	return http.DefaultTransport.RoundTrip( request )
}

// keyIDOf is the key id a body (an envelope) names.
func keyIDOf( t *testing.T , fixture *authFixture , collection string , id string ) string {
	t.Helper()
	stored , err := fixture.handlers.Docs.Get( fixture.alice.ID , collection , id )
	if err != nil { t.Fatal( err ) }
	return string( stored.Body[ 1:17 ] )
}

func TestRotateKeys( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , err := client.New( base , api_key , master_text )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()

	// top / projects / alpha, and other beside top.
	for _ , folder := range []client.NewCollection{
		{ ID: "top" } , { ID: "projects" , Parent: "top" } , { ID: "alpha" , Parent: "projects" } , { ID: "other" },
	} {
		if _ , err = owner.CreateCollection( ctx , folder ); err != nil { t.Fatalf( "create %s: %v" , folder.ID , err ) }
	}
	for collection , customer := range map[ string ]string{ "top": "Top" , "projects": "Projects" , "alpha": "Alpha" , "other": "Other" } {
		if _ , err = owner.Set( ctx , collection , "a" , invoice{ Customer: customer } ); err != nil { t.Fatal( err ) }
	}

	// Access: read/write on projects, read on top (above it).
	share := func( collection string , write bool ) ( api string , token string ) {
		key , share_err := owner.PrepareShare( ctx , collection , write )
		if share_err != nil { t.Fatal( share_err ) }
		api , _ , share_err = models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , collection , models.KeyScope{ Collection: collection , Write: write , Born: bornOf( t , fixture , collection ) } , time.Hour )
		if share_err != nil { t.Fatal( share_err ) }
		token , _ = client.NewAccessToken( api , key )
		return
	}
	writer_api , writer_token := share( "projects" , true )
	_ , top_token := share( "top" , false )
	writer , _ := client.NewScoped( base , writer_token )
	if _ , err = writer.Set( ctx , "alpha" , "w" , invoice{ Customer: "by writer" } ); err != nil { t.Fatal( err ) }
	// A folder the writer made, inside projects: rotated too, and still not
	// the owner's.
	made , err := writer.CreateCollection( ctx , client.NewCollection{ Name: "theirs" , Parent: "projects" } )
	if err != nil { t.Fatal( err ) }
	if _ , err = writer.Set( ctx , made.ID , "t" , invoice{ Customer: "theirs" } ); err != nil { t.Fatal( err ) }

	// A private envelope written after sharing stays as it is: no collection key opens it.
	private , _ := owner.Key().Seal( "alpha" , "private" , []byte( `{"customer":"mine"}` ) )
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/alpha/docs/private" , fiber.Map{ "body": base64.StdEncoding.EncodeToString( private ) } ); status != 200 {
		t.Fatalf( "private write: %d %v" , status , reply )
	}

	// Another client of the owner's, with every key cached before.
	cached , _ := client.New( base , api_key , master_text )
	var back invoice
	for _ , collection := range []string{ "projects" , "alpha" } {
		if _ , err = cached.Get( ctx , collection , "a" , &back ); err != nil { t.Fatal( err ) }
	}
	old_projects := keyIDOf( t , fixture , "projects" , "a" )
	old_top := keyIDOf( t , fixture , "top" , "a" )

	// An access key cannot rotate.
	if status , _ := fixture.withKey( t , writer_api , fiber.MethodPost , "/api/collections/projects/rotate" , fiber.Map{ "locks": fiber.Map{} } ); status != 403 {
		t.Fatalf( "scoped rotate: %d" , status )
	}

	// Rotate projects, with the commit lost on the way.
	fail := &failCommit{}
	flaky , _ := client.New( base , api_key , master_text , client.WithHTTPClient( &http.Client{ Transport: fail } ) )
	half , err := flaky.RotateKeys( ctx , "projects" )
	if err == nil || fail.failed == false { t.Fatalf( "rotation finished through a dropped commit: %+v" , half ) }
	if len( half.Revoked ) != 1 || strings.HasPrefix( writer_api , half.Revoked[ 0 ] + "." ) == false { t.Fatalf( "revoked %v, want the writer's key" , half.Revoked ) }
	if half.Docs != 4 { t.Fatalf( "sealed %d documents again, want 4" , half.Docs ) }

	// Half way: documents open (new keys and old), writes take the new
	// keys, and the tree holds still.
	fresh , _ := client.New( base , api_key , master_text )
	if _ , err = fresh.Get( ctx , "alpha" , "w" , &back ); err != nil || back.Customer != "by writer" { t.Fatalf( "mid-rotation read: %+v %v" , back , err ) }
	if _ , err = cached.Set( ctx , "alpha" , "mid" , invoice{ Customer: "mid" } ); err != nil { t.Fatalf( "mid-rotation write from a stale cache: %v" , err ) }
	if _ , err = fresh.CreateCollection( ctx , client.NewCollection{ Parent: "alpha" } ); errors.Is( err , client.ErrRotating ) == false { t.Fatalf( "folder made mid-rotation: %v" , err ) }
	if _ , err = fresh.MoveCollection( ctx , "alpha" , "other" , "" ); err == nil { t.Fatal( "folder moved out mid-rotation" ) }
	browser := fixture.signIn( t , fixture.alice.ID )
	if status , _ := send( t , browser , "/api/keys" , fiber.Map{ "name": "x" , "scope": fiber.Map{ "collection": "alpha" , "access": "read" } } ); status != 409 {
		t.Fatalf( "access key made mid-rotation: %d" , status )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/alpha/rotate" , fiber.Map{ "locks": fiber.Map{} } ); status != 409 || reply[ "error" ] != "rotating" {
		t.Fatalf( "rotation inside a rotation: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/alpha/rotate/commit" , fiber.Map{} ); status != 409 || reply[ "error" ] != "rotating" {
		t.Fatalf( "commit from inside: %d %v" , status , reply )
	}

	// Running it again finishes it.
	rotation , err := owner.RotateKeys( ctx , "projects" )
	if err != nil { t.Fatalf( "resume: %v" , err ) }
	if len( rotation.Collections ) != 3 || rotation.Collections[ 0 ] != "projects" || len( rotation.Revoked ) != 0 { t.Fatalf( "rotation: %+v" , rotation ) }
	if keyIDOf( t , fixture , "projects" , "a" ) == old_projects { t.Fatal( "projects is still sealed with its old keys" ) }
	if keyIDOf( t , fixture , "top" , "a" ) != old_top { t.Fatal( "top was rotated too" ) }
	if stored , _ := fixture.handlers.Docs.Get( fixture.alice.ID , "alpha" , "private" ); client.EnvelopeKind( stored.Body ) != client.EnvelopeMaster { t.Fatal( "the private envelope was touched" ) }
	tree , _ := owner.Collections( ctx )
	for _ , entry := range tree {
		if entry.NextLock != "" { t.Fatalf( "%s still has a next lockbox" , entry.ID ) }
	}

	// Every client reads everything: the owner, the stale cache, a reader
	// of top (above the rotation).
	top_reader , _ := client.NewScoped( base , top_token )
	for _ , who := range []*client.Client{ owner , cached , top_reader } {
		for collection , customer := range map[ string ]string{ "projects": "Projects" , "alpha": "Alpha" , made.ID: "theirs" } {
			id := "a"
			if collection == made.ID { id = "t" }
			if _ , err = who.Get( ctx , collection , id , &back ); err != nil || back.Customer != customer { t.Fatalf( "%s after rotation: %+v %v" , collection , back , err ) }
		}
		if _ , err = who.Get( ctx , "alpha" , "mid" , &back ); err != nil || back.Customer != "mid" { t.Fatalf( "mid-rotation doc: %+v %v" , back , err ) }
	}
	if _ , err = cached.Set( ctx , "projects" , "after" , invoice{ Customer: "after" } ); err != nil { t.Fatalf( "write after rotation from a stale cache: %v" , err ) }
	// The writer's folder is still not the owner's.
	if _ , err = owner.Set( ctx , made.ID , "x" , invoice{} ); errors.Is( err , client.ErrSharedCollection ) == false { t.Fatalf( "owner wrote into the sharee's folder: %v" , err ) }

	// The old token: its key is revoked, and its keys neither open what is
	// there now nor seal anything the server takes.
	if _ , err = writer.Get( ctx , "alpha" , "a" , &back ); err == nil { t.Fatal( "the revoked token still reads" ) }
	_ , old_keys , _ := client.ParseAccessToken( writer_token )
	stored , _ := fixture.handlers.Docs.Get( fixture.alice.ID , "projects" , "a" )
	if _ , err = old_keys.Open( "a" , stored.Body ); errors.Is( err , client.ErrWrongKey ) == false { t.Fatalf( "old keys on new ciphertext: %v" , err ) }
	forged , _ := old_keys.Seal( "forged" , []byte( `{"customer":"forged"}` ) )
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/projects/docs/forged" , fiber.Map{ "body": base64.StdEncoding.EncodeToString( forged ) } ); status != 409 || reply[ "error" ] != "stale_key" {
		t.Fatalf( "a write under the old keys: %d %v" , status , reply )
	}

	// Commit with nothing under way, and a start that does not carry the
	// root's lockbox.
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/projects/rotate/commit" , fiber.Map{} ); status != 409 || reply[ "error" ] != "not_rotating" {
		t.Fatalf( "commit with no rotation: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/projects/rotate" , fiber.Map{ "locks": fiber.Map{ "alpha": "{}" } } ); status != 409 || reply[ "error" ] != "not_rotating" {
		t.Fatalf( "start without the root: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/projects/rotate" , fiber.Map{ "locks": fiber.Map{ "other": "{}" } } ); status != 404 {
		t.Fatalf( "a lockbox outside the subtree: %d %v" , status , reply )
	}
}

// Commit refuses while a document is still under the old keys, and a child's
// lockbox may not come before its parent's.
func TestRotateCommitChecks( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , _ := client.New( base , api_key , master_text )
	ctx := context.Background()
	for _ , folder := range []client.NewCollection{ { ID: "root" } , { ID: "child" , Parent: "root" } } {
		if _ , err := owner.CreateCollection( ctx , folder ); err != nil { t.Fatal( err ) }
	}
	if _ , err := owner.Set( ctx , "child" , "a" , invoice{ Customer: "A" } ); err != nil { t.Fatal( err ) }
	// Lockbox text the server cannot read keys from is fine for these
	// checks: it never opens one.
	lock := `{"key_id":"` + base64.StdEncoding.EncodeToString( make( []byte , 16 ) ) + `"}`
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/root/rotate" , fiber.Map{ "locks": fiber.Map{ "child": lock } } ); status != 409 || reply[ "error" ] != "not_rotating" {
		t.Fatalf( "child first: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/root/rotate" , fiber.Map{ "locks": fiber.Map{ "root": lock } } ); status != 200 || reply[ "started" ] != true {
		t.Fatalf( "start: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/root/rotate/commit" , fiber.Map{} ); status != 409 || reply[ "error" ] != "rotate_incomplete" || reply[ "collections" ] != float64( 1 ) {
		t.Fatalf( "commit with a folder left: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/root/rotate" , fiber.Map{ "locks": fiber.Map{ "child": lock } } ); status != 200 || len( reply[ "pending" ].( []any ) ) != 0 {
		t.Fatalf( "child: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/root/rotate" , fiber.Map{ "locks": fiber.Map{ "child": lock } } ); status != 409 || reply[ "error" ] != "lock_exists" {
		t.Fatalf( "child twice: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/root/rotate/commit" , fiber.Map{} ); status != 409 || reply[ "error" ] != "rotate_incomplete" || reply[ "docs" ] != float64( 1 ) {
		t.Fatalf( "commit with a document left: %d %v" , status , reply )
	}
}
