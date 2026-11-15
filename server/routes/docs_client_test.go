package routes

import (
	context "context"
	json "encoding/json"
	errors "errors"
	net "net"
	testing "testing"

	fiber "github.com/gofiber/fiber/v3"

	client "github.com/8529398670/E2EEDB/client"
	models "github.com/8529398670/E2EEDB/server/models"
)

// The Go client against the real routes over real HTTP: what a service using
// the client gets, end to end, and proof that what reaches the server is
// ciphertext.

func serve( t *testing.T , fixture *authFixture ) ( base string ) {
	t.Helper()
	listener , err := net.Listen( "tcp" , "127.0.0.1:0" )
	if err != nil { t.Fatal( err ) }
	go fixture.app.Listener( listener , fiber.ListenConfig{ DisableStartupMessage: true } )
	t.Cleanup( func() { fixture.app.Shutdown() } )
	base = "http://" + listener.Addr().String()
	return
}

type invoice struct {
	Customer string  `json:"customer"`
	Total    float64 `json:"total"`
}

func TestGoClientEndToEnd( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master , _ := client.GenerateKey()
	store , err := client.New( base , api_key , master )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()

	id := client.NewID()
	meta , err := store.Set( ctx , "invoices" , id , invoice{ Customer: "ACME secret customer" , Total: 12.5 } , client.MustNotExist() )
	if err != nil || meta.Version != meta.Seq { t.Fatalf( "set: %+v %v" , meta , err ) }

	// What the server holds is not the plaintext.
	stored , err := fixture.handlers.Docs.Get( fixture.alice.ID , "invoices" , id )
	if err != nil { t.Fatal( err ) }
	if string( stored.Body ) == "" || containsText( stored.Body , "ACME" ) { t.Fatal( "the server holds plaintext" ) }

	var back invoice
	if meta , err = store.Get( ctx , "invoices" , id , &back ); err != nil || back.Customer != "ACME secret customer" { t.Fatalf( "get: %+v %v" , back , err ) }

	// A stale write is a ConflictError carrying the current version.
	_ , err = store.Set( ctx , "invoices" , id , invoice{ Total: 1 } , client.MustNotExist() )
	var conflict *client.ConflictError
	if errors.As( err , &conflict ) == false || conflict.Current != meta.Version { t.Fatalf( "conflict: %v" , err ) }
	if _ , err = store.Set( ctx , "invoices" , id , invoice{ Customer: "B" , Total: 2 } , client.IfVersion( meta.Version ) ); err != nil { t.Fatal( err ) }

	seen := 0
	err = store.Each( ctx , "invoices" , func( meta client.Meta , data json.RawMessage ) error {
		seen++
		return nil
	} )
	if err != nil || seen != 1 { t.Fatalf( "each: %d %v" , seen , err ) }
	collections , err := store.Collections( ctx )
	if err != nil || len( collections ) != 1 || collections[ 0 ].Name != "invoices" { t.Fatalf( "collections: %+v %v" , collections , err ) }

	if _ , err = store.Delete( ctx , "invoices" , id ); err != nil { t.Fatal( err ) }
	if _ , err = store.Get( ctx , "invoices" , id , &back ); errors.Is( err , client.ErrNotFound ) == false { t.Fatalf( "get deleted: %v" , err ) }
	changes , err := store.Changes( ctx , 0 , 100 )
	if err != nil || len( changes.Changes ) != 1 || changes.Changes[ 0 ].Deleted == false { t.Fatalf( "changes: %+v %v" , changes , err ) }

	// Another master key on the same account cannot read it, and says why.
	store.Set( ctx , "invoices" , "x" , invoice{ Total: 3 } )
	other_key , _ := client.GenerateKey()
	other , _ := client.New( base , api_key , other_key )
	if _ , err = other.Get( ctx , "invoices" , "x" , &back ); errors.Is( err , client.ErrWrongKey ) == false { t.Fatalf( "other key: %v" , err ) }
}

func containsText( body []byte , text string ) bool {
	for index := 0 ; index + len( text ) <= len( body ) ; index++ {
		if string( body[ index : index + len( text ) ] ) == text { return true }
	}
	return false
}

// Folders through the Go client: a service writing by id keeps working when
// its folder is renamed and moved, moving a document re-seals it for its new
// place, and deleting a folder takes its subfolders and documents with it.
func TestGoClientFolders( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master , _ := client.GenerateKey()
	store , err := client.New( base , api_key , master )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()

	if _ , err = store.Set( ctx , "invoices" , "a" , invoice{ Customer: "A" , Total: 1 } ); err != nil { t.Fatal( err ) }
	work , err := store.CreateCollection( ctx , client.NewCollection{ Name: "Work" } )
	if err != nil || work.ID == "" || work.Name != "Work" { t.Fatalf( "create: %+v %v" , work , err ) }
	if _ , err = store.CreateCollection( ctx , client.NewCollection{ Name: "work" } ); err == nil { t.Fatal( "a sibling's name was accepted twice" ) }
	if _ , err = store.RenameCollection( ctx , "invoices" , "Invoices 2026" ); err != nil { t.Fatal( err ) }
	if _ , err = store.MoveCollection( ctx , "invoices" , work.ID , "" ); err != nil { t.Fatal( err ) }
	if _ , err = store.MoveCollection( ctx , work.ID , "invoices" , "" ); err == nil { t.Fatal( "a folder went inside its own child" ) }

	// Renamed and moved, it still answers to its id.
	var back invoice
	if _ , err = store.Get( ctx , "invoices" , "a" , &back ); err != nil || back.Customer != "A" { t.Fatalf( "get after rename: %+v %v" , back , err ) }
	if _ , err = store.Set( ctx , "invoices" , "b" , invoice{ Customer: "B" } ); err != nil { t.Fatal( err ) }
	collections , err := store.Collections( ctx )
	if err != nil || len( collections ) != 2 { t.Fatalf( "collections: %+v %v" , collections , err ) }
	for _ , entry := range collections {
		if entry.ID == "invoices" && ( entry.Name != "Invoices 2026" || entry.Parent != work.ID || entry.Count != 2 ) {
			t.Fatalf( "invoices folder: %+v" , entry )
		}
	}

	// Move a document: it opens in its new place, and is gone from the old.
	moved , err := store.MoveDoc( ctx , "invoices" , "a" , work.ID )
	if err != nil || moved.Collection != work.ID { t.Fatalf( "move: %+v %v" , moved , err ) }
	if _ , err = store.Get( ctx , work.ID , "a" , &back ); err != nil || back.Customer != "A" { t.Fatalf( "moved get: %+v %v" , back , err ) }
	if _ , err = store.Get( ctx , "invoices" , "a" , &back ); errors.Is( err , client.ErrNotFound ) == false { t.Fatalf( "old place: %v" , err ) }

	// Deleting Work takes invoices and both documents.
	removed , err := store.DeleteCollection( ctx , work.ID )
	if err != nil || len( removed ) != 2 || removed[ 0 ] != work.ID { t.Fatalf( "delete: %v %v" , removed , err ) }
	if _ , err = store.Get( ctx , "invoices" , "b" , &back ); errors.Is( err , client.ErrNotFound ) == false { t.Fatalf( "doc survived: %v" , err ) }
	if collections , _ = store.Collections( ctx ); len( collections ) != 0 { t.Fatalf( "folders left: %+v" , collections ) }
}

func TestBigFolderDeletesInPages( t *testing.T ) {
	fixture := newAuthFixture( t )
	fixture.cfg.Docs.MaxDeleteDocs = 3
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master , _ := client.GenerateKey()
	store , err := client.New( base , api_key , master )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()
	work , err := store.CreateCollection( ctx , client.NewCollection{ Name: "Work" } )
	if err != nil { t.Fatal( err ) }
	for index := 0 ; index < 8 ; index++ {
		if _ , err = store.Set( ctx , work.ID , client.NewID() , invoice{ Total: float64( index ) } ); err != nil { t.Fatal( err ) }
	}

	// All at once is refused, and nothing goes.
	status , reply := fixture.withKey( t , api_key , "POST" , "/api/collections/" + work.ID + "/delete" , fiber.Map{} )
	if status != fiber.StatusRequestEntityTooLarge || reply[ "error" ] != "delete_too_large" || reply[ "docs" ] != float64( 8 ) || reply[ "max_docs" ] != float64( 3 ) {
		t.Fatalf( "too large: %d %v" , status , reply )
	}
	// One partial call deletes a page and leaves the folder.
	status , reply = fixture.withKey( t , api_key , "POST" , "/api/collections/" + work.ID + "/delete" , fiber.Map{ "partial": true } )
	if status != fiber.StatusOK || reply[ "done" ] != false || reply[ "docs" ] != float64( 3 ) { t.Fatalf( "partial: %d %v" , status , reply ) }
	if _ , err = fixture.handlers.Docs.GetCollection( fixture.alice.ID , work.ID ); err != nil { t.Fatalf( "folder went with a partial delete: %v" , err ) }

	// The client pages through the rest.
	removed , err := store.DeleteCollection( ctx , work.ID )
	if err != nil || len( removed ) != 1 || removed[ 0 ] != work.ID { t.Fatalf( "delete: %v %v" , removed , err ) }
	usage , _ := fixture.handlers.Docs.Usage( fixture.alice.ID )
	if usage.Docs != 0 || usage.Tombstones != 8 { t.Fatalf( "usage after: %+v" , usage ) }
}
