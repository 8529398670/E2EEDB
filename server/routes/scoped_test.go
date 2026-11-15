package routes

import (
	context "context"
	base64 "encoding/base64"
	errors "errors"
	strings "strings"
	testing "testing"
	time "time"

	fiber "github.com/gofiber/fiber/v3"

	client "github.com/8529398670/E2EEDB/client"
	db "github.com/8529398670/E2EEDB/server/db"
	docstore "github.com/8529398670/E2EEDB/server/docstore"
	models "github.com/8529398670/E2EEDB/server/models"
)

// Collection keys end to end: an access token reaches one collection and the
// ones under it, read-only or read and write, and nothing else in the
// account; the master key still reaches everything.

func TestScopedAccessTokens( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , err := client.New( base , api_key , master_text )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()

	// projects / alpha / notes, and private beside projects.
	for _ , folder := range []client.NewCollection{
		{ ID: "projects" } , { ID: "alpha" , Parent: "projects" } , { ID: "notes" , Parent: "alpha" } , { ID: "private" },
	} {
		if _ , err = owner.CreateCollection( ctx , folder ); err != nil { t.Fatalf( "create %s: %v" , folder.ID , err ) }
	}
	// A private envelope: the master key's own, which no access token opens.
	private , _ := owner.Key().Seal( "projects" , "old" , []byte( `{"customer":"private"}` ) )
	if status , reply := fixture.withKey( t , api_key , fiber.MethodPost , "/api/collections/projects/docs/old" , fiber.Map{ "body": base64.StdEncoding.EncodeToString( private ) } ); status != 200 {
		t.Fatalf( "private write: %d %v" , status , reply )
	}
	for collection , customer := range map[ string ]string{ "alpha": "Alpha" , "notes": "Notes" , "private": "Secret" } {
		if _ , err = owner.Set( ctx , collection , "a" , invoice{ Customer: customer } ); err != nil { t.Fatal( err ) }
	}

	// Share projects read-only: the private envelope is sealed again as a
	// collection envelope.
	read_key , err := owner.PrepareShare( ctx , "projects" , false )
	if err != nil || read_key.CanWrite() { t.Fatalf( "prepare: %v" , err ) }
	stored , _ := fixture.handlers.Docs.Get( fixture.alice.ID , "projects" , "old" )
	if client.EnvelopeKind( stored.Body ) != client.EnvelopeCollection { t.Fatal( "the private envelope was not sealed for sharing" ) }

	// The scoped key, made the way the browser makes it.
	browser := fixture.signIn( t , fixture.alice.ID )
	if status , _ := send( t , browser , "/api/keys" , fiber.Map{ "name": "x" , "scope": fiber.Map{ "collection": "nowhere" , "access": "read" } } ); status != 404 {
		t.Fatalf( "scope on a missing collection: %d" , status )
	}
	if status , _ := send( t , browser , "/api/keys" , fiber.Map{ "name": "x" , "role": "admin" , "scope": fiber.Map{ "collection": "projects" , "access": "read" } } ); status != 400 {
		t.Fatalf( "admin scoped key: %d" , status )
	}
	status , reply := send( t , browser , "/api/keys" , fiber.Map{ "name": "reader" , "scope": fiber.Map{ "collection": "projects" , "access": "read" } } )
	if status != 201 { t.Fatalf( "scoped key: %d %v" , status , reply ) }
	if scope , _ := reply[ "scope" ].( map[ string ]any ); scope[ "access" ] != "read" || scope[ "collection" ] != "projects" { t.Fatalf( "scope row: %v" , reply ) }
	reader_api := reply[ "credential" ].( string )
	token , err := client.NewAccessToken( reader_api , read_key )
	if err != nil { t.Fatal( err ) }
	reader , err := client.NewScoped( base , token )
	if err != nil { t.Fatal( err ) }

	// It reads the whole subtree...
	var back invoice
	if _ , err = reader.Get( ctx , "projects" , "old" , &back ); err != nil || back.Customer != "private" { t.Fatalf( "resealed via token: %+v %v" , back , err ) }
	for collection , customer := range map[ string ]string{ "alpha": "Alpha" , "notes": "Notes" } {
		if _ , err = reader.Get( ctx , collection , "a" , &back ); err != nil || back.Customer != customer { t.Fatalf( "%s via token: %+v %v" , collection , back , err ) }
	}
	// ...and nothing beside it.
	if _ , err = reader.Get( ctx , "private" , "a" , &back ); err == nil { t.Fatal( "read outside the scope" ) }
	if status , _ := fixture.withKey( t , reader_api , fiber.MethodGet , "/api/collections/private/docs/a" , nil ); status != 404 { t.Fatalf( "raw read outside: %d" , status ) }
	collections , err := reader.Collections( ctx )
	if err != nil || len( collections ) != 3 { t.Fatalf( "scoped collections: %+v %v" , collections , err ) }
	for _ , entry := range collections {
		if entry.ID == "projects" && entry.Parent != "" { t.Fatalf( "root shown under %q" , entry.Parent ) }
	}
	changes , err := reader.Changes( ctx , 0 , 100 )
	if err != nil { t.Fatal( err ) }
	for _ , change := range changes.Changes {
		if change.Collection == "private" { t.Fatal( "the feed shows the private collection" ) }
	}
	// Read-only: refused by the client (no write key) and by the server.
	if _ , err = reader.Set( ctx , "alpha" , "b" , invoice{} ); errors.Is( err , client.ErrReadOnly ) == false { t.Fatalf( "reader wrote: %v" , err ) }
	stolen , _ := fixture.handlers.Docs.Get( fixture.alice.ID , "alpha" , "a" )
	if status , _ := fixture.withKey( t , reader_api , fiber.MethodPost , "/api/collections/alpha/docs/b" , fiber.Map{ "body": base64.StdEncoding.EncodeToString( stolen.Body ) } ); status != 403 {
		t.Fatalf( "server let a read-only key write: %d" , status )
	}
	if status , _ := fixture.withKey( t , reader_api , fiber.MethodPost , "/api/collections/alpha/docs/a/delete" , fiber.Map{} ); status != 403 {
		t.Fatalf( "server let a read-only key delete: %d" , status )
	}
	// And the rest of the API is closed to it.
	for _ , path := range []string{ "/api/me" , "/api/keyring" , "/api/account/sessions" , "/api/keys" } {
		if status , _ := fixture.withKey( t , reader_api , fiber.MethodGet , path , nil ); status != 403 { t.Fatalf( "%s: %d" , path , status ) }
	}
	if status , _ := fixture.withKey( t , reader_api , fiber.MethodPost , "/api/account/login-link" , fiber.Map{} ); status != 403 { t.Fatalf( "login link: %d" , status ) }

	// A read/write token for the same collection.
	write_key , err := owner.PrepareShare( ctx , "projects" , true )
	if err != nil { t.Fatal( err ) }
	writer_api , _ , err := models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "writer" , models.KeyScope{ Collection: "projects" , Write: true , Born: bornOf( t , fixture , "projects" ) } , time.Hour )
	if err != nil { t.Fatal( err ) }
	writer_token , _ := client.NewAccessToken( writer_api , write_key )
	writer , err := client.NewScoped( base , writer_token )
	if err != nil { t.Fatal( err ) }
	if _ , err = writer.Set( ctx , "notes" , "w" , invoice{ Customer: "from writer" } ); err != nil { t.Fatal( err ) }
	// A folder a scoped key makes has a random id, and says who made it.
	if status , reply := fixture.withKey( t , writer_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "id": "beta" , "parent": "alpha" } ); status != 400 {
		t.Fatalf( "scoped key chose the id beta: %d %v" , status , reply )
	}
	made , err := writer.CreateCollection( ctx , client.NewCollection{ Name: "beta" , Parent: "alpha" } )
	if err != nil { t.Fatalf( "writer folder: %+v %v" , made , err ) }
	writer_id , _ , _ := strings.Cut( writer_api , "." )
	if made.ByKey != writer_id { t.Fatalf( "by_key %q, want %q" , made.ByKey , writer_id ) }
	beta := made.ID
	if _ , err = writer.Set( ctx , beta , "b" , invoice{ Customer: "in beta" } ); err != nil { t.Fatal( err ) }
	if _ , err = writer.MoveCollection( ctx , beta , "projects" , "" ); err != nil { t.Fatalf( "writer move inside: %v" , err ) }
	if _ , err = writer.MoveDoc( ctx , "notes" , "w" , beta ); err != nil { t.Fatalf( "writer move doc: %v" , err ) }
	if _ , err = writer.CreateCollection( ctx , client.NewCollection{ ID: "top" } ); err == nil { t.Fatal( "writer made a top-level folder" ) }
	if _ , err = writer.MoveCollection( ctx , "projects" , "private" , "" ); err == nil { t.Fatal( "writer moved its own root" ) }
	if _ , err = writer.DeleteCollection( ctx , "projects" ); err == nil { t.Fatal( "writer deleted its own root" ) }
	// Renaming its own root would test names against the owner's other
	// top-level folders: "private" is taken, and that must not show.
	if status , reply := fixture.withKey( t , writer_api , fiber.MethodPost , "/api/collections/projects" , fiber.Map{ "name": "private" } ); status != 403 {
		t.Fatalf( "writer renamed its own root: %d %v" , status , reply )
	}
	if _ , err = writer.RenameCollection( ctx , beta , "beta two" ); err != nil { t.Fatalf( "writer rename inside: %v" , err ) }
	if _ , err = writer.MoveDoc( ctx , "alpha" , "a" , "private" ); err == nil { t.Fatal( "writer moved a doc out" ) }

	// The owner, from scratch, reads what the writer wrote; a fresh reader
	// reads it too, through the re-wrapped lockbox.
	fresh_owner , _ := client.New( base , api_key , master_text )
	fresh_reader , _ := client.NewScoped( base , token )
	for _ , who := range []*client.Client{ fresh_owner , fresh_reader } {
		if _ , err = who.Get( ctx , beta , "w" , &back ); err != nil || back.Customer != "from writer" { t.Fatalf( "read writer's doc: %+v %v" , back , err ) }
	}

	// The owner moves alpha out of projects: the token no longer reaches it.
	if _ , err = fresh_owner.MoveCollection( ctx , "alpha" , "private" , "" ); err != nil { t.Fatalf( "owner move out: %v" , err ) }
	later_reader , _ := client.NewScoped( base , token )
	if _ , err = later_reader.Get( ctx , "alpha" , "a" , &back ); err == nil { t.Fatal( "token still reaches a folder moved out" ) }
	if _ , err = fresh_owner.Get( ctx , "notes" , "a" , &back ); err != nil || back.Customer != "Notes" { t.Fatalf( "owner after move: %v" , err ) }

	// Revoking the key ends it at once.
	reader_id , _ , _ := strings.Cut( reader_api , "." )
	if err = models.RevokeAPIKey( fixture.store , reader_id ); err != nil { t.Fatal( err ) }
	if _ , err = later_reader.Get( ctx , "projects" , "old" , &back ); err == nil { t.Fatal( "a revoked token still reads" ) }
}

// A read/write access token cannot take a collection id the account's own
// code writes to by name: its folders get random ids, and a master-key client
// refuses to write into a folder one made unless told to.
func TestScopedKeysCannotSquatIDs( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , err := client.New( base , api_key , master_text )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()
	if _ , err = owner.CreateCollection( ctx , client.NewCollection{ ID: "shared" } ); err != nil { t.Fatal( err ) }
	write_key , err := owner.PrepareShare( ctx , "shared" , true )
	if err != nil { t.Fatal( err ) }
	scoped_api , _ , err := models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "sharee" , models.KeyScope{ Collection: "shared" , Write: true , Born: bornOf( t , fixture , "shared" ) } , time.Hour )
	if err != nil { t.Fatal( err ) }
	token , _ := client.NewAccessToken( scoped_api , write_key )
	sharee , err := client.NewScoped( base , token )
	if err != nil { t.Fatal( err ) }

	// The id the owner's service will use is refused, even one shaped
	// like a random id...
	for _ , id := range []string{ "invoices" , "customer_invoices_2025" , client.NewID() } {
		if _ , err = sharee.CreateCollection( ctx , client.NewCollection{ ID: id , Parent: "shared" } ); err == nil { t.Fatalf( "a scoped key made a folder named %s" , id ) }
	}
	// ...so the service's first write makes its own folder, out of reach.
	if _ , err = owner.Set( ctx , "invoices" , "inv1" , invoice{ Customer: "TOP SECRET" } ); err != nil { t.Fatalf( "owner set: %v" , err ) }
	var stolen invoice
	if _ , err = sharee.Get( ctx , "invoices" , "inv1" , &stolen ); err == nil { t.Fatalf( "the sharee read the owner's document: %+v" , stolen ) }

	// A folder the sharee made, even under a random id the owner's code
	// somehow used, is refused to a master-key write unless asked for.
	made , err := sharee.CreateCollection( ctx , client.NewCollection{ Parent: "shared" } )
	if err != nil { t.Fatalf( "sharee folder: %v" , err ) }
	guessed := made.ID
	if made.Lock == "" { t.Fatal( "the sharee's folder has no lockbox" ) }
	fresh_owner , _ := client.New( base , api_key , master_text )
	if _ , err = fresh_owner.Set( ctx , guessed , "x" , invoice{ Customer: "private" } ); errors.Is( err , client.ErrSharedCollection ) == false {
		t.Fatalf( "owner wrote into a sharee's folder: %v" , err )
	}
	if _ , err = fresh_owner.Set( ctx , guessed , "x" , invoice{ Customer: "meant for them" } , client.AllowShared() ); err != nil {
		t.Fatalf( "AllowShared write: %v" , err )
	}
	var back invoice
	if _ , err = sharee.Get( ctx , guessed , "x" , &back ); err != nil || back.Customer != "meant for them" { t.Fatalf( "sharee read: %+v %v" , back , err ) }
}

// Deleting a shared folder revokes its access keys, and a key never reaches a
// later folder that reuses the id -- including a key from before keys
// recorded which folder they were for, once it is backfilled.
func TestScopedKeysDieWithTheirFolder( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , err := client.New( base , api_key , master_text )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()
	if _ , err = owner.CreateCollection( ctx , client.NewCollection{ ID: "shared" } ); err != nil { t.Fatal( err ) }
	if _ , err = owner.PrepareShare( ctx , "shared" , true ); err != nil { t.Fatal( err ) }
	browser := fixture.signIn( t , fixture.alice.ID )
	status , reply := send( t , browser , "/api/keys" , fiber.Map{ "name": "w" , "scope": fiber.Map{ "collection": "shared" , "access": "write" } } )
	if status != 201 { t.Fatalf( "scoped key: %d %v" , status , reply ) }
	scoped_api := reply[ "credential" ].( string )
	scoped_id , _ , _ := strings.Cut( scoped_api , "." )
	// A key without its folder's born value is never minted.
	if _ , _ , err = models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "no born" , models.KeyScope{ Collection: "shared" , Write: true } , time.Hour ); errors.Is( err , models.ErrScopeBorn ) == false {
		t.Fatalf( "scoped key without born: %v" , err )
	}

	if _ , err = owner.DeleteCollection( ctx , "shared" ); err != nil { t.Fatalf( "delete: %v" , err ) }
	stored , err := models.GetAPIKey( fixture.store , scoped_id )
	if err != nil || stored.Revoked() == false { t.Fatalf( "the deleted folder's key is not revoked: %+v %v" , stored , err ) }

	// The same id, made again: neither key reaches it, even if one were
	// somehow live again.
	if _ , err = owner.Set( ctx , "shared" , "fresh" , invoice{ Customer: "new" } ); err != nil { t.Fatalf( "recreate: %v" , err ) }
	if status , _ := fixture.withKey( t , scoped_api , fiber.MethodGet , "/api/collections/shared/docs" , nil ); status == 200 { t.Fatal( "an old key lists the new folder" ) }
	// Born alone also keeps an unrevoked key out: a key for the old folder,
	// with its revocation undone, still gets 404.
	if err = fixture.store.Write( func( tx *db.Tx ) ( tx_err error ) {
		key := &models.APIKey{}
		if tx_err = tx.Get( db.BucketAPIKeys , []byte( scoped_id ) , key ); tx_err != nil { return }
		key.RevokedAt = nil
		tx_err = tx.Put( db.BucketAPIKeys , []byte( scoped_id ) , key )
		return
	} ); err != nil { t.Fatal( err ) }
	for _ , path := range []string{ "/api/collections/shared/docs" , "/api/collections" , "/api/changes" } {
		if status , reply := fixture.withKey( t , scoped_api , fiber.MethodGet , path , nil ); status != 404 { t.Fatalf( "%s with the old folder's key: %d %v" , path , status , reply ) }
	}
	if status , _ := fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections/shared/docs/fresh/delete" , fiber.Map{} ); status != 404 { t.Fatalf( "old key deleted in the new folder: %d" , status ) }
}

// bornOf is collection's born value, which a scoped key is minted with.
func bornOf( t *testing.T , fixture *authFixture , collection string ) int64 {
	t.Helper()
	entry , err := fixture.handlers.Docs.GetCollection( fixture.alice.ID , collection )
	if err != nil { t.Fatal( err ) }
	return entry.Born
}

// An access key sees its share, not the account: no account-wide tree_seq,
// its root at position 0, the share's limits, and the share's errors even
// when the account's own limits are what refused it.
func TestScopedKeysSeeOnlyTheirShare( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , err := client.New( base , api_key , master_text )
	if err != nil { t.Fatal( err ) }
	ctx := context.Background()
	for _ , id := range []string{ "first" , "second" , "shared" } {
		if _ , err = owner.CreateCollection( ctx , client.NewCollection{ ID: id } ); err != nil { t.Fatal( err ) }
	}
	write_key , err := owner.PrepareShare( ctx , "shared" , true )
	if err != nil { t.Fatal( err ) }
	scoped_api , _ , err := models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "sharee" , models.KeyScope{ Collection: "shared" , Write: true , Born: bornOf( t , fixture , "shared" ) } , time.Hour )
	if err != nil { t.Fatal( err ) }
	token , _ := client.NewAccessToken( scoped_api , write_key )
	sharee , err := client.NewScoped( base , token )
	if err != nil { t.Fatal( err ) }

	fixture.cfg.Docs = fixture.cfg.Docs.Limits()
	fixture.cfg.Docs.ShareMaxCollections = 2
	fixture.cfg.Docs.ShareQuotaBytes = 1000

	status , reply := fixture.withKey( t , api_key , fiber.MethodGet , "/api/collections" , nil )
	if _ , found := reply[ "tree_seq" ]; status != 200 || found == false { t.Fatalf( "owner list: %d %v" , status , reply ) }
	status , reply = fixture.withKey( t , scoped_api , fiber.MethodGet , "/api/collections" , nil )
	if status != 200 { t.Fatalf( "scoped list: %d %v" , status , reply ) }
	if _ , found := reply[ "tree_seq" ]; found { t.Fatalf( "an access key got the account's tree_seq: %v" , reply ) }
	if reply[ "max_collections" ] != float64( 2 ) || reply[ "quota_bytes" ] != float64( 1000 ) { t.Fatalf( "scoped limits: %v" , reply ) }
	rows , _ := reply[ "collections" ].( []any )
	if len( rows ) != 1 || rows[ 0 ].( map[ string ]any )[ "position" ] != float64( 0 ) { t.Fatalf( "scoped root row: %v" , rows ) }

	// Two folders in the share, then no more through the key...
	if _ , err = sharee.CreateCollection( ctx , client.NewCollection{ Name: "one" , Parent: "shared" } ); err != nil { t.Fatal( err ) }
	_ , err = sharee.CreateCollection( ctx , client.NewCollection{ Name: "two" , Parent: "shared" } )
	var refused *client.APIError
	if errors.As( err , &refused ) == false || refused.Message != "share_too_many_collections" { t.Fatalf( "past the share's folders: %v" , err ) }
	// ...while the owner may still add to it.
	if _ , err = owner.CreateCollection( ctx , client.NewCollection{ ID: "owners" , Parent: "shared" } ); err != nil { t.Fatalf( "owner folder in the share: %v" , err ) }
	// Bytes: a big document is refused with the share's error.
	big := strings.Repeat( "x" , 1200 )
	if _ , err = sharee.Set( ctx , "shared" , "big" , map[ string ]string{ "x": big } ); errors.As( err , &refused ) == false || refused.Message != "share_quota_exceeded" {
		t.Fatalf( "past the share's bytes: %v" , err )
	}
	// The account full: the key hears the share's error, not the account's.
	fixture.cfg.Docs.ShareMaxCollections = 0
	fixture.cfg.Docs.MaxCollections = 5
	status , reply = fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "name": "three" , "parent": "shared" } )
	if status != 413 || reply[ "error" ] != "share_too_many_collections" || reply[ "max_collections" ] != float64( 0 ) { t.Fatalf( "account full, scoped: %d %v" , status , reply ) }
}

// A scoped key's new folder gets its id from the server. The one id it may
// send is that of a folder deleted from inside its own, to undo the delete.
func TestScopedCreateIDs( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , _ := client.New( base , api_key , master_text )
	ctx := context.Background()
	for _ , folder := range []client.NewCollection{ { ID: "shared" } , { ID: "elsewhere" } , { ID: "mine" , Parent: "elsewhere" } } {
		if _ , err := owner.CreateCollection( ctx , folder ); err != nil { t.Fatal( err ) }
	}
	write_key , _ := owner.PrepareShare( ctx , "shared" , true )
	scoped_api , _ , err := models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "sharee" , models.KeyScope{ Collection: "shared" , Write: true , Born: bornOf( t , fixture , "shared" ) } , time.Hour )
	if err != nil { t.Fatal( err ) }
	token , _ := client.NewAccessToken( scoped_api , write_key )
	sharee , _ := client.NewScoped( base , token )

	if status , reply := fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "id": "customer_invoices_2025" , "parent": "shared" } ); status != 400 || reply[ "error" ] != "id_not_reusable" {
		t.Fatalf( "chosen id: %d %v" , status , reply )
	}
	if status , reply := fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "parent": "shared" , "lock": shapedLock( "shared" ) } ); status != 400 {
		t.Fatalf( "lockbox with no id: %d %v" , status , reply )
	}
	status , reply := fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "parent": "shared" , "name": "plain" } )
	if status != 200 || reply[ "id" ] == "customer_invoices_2025" || len( reply[ "id" ].( string ) ) != 16 { t.Fatalf( "server id: %d %v" , status , reply ) }

	// Made, deleted and made again under its id, keys and all.
	made , err := sharee.CreateCollection( ctx , client.NewCollection{ Name: "sub" , Parent: "shared" } )
	if err != nil { t.Fatal( err ) }
	if _ , err = sharee.Set( ctx , made.ID , "a" , invoice{ Customer: "A" } ); err != nil { t.Fatal( err ) }
	if _ , err = sharee.DeleteCollection( ctx , made.ID ); err != nil { t.Fatal( err ) }
	if status , reply := fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "id": made.ID , "parent": "shared" , "name": "sub" , "lock": made.Lock } ); status != 200 {
		t.Fatalf( "undo: %d %v" , status , reply )
	}
	// The owner's folder deleted outside the share stays out of reach.
	if _ , err = owner.DeleteCollection( ctx , "mine" ); err != nil { t.Fatal( err ) }
	if status , reply := fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "id": "mine" , "parent": "shared" } ); status != 400 || reply[ "error" ] != "id_not_reusable" {
		t.Fatalf( "an id deleted elsewhere: %d %v" , status , reply )
	}
}

// An access key's max_depth counts from its own folder, in the list and in
// too_deep, so neither says how deep that folder sits.
func TestScopedMaxDepthIsRelative( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master_text , _ := client.GenerateKey()
	owner , _ := client.New( base , api_key , master_text )
	ctx := context.Background()
	for _ , folder := range []client.NewCollection{ { ID: "top" } , { ID: "mid" , Parent: "top" } , { ID: "shared" , Parent: "mid" } } {
		if _ , err := owner.CreateCollection( ctx , folder ); err != nil { t.Fatal( err ) }
	}
	scoped_api , _ , err := models.IssueScopedAPIKey( fixture.store , fixture.alice.ID , "sharee" , models.KeyScope{ Collection: "shared" , Write: true , Born: bornOf( t , fixture , "shared" ) } , time.Hour )
	if err != nil { t.Fatal( err ) }
	account := fixture.handlers.docLimits().MaxDepth
	if account == 0 { account = docstore.DefaultMaxDepth }
	status , reply := fixture.withKey( t , scoped_api , fiber.MethodGet , "/api/collections" , nil )
	if status != 200 || reply[ "max_depth" ] != float64( account - 2 ) { t.Fatalf( "list: %d %v, want max_depth %d" , status , reply[ "max_depth" ] , account - 2 ) }
	// Fill the share to its depth, then one more.
	parent := "shared"
	for depth := 2 ; depth <= account - 2 ; depth++ {
		status , reply = fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "parent": parent } )
		if status != 200 { t.Fatalf( "depth %d: %d %v" , depth , status , reply ) }
		parent = reply[ "id" ].( string )
	}
	status , reply = fixture.withKey( t , scoped_api , fiber.MethodPost , "/api/collections" , fiber.Map{ "parent": parent } )
	if status != 400 || reply[ "error" ] != "too_deep" || reply[ "max_depth" ] != float64( account - 2 ) { t.Fatalf( "too deep: %d %v" , status , reply ) }
}
