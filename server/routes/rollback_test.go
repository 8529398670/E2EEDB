package routes

import (
	bytes "bytes"
	context "context"
	json "encoding/json"
	errors "errors"
	io "io"
	http "net/http"
	httptest "net/http/httptest"
	os "os"
	filepath "path/filepath"
	sync "sync"
	testing "testing"

	client "github.com/8529398670/E2EEDB/client"
	models "github.com/8529398670/E2EEDB/server/models"
)

// A dishonest server undoing a key rotation: after the owner rotates a
// collection (say, after revoking someone), it serves the old lockbox again,
// whose keys the revoked holder kept. Every client that has seen the
// rotation refuses it (client.ErrRolledBack): the one that rotated, even
// after it dropped its cached keys; a new one reading the same state file;
// and one that only saw the rotation under way.

// lockProxy passes requests through to the real server, but while a swap
// is set, GET /api/collections answers with the lockboxes it names.
type lockProxy struct {
	base  string
	mutex sync.Mutex
	swaps map[ string ][ 2 ]string // id -> lock , next_lock
}

func newLockProxy( t *testing.T , base string ) ( proxy *lockProxy , url string ) {
	proxy = &lockProxy{ base: base , swaps: map[ string ][ 2 ]string{} }
	server := httptest.NewServer( proxy )
	t.Cleanup( server.Close )
	url = server.URL
	return
}

func ( proxy *lockProxy ) swap( id string , lock string , next string ) {
	proxy.mutex.Lock()
	defer proxy.mutex.Unlock()
	proxy.swaps[ id ] = [ 2 ]string{ lock , next }
}

func ( proxy *lockProxy ) honest() {
	proxy.mutex.Lock()
	defer proxy.mutex.Unlock()
	proxy.swaps = map[ string ][ 2 ]string{}
}

func ( proxy *lockProxy ) ServeHTTP( w http.ResponseWriter , r *http.Request ) {
	body , _ := io.ReadAll( r.Body )
	request , _ := http.NewRequest( r.Method , proxy.base + r.URL.RequestURI() , bytes.NewReader( body ) )
	request.Header = r.Header.Clone()
	response , err := http.DefaultClient.Do( request )
	if err != nil {
		http.Error( w , err.Error() , http.StatusBadGateway )
		return
	}
	defer response.Body.Close()
	reply , _ := io.ReadAll( response.Body )
	proxy.mutex.Lock()
	swaps := proxy.swaps
	proxy.mutex.Unlock()
	if r.Method == http.MethodGet && r.URL.Path == "/api/collections" && len( swaps ) > 0 {
		var page map[ string ]any
		if json.Unmarshal( reply , &page ) == nil {
			rows , _ := page[ "collections" ].( []any )
			for _ , row := range rows {
				entry := row.( map[ string ]any )
				id , _ := entry[ "id" ].( string )
				if swap , found := swaps[ id ]; found {
					entry[ "lock" ] = swap[ 0 ]
					delete( entry , "next_lock" )
					if swap[ 1 ] != "" { entry[ "next_lock" ] = swap[ 1 ] }
				}
			}
			reply , _ = json.Marshal( page )
		}
	}
	w.Header().Set( "Content-Type" , response.Header.Get( "Content-Type" ) )
	w.WriteHeader( response.StatusCode )
	w.Write( reply )
}

func lockOf( t *testing.T , store *client.Client , id string ) ( lock string ) {
	t.Helper()
	collections , err := store.Collections( context.Background() )
	if err != nil { t.Fatal( err ) }
	for _ , entry := range collections {
		if entry.ID == id { return entry.Lock }
	}
	t.Fatalf( "no collection %s" , id )
	return
}

func TestRotationRollbackRefused( t *testing.T ) {
	fixture := newAuthFixture( t )
	base := serve( t , fixture )
	api_key := issueKey( t , fixture , fixture.alice , models.RoleUser )
	master , _ := client.GenerateKey()
	proxy , url := newLockProxy( t , base )
	dir := t.TempDir()
	state := filepath.Join( dir , "state.json" )
	ctx := context.Background()

	owner , err := client.New( url , api_key , master , client.WithState( state ) )
	if err != nil { t.Fatal( err ) }
	if _ , err = owner.CreateCollection( ctx , client.NewCollection{ ID: "notes" } ); err != nil { t.Fatal( err ) }
	if _ , err = owner.Set( ctx , "notes" , "a" , invoice{ Customer: "before" } ); err != nil { t.Fatal( err ) }
	old_lock := lockOf( t , owner , "notes" )
	// Another device, with its own memory, that has seen the old keys.
	watcher_state := filepath.Join( dir , "watcher.json" )
	watcher , _ := client.New( url , api_key , master , client.WithState( watcher_state ) )
	if _ , err = watcher.CollectionKey( ctx , "notes" , false ); err != nil { t.Fatal( err ) }

	if _ , err = owner.RotateKeys( ctx , "notes" ); err != nil { t.Fatal( err ) }
	new_lock := lockOf( t , owner , "notes" )
	if new_lock == old_lock { t.Fatal( "the rotation did not change the lockbox" ) }

	// The watcher, started again, writes while the rotation looks under
	// way (old lock, new next_lock): it seals with the new keys, and so has
	// seen them.
	proxy.swap( "notes" , old_lock , new_lock )
	watcher , _ = client.New( url , api_key , master , client.WithState( watcher_state ) )
	if _ , err = watcher.Set( ctx , "notes" , "w" , invoice{ Customer: "mid" } ); err != nil { t.Fatalf( "mid-rotation write: %v" , err ) }

	// Now the server serves the old lockbox alone.
	proxy.swap( "notes" , old_lock , "" )
	if _ , err = owner.CollectionKey( ctx , "notes" , false ); errors.Is( err , client.ErrRolledBack ) == false {
		t.Fatalf( "the rotating client took the old lockbox: %v" , err )
	}
	again , err := client.New( url , api_key , master , client.WithState( state ) )
	if err != nil { t.Fatal( err ) }
	if _ , err = again.CollectionKey( ctx , "notes" , false ); errors.Is( err , client.ErrRolledBack ) == false {
		t.Fatalf( "a client with the same state took the old lockbox: %v" , err )
	}
	watcher_again , _ := client.New( url , api_key , master , client.WithState( watcher_state ) )
	if _ , err = watcher_again.CollectionKey( ctx , "notes" , false ); errors.Is( err , client.ErrRolledBack ) == false {
		t.Fatalf( "a client that saw the rotation under way took the old lockbox: %v" , err )
	}
	var back invoice
	if _ , err = again.Get( ctx , "notes" , "a" , &back ); errors.Is( err , client.ErrRolledBack ) == false {
		t.Fatalf( "Get with the old lockbox: %v" , err )
	}
	if _ , err = again.Set( ctx , "notes" , "b" , invoice{ Customer: "after" } ); errors.Is( err , client.ErrRolledBack ) == false {
		t.Fatalf( "Set with the old lockbox: %v" , err )
	}

	// Or the old lockbox with the new one as if the rotation were still under
	// way: a client that saw it finish knows better.
	proxy.swap( "notes" , old_lock , new_lock )
	if _ , err = again.CollectionKey( ctx , "notes" , false ); errors.Is( err , client.ErrRolledBack ) == false {
		t.Fatalf( "old lock with a next_lock after the commit: %v" , err )
	}

	// A client with no memory cannot tell (README.md, "Known limits").
	fresh , _ := client.New( url , api_key , master )
	proxy.swap( "notes" , old_lock , "" )
	if _ , err = fresh.CollectionKey( ctx , "notes" , false ); err != nil { t.Fatalf( "a new client: %v" , err ) }

	// Honest again, everything opens.
	proxy.honest()
	if _ , err = again.Get( ctx , "notes" , "a" , &back ); err != nil || back.Customer != "before" { t.Fatalf( "after: %+v %v" , back , err ) }
	info , err := os.Stat( state )
	if err != nil || info.Mode().Perm() != 0o600 { t.Fatalf( "state file: %v %v" , info , err ) }
}
