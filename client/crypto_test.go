package client

import (
	bytes "bytes"
	ed25519 "crypto/ed25519"
	json "encoding/json"
	errors "errors"
	flag "flag"
	os "os"
	testing "testing"
)

// The vectors in testdata/vectors.json fix the format: the browser viewer is
// checked against the same file (see README.md, "Checking the browser"). Run
// `go test ./client -run Vectors -update` only on purpose -- a changed vector
// means every stored document changed format.
var update = flag.Bool( "update" , false , "rewrite testdata/vectors.json" )

type vectors struct {
	MasterKey  string `json:"master_key"`
	KeyID      string `json:"key_id"`
	Collection string `json:"collection"`
	DocID      string `json:"doc_id"`
	Plaintext  string `json:"plaintext"`
	Nonce      string `json:"nonce"`
	Envelope   string `json:"envelope"`
	Passphrase string `json:"passphrase"`
	Keyring    string `json:"keyring"`
	// Format v2: collection "notes" (top level) and "notes-2024" under it.
	ReadKey      string `json:"read_key"`
	WriteKey     string `json:"write_key"`
	VerifyKey    string `json:"verify_key"`
	ReadKeyID    string `json:"read_key_id"`
	EnvelopeV2   string `json:"envelope_v2"`
	Lockbox      string `json:"lockbox"`
	Child        string `json:"child"`
	ChildRead    string `json:"child_read_key"`
	ChildWrite   string `json:"child_write_key"`
	ChildLockbox string `json:"child_lockbox"`
	// The same child lockbox in the unsigned format from before v3, which
	// holders of the write half still open and read-only holders refuse.
	ChildLockboxV2 string `json:"child_lockbox_v2"`
	APIKey       string `json:"api_key"`
	AccessToken  string `json:"access_token_read_only"`
}

func fixedVectors( t *testing.T ) ( result vectors ) {
	t.Helper()
	master := make( []byte , KeySize )
	for index := range master { master[ index ] = byte( index ) }
	nonce := bytes.Repeat( []byte{ 0x24 } , nonceSize )
	salt := bytes.Repeat( []byte{ 0x5a } , saltSize )
	key := deriveKey( master )
	plaintext := `{"hello":"world","n":1}`
	envelope , err := key.sealWithNonce( "notes" , "doc-1" , []byte( plaintext ) , nonce )
	if err != nil { t.Fatal( err ) }
	ring , err := key.wrapWith( "correct horse battery staple" , salt , nonce , keyringOps , keyringMem )
	if err != nil { t.Fatal( err ) }
	notes := fixedCollectionKey( t , "notes" , 0x40 )
	child := fixedCollectionKey( t , "notes-2024" , 0x60 )
	envelope_v2 , err := notes.sealWithNonce( "doc-1" , []byte( plaintext ) , nonce )
	if err != nil { t.Fatal( err ) }
	nonce_w := bytes.Repeat( []byte{ 0x42 } , nonceSize )
	lock , err := sealLockWith( notes , key , nonce , nonce_w )
	if err != nil { t.Fatal( err ) }
	child_lock , err := sealLockWith( child , notes , nonce , nonce_w )
	if err != nil { t.Fatal( err ) }
	child_lock_v2 , err := sealLockVersion( child , notes , nonce , nonce_w , lockboxV2 )
	if err != nil { t.Fatal( err ) }
	token , err := NewAccessToken( "kid.secret" , notes.ReadOnly() )
	if err != nil { t.Fatal( err ) }
	result = vectors{
		ChildLockboxV2: child_lock_v2 ,
		ReadKey: b64.EncodeToString( notes.read[ : ] ) , WriteKey: b64.EncodeToString( notes.sign.Seed() ) ,
		VerifyKey: b64.EncodeToString( notes.verify ) , ReadKeyID: notes.ID() ,
		EnvelopeV2: b64.EncodeToString( envelope_v2 ) , Lockbox: lock ,
		Child: "notes-2024" , ChildRead: b64.EncodeToString( child.read[ : ] ) , ChildWrite: b64.EncodeToString( child.sign.Seed() ) ,
		ChildLockbox: child_lock , APIKey: "kid.secret" , AccessToken: token ,
		MasterKey: key.Export() , KeyID: key.ID() , Collection: "notes" , DocID: "doc-1" , Plaintext: plaintext ,
		Nonce: b64.EncodeToString( nonce ) , Envelope: b64.EncodeToString( envelope ) ,
		Passphrase: "correct horse battery staple" , Keyring: ring ,
	}
	return
}

// fixedCollectionKey is a collection key whose read key is 32 bytes counting
// up from start and whose write seed counts up from start + 32.
func fixedCollectionKey( t *testing.T , collection string , start byte ) ( key *CollectionKey ) {
	t.Helper()
	read := make( []byte , 32 )
	seed := make( []byte , ed25519.SeedSize )
	for index := range read { read[ index ] = start + byte( index ) }
	for index := range seed { seed[ index ] = start + 32 + byte( index ) }
	key , err := newCollectionKey( collection , read , ed25519.NewKeyFromSeed( seed ).Public().( ed25519.PublicKey ) , seed )
	if err != nil { t.Fatal( err ) }
	return
}

func TestVectors( t *testing.T ) {
	computed := fixedVectors( t )
	if *update {
		encoded , _ := json.MarshalIndent( computed , "" , "  " )
		if err := os.WriteFile( "testdata/vectors.json" , append( encoded , '\n' ) , 0o644 ); err != nil { t.Fatal( err ) }
	}
	raw , err := os.ReadFile( "testdata/vectors.json" )
	if err != nil { t.Fatal( err ) }
	var stored vectors
	if err = json.Unmarshal( raw , &stored ); err != nil { t.Fatal( err ) }
	if stored != computed { t.Fatalf( "the format changed:\nstored   %+v\ncomputed %+v" , stored , computed ) }

	key , err := ParseKey( stored.MasterKey )
	if err != nil { t.Fatal( err ) }
	envelope , _ := b64.DecodeString( stored.Envelope )
	plaintext , err := key.Open( stored.Collection , stored.DocID , envelope )
	if err != nil || string( plaintext ) != stored.Plaintext { t.Fatalf( "open vector: %q %v" , plaintext , err ) }
	unwrapped , err := UnwrapKey( stored.Keyring , stored.Passphrase )
	if err != nil || unwrapped.Export() != stored.MasterKey { t.Fatalf( "unwrap vector: %v" , err ) }

	// v2: the master key opens the top-level lockbox, its keys open the
	// child's, and the read-only token opens the document but cannot write.
	notes , err := openLock( stored.Lockbox , stored.Collection , key )
	if err != nil || notes.CanWrite() == false { t.Fatalf( "open lockbox: %v" , err ) }
	envelope_v2 , _ := b64.DecodeString( stored.EnvelopeV2 )
	if plaintext , err = notes.Open( stored.DocID , envelope_v2 ); err != nil || string( plaintext ) != stored.Plaintext { t.Fatalf( "open v2: %q %v" , plaintext , err ) }
	child , err := openLock( stored.ChildLockbox , stored.Child , notes )
	if err != nil || b64.EncodeToString( child.read[ : ] ) != stored.ChildRead { t.Fatalf( "open child lockbox: %v" , err ) }
	api_key , reader , err := ParseAccessToken( stored.AccessToken )
	if err != nil || api_key != stored.APIKey || reader.CanWrite() { t.Fatalf( "token: %v" , err ) }
	if plaintext , err = reader.Open( stored.DocID , envelope_v2 ); err != nil || string( plaintext ) != stored.Plaintext { t.Fatalf( "reader open: %v" , err ) }
	child_read , err := openLock( stored.ChildLockbox , stored.Child , reader )
	if err != nil || child_read.CanWrite() { t.Fatalf( "reader child lockbox: %v" , err ) }
	// The unsigned v2 lockbox: the write half's holder still opens it, a
	// read-only holder refuses it.
	if child , err = openLock( stored.ChildLockboxV2 , stored.Child , notes ); err != nil || child.CanWrite() == false { t.Fatalf( "v2 child lockbox: %v" , err ) }
	if _ , err = openLock( stored.ChildLockboxV2 , stored.Child , reader ); errors.Is( err , ErrLockUnsigned ) == false { t.Fatalf( "reader opened a v2 lockbox: %v" , err ) }
}

// forger is what a read-only holder of parent can make lockboxes with: the
// parent's read wrap, and its own write wrap and signing key.
type forger struct {
	parent *CollectionKey
	sign   ed25519.PrivateKey
	write  []byte
}

func ( holder forger ) lockParent() string { return holder.parent.collection }
func ( holder forger ) ID() string { return holder.parent.ID() }
func ( holder forger ) wrapRead() []byte { return holder.parent.wrapRead() }
func ( holder forger ) wrapWrite() []byte { return holder.write }
func ( holder forger ) lockSigner() ed25519.PrivateKey { return holder.sign }
func ( holder forger ) lockVerifier() ed25519.PublicKey { return holder.sign.Public().( ed25519.PublicKey ) }

// A read-only key, even with the server's help, cannot plant a sub-collection
// lockbox other holders accept: it can wrap the read half, but cannot sign as
// the parent (v3), and an unsigned one (v2) is refused to read-only holders
// and fails the write-half check for everyone else.
func TestForgedChildLockbox( t *testing.T ) {
	parent , _ := generateCollectionKey( "parent" )
	_ , own_sign , _ := ed25519.GenerateKey( nil )
	fake := forger{ parent: parent.ReadOnly() , sign: own_sign , write: bytes.Repeat( []byte{ 7 } , 32 ) }
	planted , _ := generateCollectionKey( "child" )
	for _ , version := range []int{ lockboxV2 , lockboxV3 } {
		lock , err := sealLockVersion( planted , fake , bytes.Repeat( []byte{ 1 } , nonceSize ) , bytes.Repeat( []byte{ 2 } , nonceSize ) , version )
		if err != nil { t.Fatal( err ) }
		if _ , err = openLock( lock , "child" , parent.ReadOnly() ); err == nil { t.Fatalf( "v%d: another read-only holder accepted a forged lockbox" , version ) }
		if _ , err = openLock( lock , "child" , parent ); err == nil { t.Fatalf( "v%d: the parent's full holder accepted a forged lockbox" , version ) }
	}
	// The real one opens for both.
	real , _ := generateCollectionKey( "child" )
	lock , _ := sealLock( real , parent )
	if _ , err := openLock( lock , "child" , parent.ReadOnly() ); err != nil { t.Fatalf( "reader: %v" , err ) }
	if _ , err := openLock( lock , "child" , parent ); err != nil { t.Fatalf( "writer: %v" , err ) }
}

func TestSealOpen( t *testing.T ) {
	encoded , err := GenerateKey()
	if err != nil { t.Fatal( err ) }
	key , _ := ParseKey( encoded )
	envelope , err := key.Seal( "notes" , "a" , []byte( `{"x":1}` ) )
	if err != nil { t.Fatal( err ) }
	if envelope[ 0 ] != envelopeV1 || len( envelope ) != envelopeMin + 7 { t.Fatalf( "envelope shape: %d bytes" , len( envelope ) ) }

	if plain , err := key.Open( "notes" , "a" , envelope ); err != nil || string( plain ) != `{"x":1}` { t.Fatalf( "open: %q %v" , plain , err ) }
	// Moved to another id or collection: refused, not shown.
	if _ , err := key.Open( "notes" , "b" , envelope ); errors.Is( err , ErrCorrupt ) == false { t.Fatalf( "moved id: %v" , err ) }
	if _ , err := key.Open( "other" , "a" , envelope ); errors.Is( err , ErrCorrupt ) == false { t.Fatalf( "moved collection: %v" , err ) }
	// Changed by one bit.
	envelope[ len( envelope ) - 1 ] ^= 1
	if _ , err := key.Open( "notes" , "a" , envelope ); errors.Is( err , ErrCorrupt ) == false { t.Fatalf( "flipped bit: %v" , err ) }
	envelope[ len( envelope ) - 1 ] ^= 1
	// Another key.
	other_encoded , _ := GenerateKey()
	other , _ := ParseKey( other_encoded )
	if _ , err := other.Open( "notes" , "a" , envelope ); errors.Is( err , ErrWrongKey ) == false { t.Fatalf( "other key: %v" , err ) }
	// Two seals of the same thing differ (random nonce).
	again , _ := key.Seal( "notes" , "a" , []byte( `{"x":1}` ) )
	if bytes.Equal( again , envelope ) { t.Fatal( "nonce reused" ) }
}

func TestKeyring( t *testing.T ) {
	encoded , _ := GenerateKey()
	key , _ := ParseKey( encoded )
	text , err := key.WrapKey( "a long passphrase" )
	if err != nil { t.Fatal( err ) }
	back , err := UnwrapKey( text , "a long passphrase" )
	if err != nil || back.Export() != encoded { t.Fatalf( "unwrap: %v" , err ) }
	if _ , err = UnwrapKey( text , "the wrong one" ); errors.Is( err , ErrWrongKey ) == false { t.Fatalf( "wrong passphrase: %v" , err ) }
	if _ , err = key.WrapKey( "" ); err == nil { t.Fatal( "empty passphrase accepted" ) }

	// A server cannot make a client spend a gigabyte and a minute on one try.
	var ring keyring
	json.Unmarshal( []byte( text ) , &ring )
	ring.Mem = 4 * 1024 * 1024 * 1024
	greedy , _ := json.Marshal( ring )
	if _ , err = UnwrapKey( string( greedy ) , "a long passphrase" ); errors.Is( err , ErrCorrupt ) == false { t.Fatalf( "greedy parameters: %v" , err ) }
}

func TestParseKey( t *testing.T ) {
	for _ , bad := range []string{ "" , "short" , b64.EncodeToString( make( []byte , 31 ) ) } {
		if _ , err := ParseKey( bad ); err == nil { t.Errorf( "%q accepted" , bad ) }
	}
	if id := NewID(); len( id ) != 22 { t.Fatalf( "id %q" , id ) }
}

func TestCollectionKeys( t *testing.T ) {
	encoded , _ := GenerateKey()
	master , _ := ParseKey( encoded )
	parent , err := generateCollectionKey( "parent" )
	if err != nil { t.Fatal( err ) }
	child , _ := generateCollectionKey( "child" )
	parent_lock , err := sealLock( parent , master )
	if err != nil { t.Fatal( err ) }
	child_lock , err := sealLock( child , parent )
	if err != nil { t.Fatal( err ) }

	envelope , err := child.Seal( "a" , []byte( `{"x":1}` ) )
	if err != nil || EnvelopeVersion( envelope ) != 2 { t.Fatalf( "seal: %v" , err ) }

	// Master -> parent -> child.
	opened_parent , err := openLock( parent_lock , "parent" , master )
	if err != nil { t.Fatal( err ) }
	opened_child , err := openLock( child_lock , "child" , opened_parent )
	if err != nil || opened_child.CanWrite() == false { t.Fatalf( "child: %v" , err ) }
	if plain , err := opened_child.Open( "a" , envelope ); err != nil || string( plain ) != `{"x":1}` { t.Fatalf( "open: %v" , err ) }

	// A lockbox read for another collection, or with the wrong holder, fails.
	if _ , err = openLock( child_lock , "other" , opened_parent ); errors.Is( err , ErrCorrupt ) == false { t.Fatalf( "wrong collection: %v" , err ) }
	if _ , err = openLock( child_lock , "child" , master ); errors.Is( err , ErrCorrupt ) == false { t.Fatalf( "wrong parent: %v" , err ) }
	stranger , _ := generateCollectionKey( "parent" )
	if _ , err = openLock( child_lock , "child" , stranger ); errors.Is( err , ErrWrongKey ) == false { t.Fatalf( "stranger: %v" , err ) }
	other_encoded , _ := GenerateKey()
	other_master , _ := ParseKey( other_encoded )
	if _ , err = openLock( parent_lock , "parent" , other_master ); errors.Is( err , ErrWrongKey ) == false { t.Fatalf( "other master: %v" , err ) }

	// A read-only parent opens the child read-only, and cannot write or wrap.
	reader , err := openLock( child_lock , "child" , parent.ReadOnly() )
	if err != nil || reader.CanWrite() { t.Fatalf( "reader: %v" , err ) }
	if _ , err = reader.Seal( "b" , []byte( `{}` ) ); errors.Is( err , ErrReadOnly ) == false { t.Fatalf( "reader sealed: %v" , err ) }
	if _ , err = sealLock( child , parent.ReadOnly() ); errors.Is( err , ErrReadOnly ) == false { t.Fatalf( "reader wrapped: %v" , err ) }

	// A reader can encrypt with the read key but not sign: a forged document
	// (right key, no valid signature) is refused.
	forged := append( []byte{} , envelope... )
	forged[ headerSize + nonceSize ] ^= 1
	if _ , err = reader.Open( "a" , forged ); errors.Is( err , ErrCorrupt ) == false { t.Fatalf( "forged: %v" , err ) }
	if _ , err = reader.Open( "b" , envelope ); errors.Is( err , ErrCorrupt ) == false { t.Fatalf( "moved: %v" , err ) }
	if _ , err = parent.Open( "a" , envelope ); errors.Is( err , ErrWrongKey ) == false { t.Fatalf( "other collection key: %v" , err ) }

	// Tokens round-trip, with and without the write half.
	for _ , key := range []*CollectionKey{ child , child.ReadOnly() } {
		token , err := NewAccessToken( "id.secret" , key )
		if err != nil { t.Fatal( err ) }
		api_key , back , err := ParseAccessToken( token )
		if err != nil || api_key != "id.secret" || back.CanWrite() != key.CanWrite() || back.ID() != key.ID() { t.Fatalf( "token: %v" , err ) }
	}
	if _ , _ , err = ParseAccessToken( "e2eedb-ck1.nope" ); err == nil { t.Fatal( "bad token accepted" ) }
}
