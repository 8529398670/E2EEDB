package client

import (
	bytes "bytes"
	json "encoding/json"
	os "os"
	testing "testing"
)

// Fuzz targets for everything the client parses from a server it does not
// trust: envelopes, lockboxes, keyrings, and the access tokens people paste.
// The fixed key and the vectors in testdata/vectors.json are the only valid
// inputs the fuzzer starts from, so anything else it gets accepted is a
// forgery. Run one with, for example:
//
//	go test ./client -run '^$' -fuzz FuzzOpenLock -fuzztime 60s

func fuzzVectors( f *testing.F ) ( stored vectors , master *Key , notes *CollectionKey ) {
	raw , err := os.ReadFile( "testdata/vectors.json" )
	if err != nil { f.Fatal( err ) }
	if err = json.Unmarshal( raw , &stored ); err != nil { f.Fatal( err ) }
	if master , err = ParseKey( stored.MasterKey ); err != nil { f.Fatal( err ) }
	if notes , err = openLock( stored.Lockbox , stored.Collection , master ); err != nil { f.Fatal( err ) }
	return
}

// A private envelope opens only as itself, in its own place.
func FuzzOpenPrivate( f *testing.F ) {
	stored , master , _ := fuzzVectors( f )
	envelope , _ := b64.DecodeString( stored.Envelope )
	f.Add( envelope , stored.Collection , stored.DocID )
	f.Add( envelope[ :len( envelope ) - 1 ] , stored.Collection , stored.DocID )
	f.Add( []byte{ EnvelopeMaster } , "" , "" )
	f.Fuzz( func( t *testing.T , body []byte , collection string , id string ) {
		plaintext , err := master.Open( collection , id , body )
		if err != nil { return }
		if bytes.Equal( body , envelope ) == false || collection != stored.Collection || id != stored.DocID {
			t.Fatalf( "forged private envelope accepted: %x in %q/%q -> %q" , body , collection , id , plaintext )
		}
	} )
}

// A collection envelope opens only as itself, signed, for its own id.
func FuzzOpenCollection( f *testing.F ) {
	stored , _ , notes := fuzzVectors( f )
	envelope , _ := b64.DecodeString( stored.EnvelopeCollection )
	f.Add( envelope , stored.DocID )
	f.Add( envelope[ :len( envelope ) - 1 ] , stored.DocID )
	f.Add( []byte{ EnvelopeCollection } , "" )
	f.Fuzz( func( t *testing.T , body []byte , id string ) {
		for _ , holder := range []*CollectionKey{ notes , notes.ReadOnly() } {
			plaintext , err := holder.Open( id , body )
			if err != nil { continue }
			if bytes.Equal( body , envelope ) == false || id != stored.DocID {
				t.Fatalf( "forged collection envelope accepted: %x as %q -> %q" , body , id , plaintext )
			}
		}
	} )
}

// A lockbox the fuzzer makes up never yields keys other than the real ones,
// whether the master key opens it or a parent collection's keys (full or
// read only) do.
func FuzzOpenLock( f *testing.F ) {
	stored , master , notes := fuzzVectors( f )
	child , err := openLock( stored.ChildLockbox , stored.Child , notes )
	if err != nil { f.Fatal( err ) }
	f.Add( stored.Lockbox , stored.Collection , uint8( 0 ) )
	f.Add( stored.ChildLockbox , stored.Child , uint8( 1 ) )
	f.Add( stored.ChildLockbox , stored.Child , uint8( 2 ) )
	f.Add( `{}` , "" , uint8( 0 ) )
	f.Add( `{"parent":"notes","by":"","key_id":"","nonce_r":"","read":"","sig":""}` , "x" , uint8( 1 ) )
	f.Fuzz( func( t *testing.T , text string , collection string , which uint8 ) {
		var holder lockHolder
		var want *CollectionKey
		switch which % 3 {
		case 0:
			holder , want = master , notes
			if collection != stored.Collection { want = nil }
		case 1:
			holder , want = notes , child
			if collection != stored.Child { want = nil }
		case 2:
			holder , want = notes.ReadOnly() , child
			if collection != stored.Child { want = nil }
		}
		key , err := openLock( text , collection , holder )
		if err != nil { return }
		if want == nil || key.read != want.read || bytes.Equal( key.verify , want.verify ) == false || key.id != want.id {
			t.Fatalf( "forged lockbox accepted for %q by holder %d: %q" , collection , which % 3 , text )
		}
		if which % 3 == 2 && key.CanWrite() {
			t.Fatalf( "a read-only holder got write keys from %q" , text )
		}
		if key.CanWrite() && bytes.Equal( key.sign.Seed() , want.sign.Seed() ) == false {
			t.Fatalf( "lockbox gave a different write key: %q" , text )
		}
	} )
}

// Whatever is pasted, ParseAccessToken never panics, and what it accepts
// encodes back to a token that parses the same.
func FuzzParseAccessToken( f *testing.F ) {
	stored , _ , _ := fuzzVectors( f )
	f.Add( stored.AccessToken )
	f.Add( AccessTokenPrefix )
	f.Add( AccessTokenPrefix + "e30" )
	f.Fuzz( func( t *testing.T , token string ) {
		api_key , key , err := ParseAccessToken( token )
		if err != nil { return }
		again , err := NewAccessToken( api_key , key )
		if err != nil { t.Fatalf( "accepted %q but cannot encode it again: %v" , token , err ) }
		api_key_2 , key_2 , err := ParseAccessToken( again )
		if err != nil || api_key_2 != api_key || key_2.read != key.read || key_2.id != key.id || key_2.CanWrite() != key.CanWrite() {
			t.Fatalf( "token does not round-trip: %q -> %q (%v)" , token , again , err )
		}
	} )
}

// A keyring from the server is checked before Argon2 runs, so a hostile one
// cannot ask for unbounded memory or time, and only the real one unwraps.
func FuzzUnwrapKey( f *testing.F ) {
	stored , _ , _ := fuzzVectors( f )
	f.Add( stored.Keyring , stored.Passphrase )
	f.Add( `{"alg":"argon2id13","ops":4294967295,"mem":18446744073709551615}` , "x" )
	f.Add( `{"alg":"argon2id13","ops":1,"mem":0}` , "x" )
	f.Fuzz( func( t *testing.T , text string , passphrase string ) {
		var ring keyring
		if json.Unmarshal( []byte( text ) , &ring ) == nil && ( ring.Ops > maxKeyringOps || ring.Mem > maxKeyringMem ) {
			if _ , err := UnwrapKey( text , passphrase ); err == nil { t.Fatalf( "out-of-range keyring accepted: %q" , text ) }
			return
		}
		key , err := UnwrapKey( text , passphrase )
		if err != nil { return }
		if key.Export() != stored.MasterKey {
			t.Fatalf( "keyring %q gave another master key" , text )
		}
	} )
}

// Sealing and opening round-trip for any plaintext and place, and changing
// any one byte of the envelope, or opening it somewhere else, fails.
func FuzzSealTamper( f *testing.F ) {
	_ , master , notes := fuzzVectors( f )
	f.Add( []byte( `{"a":1}` ) , "notes" , "doc" , uint16( 0 ) , byte( 1 ) )
	f.Add( []byte{} , "c" , "" , uint16( 40 ) , byte( 0x80 ) )
	f.Fuzz( func( t *testing.T , plaintext []byte , collection string , id string , at uint16 , flip byte ) {
		if flip == 0 { flip = 1 }
		check := func( kind string , envelope []byte , open func( c string , i string , e []byte ) ( []byte , error ) ) {
			back , err := open( collection , id , envelope )
			if err != nil || bytes.Equal( back , plaintext ) == false { t.Fatalf( "%s round trip: %v" , kind , err ) }
			changed := append( []byte( nil ) , envelope... )
			changed[ int( at ) % len( changed ) ] ^= flip
			if _ , err = open( collection , id , changed ); err == nil { t.Fatalf( "%s: a changed byte at %d was accepted" , kind , int( at ) % len( changed ) ) }
			if _ , err = open( collection , id + "x" , envelope ); err == nil { t.Fatalf( "%s: opened under another id" , kind ) }
		}
		private , err := master.Seal( collection , id , plaintext )
		if err != nil { t.Fatal( err ) }
		check( "private" , private , master.Open )
		// A collection key is bound to its own collection; the place is the id.
		shared , err := notes.Seal( id , plaintext )
		if err != nil { t.Fatal( err ) }
		collection = notes.Collection()
		check( "collection" , shared , func( _ string , i string , e []byte ) ( []byte , error ) { return notes.Open( i , e ) } )
		if _ , err = notes.ReadOnly().Open( id , shared ); err != nil { t.Fatalf( "read-only open: %v" , err ) }
	} )
}
