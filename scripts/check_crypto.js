#!/usr/bin/env node
// Holds the browser's crypto (static/js/docs_crypto.js, on the vendored
// plain-JS libsodium) to the format the Go client pins in
// client/testdata/vectors.json: private envelopes, the passphrase keyring,
// and collection keys, signed lockboxes, collection envelopes and access
// tokens. Run by the
// tests, or on its own: node scripts/check_crypto.js
const fs = require( "fs" );
const path = require( "path" );
const vm = require( "vm" );

const root = path.join( __dirname , ".." );
const vectors = JSON.parse( fs.readFileSync( path.join( root , "client" , "testdata" , "vectors.json" ) , "utf8" ) );

// The vendored loader, told (as the page tells it) not to try WebAssembly.
const module_object = { instantiateWasm() { module_object.onAbort( "no WebAssembly" ); return {}; } };
const page = { libsodium_mod: module_object , crypto: require( "crypto" ).webcrypto , TextDecoder , console };
page.window = page;
page.self = page;
vm.createContext( page );
// Byte arrays must be the context's own: libsodium checks instanceof.
const Bytes = vm.runInContext( "Uint8Array" , page );
page.TextEncoder = class { encode( text ) { return new Bytes( Buffer.from( text , "utf8" ) ); } };
vm.runInContext( fs.readFileSync( path.join( root , "static" , "vendor" , "sodium.js" ) , "utf8" ) , page );
vm.runInContext( fs.readFileSync( path.join( root , "static" , "js" , "docs_crypto.js" ) , "utf8" ) + "\nglobalThis.DocsCrypto = DocsCrypto;" , page );
page.I18n = { get: ( key ) => key };

let failed = 0;
function check( name , ok ) {
  if ( !ok ) {
    failed += 1;
    console.error( "FAIL " + name );
  }
}

page.sodium.ready.then( () => {
  const C = page.DocsCrypto;
  C.sodium = page.sodium;
  const nonce = C.unb64( vectors.nonce );
  const nonce_w = new Bytes( 24 ).fill( 0x42 );

  // The master key, its private envelope, and the keyring.
  const master = C.parseKey( vectors.master_key );
  check( "master key id" , C.keyId( master ) === vectors.key_id );
  check( "private seal" , C.seal( master , vectors.collection , vectors.doc_id , vectors.plaintext , nonce ) === vectors.envelope_private );
  check( "private open" , C.open( master , vectors.collection , vectors.doc_id , vectors.envelope_private ) === vectors.plaintext );
  check( "keyring" , C.keyId( C.unwrap( vectors.keyring , vectors.passphrase ) ) === vectors.key_id );

  // Collection keys, built from the same fixed bytes the Go test uses.
  const counting = ( start , n ) => Bytes.from( { length: n } , ( _ , i ) => ( start + i ) & 255 );
  const fixed = ( collection , start , epoch ) => {
    const seed = counting( start + 32 , 32 );
    const key = C.collectionKey( collection , counting( start , 32 ) , C.sodium.crypto_sign_seed_keypair( seed ).publicKey , seed );
    key.epoch = epoch;
    return key;
  };
  const notes = fixed( vectors.collection , 0x40 , vectors.epoch );
  const child = fixed( vectors.child , 0x60 , vectors.child_epoch );
  check( "verify key" , C.b64( notes.verify ) === vectors.verify_key );
  check( "read key id" , C.b64( notes.id ) === vectors.read_key_id );
  check( "collection seal" , C.sealCollection( notes , vectors.doc_id , vectors.plaintext , nonce ) === vectors.envelope_collection );
  check( "lockbox seal" , C.sealLock( notes , master , nonce , nonce_w , C.ownTag( master , notes.collection , notes.id ) ) === vectors.lockbox );
  check( "child lockbox seal" , C.sealLock( child , notes , nonce , nonce_w , C.ownTag( master , child.collection , child.id ) ) === vectors.child_lockbox );
  // The owner tag: the master key's, for these keys only.
  check( "owner tag" , C.owns( master , vectors.lockbox , vectors.collection ) && C.owns( master , vectors.child_lockbox , vectors.child ) );
  check( "owner tag elsewhere" , !C.owns( master , vectors.lockbox , vectors.child ) && !C.owns( C.keyFrom( new Bytes( 32 ).fill( 9 ) ) , vectors.lockbox , vectors.collection ) );
  const squat = C.generateCollectionKey( vectors.child );
  check( "owner tag copied onto other keys" , !C.owns( master , C.sealLock( squat , notes , null , null , C.lockOwn( vectors.child_lockbox ) ) , vectors.child ) );
  check( "token" , C.makeToken( vectors.api_key , C.readOnly( notes ) ) === vectors.access_token_read_only );

  // And opening what Go wrote.
  const opened = C.openLock( vectors.lockbox , vectors.collection , master );
  check( "lockbox open" , C.canWrite( opened ) && C.openCollection( opened , vectors.doc_id , vectors.envelope_collection ) === vectors.plaintext );
  check( "lockbox epoch" , opened.epoch === vectors.epoch );
  // The epoch is signed: a lockbox served with an older one opens for nobody.
  for ( const epoch of [ vectors.epoch - 1 , 0 , 1.5 , "1" , null , 2 ** 53 ] ) {
    const changed = JSON.parse( vectors.lockbox );
    changed.epoch = epoch;
    let code = "";
    try { C.openLock( JSON.stringify( changed ) , vectors.collection , master ); } catch ( error ) { code = error.code; }
    check( "changed epoch refused (" + epoch + ")" , code === "corrupt" );
  }
  check( "child lockbox open" , C.b64( C.openLock( vectors.child_lockbox , vectors.child , opened ).read ) === vectors.child_read_key );
  const token = C.parseToken( vectors.access_token_read_only );
  check( "token parse" , token && token.api_key === vectors.api_key && !C.canWrite( token.key ) );
  check( "reader opens" , C.openCollection( token.key , vectors.doc_id , vectors.envelope_collection ) === vectors.plaintext );
  const child_read = C.openLock( vectors.child_lockbox , vectors.child , token.key );
  check( "reader child is read-only" , !C.canWrite( child_read ) );
  // A lockbox with its signature stripped opens for nobody.
  const stripped = JSON.parse( vectors.child_lockbox );
  delete stripped.sig;
  for ( const holder of [ opened , token.key ] ) {
    let unsigned = "";
    try { C.openLock( JSON.stringify( stripped ) , vectors.child , holder ); } catch ( error ) { unsigned = error.code; }
    check( "unsigned lockbox refused" , unsigned === "corrupt" );
  }
  // A reader planting a child lockbox: it can wrap the read half, but its
  // signature is not the parent's.
  const planted = fixed( "planted" , 0x10 , 1 );
  const box = JSON.parse( C.sealLock( planted , notes , nonce , nonce_w ) );
  const own = C.sodium.crypto_sign_seed_keypair( counting( 0x90 , 32 ) );
  box.sig = C.b64( C.sodium.crypto_sign_detached( C.lockSigned( "planted" , box.parent , C.unb64( box.key_id ) , box.epoch , C.unb64( box.nonce_r ) , C.unb64( box.read ) , C.unb64( box.nonce_w ) , C.unb64( box.write ) ) , own.privateKey ) );
  let forged_lock = "";
  try { C.openLock( JSON.stringify( box ) , "planted" , token.key ); } catch ( error ) { forged_lock = error.code; }
  check( "forged lockbox refused to a reader" , forged_lock === "corrupt" );
  let refused = "";
  try { C.sealCollection( token.key , "x" , "{}" ); } catch ( error ) { refused = error.code; }
  check( "reader cannot seal" , refused === "read_only" );
  const bytes = C.unb64( vectors.envelope_collection );
  bytes[ 60 ] ^= 1;
  refused = "";
  try { C.openCollection( token.key , vectors.doc_id , C.b64( bytes ) ); } catch ( error ) { refused = error.code; }
  check( "forged collection envelope refused" , refused === "corrupt" );

  if ( failed > 0 ) process.exit( 1 );
  console.log( "ok: browser crypto matches the Go vectors" );
} ).catch( ( error ) => {
  console.error( "FAIL " + String( error && error.message || error ).slice( 0 , 300 ) );
  process.exit( 1 );
} );
