#!/usr/bin/env node
// Holds the Documents screen's key handling (static/js/docs.js) to what the
// Go client does against a dishonest server, with the page's other parts
// (the folder tree, the API, dialogs) stubbed:
//
//   - a folder the server says sits inside a shared one, with no keys yet,
//     gets none (and nothing is written there) unless the person says so;
//   - a folder whose keys are not the master key's own, or sit under keys
//     that are not, is written to only once the person says so, and its
//     private envelopes are never sealed for sharing;
//   - once this device has seen a key rotation, the lockbox from before it
//     is refused, alone or dressed up as a rotation still under way.
//
// Run by the tests, or on its own: node scripts/check_docs_keys.js
const fs = require( "fs" );
const path = require( "path" );
const vm = require( "vm" );

const root = path.join( __dirname , ".." );
const vectors = JSON.parse( fs.readFileSync( path.join( root , "client" , "testdata" , "vectors.json" ) , "utf8" ) );

const module_object = { instantiateWasm() { module_object.onAbort( "no WebAssembly" ); return {}; } };
const page = { libsodium_mod: module_object , crypto: require( "crypto" ).webcrypto , TextDecoder , console };
page.window = page;
page.self = page;
vm.createContext( page );
const Bytes = vm.runInContext( "Uint8Array" , page );
page.TextEncoder = class { encode( text ) { return new Bytes( Buffer.from( text , "utf8" ) ); } };
vm.runInContext( fs.readFileSync( path.join( root , "static" , "vendor" , "sodium.js" ) , "utf8" ) , page );
vm.runInContext( fs.readFileSync( path.join( root , "static" , "js" , "docs_crypto.js" ) , "utf8" ) + "\nglobalThis.DocsCrypto = DocsCrypto;" , page );
vm.runInContext( fs.readFileSync( path.join( root , "static" , "js" , "docs.js" ) , "utf8" ) + "\nglobalThis.Docs = Docs;" , page );
page.I18n = { get: ( key ) => key };

// The stubs: a folder tree the test sets, an API that records what is sent,
// and a confirm dialog that answers as told.
const tree = new Map();
page.DocsTree = {
  get: ( id ) => tree.get( id ),
  refresh: async () => {},
  render: () => {},
  subtree( id ) {
    const order = [ id ];
    for ( let at = 0; at < order.length; at++ ) {
      for ( const folder of tree.values() ) if ( folder.parent === order[ at ] ) order.push( folder.id );
    }
    return order;
  },
};
const sent = [];
const bodies = new Map();
page.Api = {
  async updateCollection( id , change ) { sent.push( "update " + id ); Object.assign( tree.get( id ) , change ); return tree.get( id ); },
  async createCollection( change ) { sent.push( "create " + change.id ); return change; },
  async setDoc( collection , id ) { sent.push( "set " + collection + "/" + id ); return {}; },
  async docs( collection ) { return { docs: bodies.get( collection ) || [] , next: null }; },
};
const asked = [];
let answer = false;
page.Dom = { confirm: async ( question ) => { asked.push( question ); return answer; } , toast() {} };

let failed = 0;
function check( name , ok ) {
  if ( !ok ) {
    failed += 1;
    console.error( "FAIL " + name );
  }
}

async function refused( promise ) {
  try {
    await promise;
    return "";
  } catch ( error ) {
    return error.code || error.message || "error";
  }
}

// A device starting over: no keys held, nothing remembered.
function freshDevice( Docs , master ) {
  Docs.key = master;
  Docs.me = { id: 1 };
  Docs.scope = null;
  Docs.epochs = new Map();
  Docs.epochsFor = null;
  Docs.epochsLoading = null;
  if ( Docs.sharedAllowed ) Docs.sharedAllowed.clear();
  Docs.ownedLocks = null;
  Docs.forgetKeys();
  sent.length = 0;
  asked.length = 0;
  answer = false;
}

page.sodium.ready.then( async () => {
  const C = page.DocsCrypto;
  C.sodium = page.sodium;
  const Docs = page.Docs;
  const master = C.parseKey( vectors.master_key );
  const mine = ( id , epoch , holder ) => {
    const key = C.generateCollectionKey( id , epoch );
    return { key: key , lock: C.sealLock( key , holder || master , null , null , C.ownTag( master , id , key.id ) ) };
  };
  const theirs = ( id , epoch , holder ) => {
    const key = C.generateCollectionKey( id , epoch );
    return { key: key , lock: C.sealLock( key , holder , null , null , "" ) };
  };
  const shared = mine( "S" , 10 );
  const secret = C.seal( master , "diary" , "entry" , '{"secret":1}' );

  // ---- G2: a folder the server puts inside a shared one ------------------

  tree.clear();
  tree.set( "S" , { id: "S" , name: "S" , parent: "" , lock: shared.lock } );
  tree.set( "diary" , { id: "diary" , name: "diary" , parent: "S" , lock: "" } );
  bodies.set( "diary" , [ { collection: "diary" , id: "entry" , version: 1 , body: secret } ] );
  freshDevice( Docs , master );
  check( "no keys made without asking" , ( await refused( Docs.sealBody( "diary" , "x" , "{}" ) ) ) === "cancelled" && asked.length === 1 && sent.length === 0 );
  check( "asked about the parent" , asked[ 0 ] === "docs.keys_under_parent_question" );
  check( "share refuses it" , ( await refused( Docs.prepareShare( "S" ) ) ) === "docs.share_not_owned" && sent.length === 0 );
  answer = true;
  check( "given keys once asked" , ( await refused( Docs.sealBody( "diary" , "x" , "{}" ) ) ) === "" && sent.join() === "update diary" && asked.length === 2 );

  // The same folder with a lockbox planted under S's keys (S's sharee holds
  // them): it opens, but it is not the owner's.
  const planted = theirs( "diary" , 10 , shared.key );
  tree.get( "diary" ).lock = planted.lock;
  freshDevice( Docs , master );
  check( "planted keys are not written with unasked" , ( await refused( Docs.sealBody( "diary" , "x" , "{}" ) ) ) === "cancelled" && asked[ 0 ] === "docs.write_shared_question" );
  check( "planted keys marked" , Docs.madeByShare( tree.get( "diary" ) ) );
  check( "share refuses planted keys" , ( await refused( Docs.prepareShare( "S" ) ) ) === "docs.share_not_owned" && sent.length === 0 );

  // Owned all the way down: tagged keys under a sharee's folder are not
  // the owner's, and a folder made inside the sharee's gets no tag.
  const their_folder = theirs( "X" , 10 , shared.key );
  const below = mine( "Y" , 10 , their_folder.key );
  tree.delete( "diary" );
  tree.set( "X" , { id: "X" , name: "X" , parent: "S" , lock: their_folder.lock } );
  tree.set( "Y" , { id: "Y" , name: "Y" , parent: "X" , lock: below.lock } );
  freshDevice( Docs , master );
  check( "S is the owner's" , !Docs.madeByShare( tree.get( "S" ) ) );
  check( "under a sharee's folder is not" , Docs.madeByShare( tree.get( "Y" ) ) );
  check( "writing there asks" , ( await refused( Docs.sealBody( "Y" , "x" , "{}" ) ) ) === "cancelled" && sent.length === 0 );
  const made = await Docs.newLock( "Z" , "X" );
  check( "no tag inside a sharee's folder" , C.lockOwn( made.lock ) === "" && !made.key.owned );
  const own = await Docs.newLock( "W" , "S" );
  check( "tag inside the owner's" , C.owns( master , own.lock , "W" ) && own.key.owned );

  // ---- G1: a rotation rolled back -----------------------------------------

  const before = mine( "notes" , 100 );
  const after = mine( "notes" , 101 );
  tree.clear();
  tree.set( "notes" , { id: "notes" , name: "notes" , parent: "" , lock: before.lock } );
  freshDevice( Docs , master );
  check( "old keys open first" , ( await refused( Docs.keyFor( "notes" , false ) ) ) === "" );
  // Rotated: the new lockbox is seen.
  tree.get( "notes" ).lock = after.lock;
  Docs.forgetKeys();
  check( "new keys open" , ( await refused( Docs.keyFor( "notes" , false ) ) ) === "" );
  // Then the server serves the old one again.
  tree.get( "notes" ).lock = before.lock;
  Docs.forgetKeys();
  check( "old lockbox refused" , ( await refused( Docs.keyFor( "notes" , false ) ) ) === "rolled_back" );
  check( "writing with it refused" , ( await refused( Docs.sealBody( "notes" , "x" , "{}" ) ) ) === "rolled_back" && sent.length === 0 );
  tree.get( "notes" ).next_lock = after.lock;
  Docs.forgetKeys();
  check( "old lockbox dressed as a rotation refused" , ( await refused( Docs.keyFor( "notes" , false ) ) ) === "rolled_back" );

  // A device that saw the rotation only under way.
  freshDevice( Docs , master );
  check( "mid-rotation opens" , ( await refused( Docs.sealBody( "notes" , "x" , "{}" ) ) ) === "" && ( await refused( Docs.keyFor( "notes" , false ) ) ) === "" );
  delete tree.get( "notes" ).next_lock;
  Docs.forgetKeys();
  check( "old lockbox alone refused after seeing the rotation" , ( await refused( Docs.keyFor( "notes" , false ) ) ) === "rolled_back" );
  // An older rotation's next_lock is refused too.
  tree.get( "notes" ).lock = after.lock;
  tree.get( "notes" ).next_lock = mine( "notes" , 101 , master ).lock;
  Docs.forgetKeys();
  check( "a next_lock no newer than what is seen" , ( await refused( Docs.nextKeyFor( "notes" ) ) ) === "" );
  tree.get( "notes" ).next_lock = mine( "notes" , 100 ).lock;
  Docs.forgetKeys();
  check( "an older next_lock refused" , ( await refused( Docs.nextKeyFor( "notes" ) ) ) === "rolled_back" );

  // A device with no memory cannot tell (README.md, "Known limits"), and
  // forgetting the device is that.
  delete tree.get( "notes" ).next_lock;
  tree.get( "notes" ).lock = before.lock;
  await Docs.forgetDevice();
  Docs.forgetKeys();
  check( "a forgotten device takes the old lockbox" , ( await refused( Docs.keyFor( "notes" , false ) ) ) === "" );

  // New keys for an id start above anything this device saw for it.
  check( "fresh epoch is above the seen one" , C.generateCollectionKey( "n" , Docs.freshEpoch( "notes" ) ).epoch > 100 );

  if ( failed > 0 ) process.exit( 1 );
  console.log( "ok: the Documents screen refuses what the Go client refuses" );
} ).catch( ( error ) => {
  console.error( "FAIL " + String( error && error.stack || error ).slice( 0 , 600 ) );
  process.exit( 1 );
} );
