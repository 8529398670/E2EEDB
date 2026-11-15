// The Documents screen's crypto, and the only file in the browser that touches
// libsodium. It reads and writes exactly what the Go client (client/crypto.go
// and client/crypto_collection.go) does; README.md, "Crypto format", is the
// specification for both, and client/testdata/vectors.json pins it
// (scripts/check_crypto.js checks this file against it).
//
// Every collection has its own read key and Ed25519 write key, kept in a
// signed lockbox wrapped by its parent's keys (the master key at the top
// level). A document is a collection envelope, sealed with the read key and
// signed with the write key, or, as the other option, a private envelope
// sealed with the master key's own subkey, which nothing but the master key
// opens. A collection's keys reach its subtree; an access token carries one
// collection's keys, read-only or with the write half.
//
// No WebAssembly is used. static/vendor/sodium.js is libsodium.js with its
// WebAssembly copy cut out (misc/vendor_sodium.sh), leaving the plain-JS build
// it ships as a backup; the page's CSP (script-src 'self') would refuse to
// compile WebAssembly anyway. The loader is told, through the module object it
// reads from window.libsodium_mod, that WebAssembly is not available, so it
// goes straight to the plain-JS module without trying.
//
// sodium.js is about a megabyte, so it is only fetched the first time this
// screen needs it.
const DocsCrypto = {
  sodium: null,
  loading: null,

  ENVELOPE_MASTER: 1,
  ENVELOPE_COLLECTION: 2,
  SIGNATURE_BYTES: 64,
  TOKEN_PREFIX: "e2eedb-ck.",
  KEY_BYTES: 32,
  KEY_ID_BYTES: 16,
  NONCE_BYTES: 24,
  // Argon2id cost for a new keyring: the same as the Go client's.
  KEYRING_OPS: 2,
  KEYRING_MEM: 32 * 1024 * 1024,
  // What an unwrap accepts from the server, as in the Go client.
  MAX_OPS: 10,
  MIN_MEM: 8 * 1024 * 1024,
  MAX_MEM: 1024 * 1024 * 1024,

  load() {
    if ( this.loading ) return this.loading;
    this.loading = new Promise( ( resolve , reject ) => {
      const module = {
        // Called by the loader instead of compiling WebAssembly. Aborting
        // here is what sends it to its plain-JS module.
        instantiateWasm: function () {
          module.onAbort( "WebAssembly is not used here" );
          return {};
        },
      };
      window.libsodium_mod = module;
      const script = document.createElement( "script" );
      script.src = "/vendor/sodium.js";
      script.onload = () => {
        window.sodium.ready.then( () => {
          this.sodium = window.sodium;
          resolve( this.sodium );
        } , reject );
      };
      script.onerror = () => reject( new Error( I18n.get( "docs.error_load" ) ) );
      document.head.appendChild( script );
    } );
    // A failed load can be tried again.
    this.loading.catch( () => { this.loading = null; } );
    return this.loading;
  },

  b64( bytes ) {
    return this.sodium.to_base64( bytes , this.sodium.base64_variants.ORIGINAL );
  },

  unb64( text ) {
    return this.sodium.from_base64( text , this.sodium.base64_variants.ORIGINAL );
  },

  utf8( text ) {
    return new TextEncoder().encode( text );
  },

  join( ...parts ) {
    const total = parts.reduce( ( sum , part ) => sum + part.length , 0 );
    const out = new Uint8Array( total );
    let at = 0;
    parts.forEach( ( part ) => { out.set( part , at ); at += part.length; } );
    return out;
  },

  // A key from its base64 form, or null if it is not one.
  parseKey( text ) {
    let master;
    try {
      master = this.unb64( text.trim() );
    } catch ( error ) {
      return null;
    }
    return master.length === this.KEY_BYTES ? this.keyFrom( master ) : null;
  },

  keyFrom( master ) {
    const sodium = this.sodium;
    return {
      master: master,
      enc: sodium.crypto_generichash( 32 , this.utf8( "e2eedb/master/enc" ) , master ),
      id: sodium.crypto_generichash( this.KEY_ID_BYTES , this.utf8( "e2eedb/master/kid" ) , master ),
    };
  },

  generateKey() {
    return this.b64( this.sodium.randombytes_buf( this.KEY_BYTES ) );
  },

  keyId( key ) {
    return this.b64( key.id );
  },

  // A random document id: 22 URL-safe characters, like client.NewID.
  newId() {
    return this.sodium.to_base64( this.sodium.randombytes_buf( 16 ) , this.sodium.base64_variants.URLSAFE_NO_PADDING );
  },

  associated( header , collection , id ) {
    return this.join( header , this.utf8( collection ) , new Uint8Array( [ 0 ] ) , this.utf8( id ) );
  },

  // JSON text in, base64 private envelope out.
  seal( key , collection , id , text , nonce ) {
    const sodium = this.sodium;
    const header = this.join( new Uint8Array( [ this.ENVELOPE_MASTER ] ) , key.id );
    nonce = nonce || sodium.randombytes_buf( this.NONCE_BYTES );
    const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt( this.utf8( text ) , this.associated( header , collection , id ) , null , nonce , key.enc );
    return this.b64( this.join( header , nonce , sealed ) );
  },

  // The key id an envelope names (the master key's for a private envelope,
  // the collection key's otherwise), base64, or "" if it is not an envelope.
  envelopeKeyId( body ) {
    const bytes = this.unb64( body );
    if ( bytes.length < 1 + this.KEY_ID_BYTES || ( bytes[ 0 ] !== this.ENVELOPE_MASTER && bytes[ 0 ] !== this.ENVELOPE_COLLECTION ) ) return "";
    return this.b64( bytes.subarray( 1 , 1 + this.KEY_ID_BYTES ) );
  },

  // Base64 private envelope in, JSON text out. Throws an Error whose code is
  // "wrong_key" (sealed under another key) or "corrupt".
  open( key , collection , id , body ) {
    const sodium = this.sodium;
    const fail = ( code ) => {
      const error = new Error( I18n.get( "docs.error_" + code ) );
      error.code = code;
      return error;
    };
    const bytes = this.unb64( body );
    const header_end = 1 + this.KEY_ID_BYTES;
    if ( bytes.length < header_end + this.NONCE_BYTES + 16 || bytes[ 0 ] !== this.ENVELOPE_MASTER ) throw fail( "corrupt" );
    if ( !sodium.memcmp( bytes.subarray( 1 , header_end ) , key.id ) ) throw fail( "wrong_key" );
    const header = bytes.subarray( 0 , header_end );
    const nonce = bytes.subarray( header_end , header_end + this.NONCE_BYTES );
    try {
      const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt( null , bytes.subarray( header_end + this.NONCE_BYTES ) , this.associated( header , collection , id ) , nonce , key.enc );
      return sodium.to_string( plain );
    } catch ( error ) {
      throw fail( "corrupt" );
    }
  },

  fail( code ) {
    const error = new Error( I18n.get( "docs.error_" + code ) );
    error.code = code;
    return error;
  },

  // The kind of a base64 envelope: ENVELOPE_MASTER, ENVELOPE_COLLECTION, or 0.
  envelopeKind( body ) {
    try {
      const bytes = this.unb64( body );
      return bytes.length ? bytes[ 0 ] : 0;
    } catch ( error ) {
      return 0;
    }
  },

  // ---- collection keys ----

  // One collection's keys. seed (the write half) may be null: read-only.
  collectionKey( collection , read , verify , seed ) {
    const sodium = this.sodium;
    if ( read.length !== 32 || verify.length !== 32 || ( seed && seed.length !== 32 ) ) throw this.fail( "corrupt" );
    const key = {
      collection: collection ,
      read: read ,
      enc: sodium.crypto_generichash( 32 , this.utf8( "e2eedb/collection/enc" ) , read ) ,
      id: sodium.crypto_generichash( this.KEY_ID_BYTES , this.utf8( "e2eedb/collection/kid" ) , read ) ,
      verify: verify ,
      seed: seed || null ,
      sign: null ,
    };
    if ( seed ) {
      const pair = sodium.crypto_sign_seed_keypair( seed );
      if ( !sodium.memcmp( pair.publicKey , verify ) ) throw this.fail( "corrupt" );
      key.sign = pair.privateKey;
    }
    return key;
  },

  // Fresh keys for collection. epoch is the lockbox epoch they will carry
  // (freshEpoch, or one more than the keys they replace).
  generateCollectionKey( collection , epoch ) {
    const seed = this.sodium.randombytes_buf( 32 );
    const key = this.collectionKey( collection , this.sodium.randombytes_buf( 32 ) , this.sodium.crypto_sign_seed_keypair( seed ).publicKey , seed );
    key.epoch = epoch || this.freshEpoch( 0 );
    return key;
  },

  // A lockbox's epoch (README.md, "Lockboxes"): new keys start at the time
  // they were made, in seconds, and each rotation adds one, so a client that
  // remembers the highest it has seen can refuse an older lockbox the server
  // serves again. above is the highest this client has seen for the id.
  MAX_EPOCH: Number.MAX_SAFE_INTEGER ,
  freshEpoch( above ) {
    return Math.max( Math.floor( Date.now() / 1000 ) , ( above || 0 ) + 1 );
  },

  validEpoch( epoch ) {
    return Number.isSafeInteger( epoch ) && epoch >= 1 && epoch <= this.MAX_EPOCH;
  },

  // An epoch as the 8 big-endian bytes lockSigned covers.
  epochBytes( epoch ) {
    const bytes = new Uint8Array( 8 );
    let rest = epoch;
    for ( let at = 7; at >= 0; at-- ) {
      bytes[ at ] = rest % 256;
      rest = Math.floor( rest / 256 );
    }
    return bytes;
  },

  // The epoch a lockbox says it has, unchecked: 0 when it has none. Only for
  // telling whether a lockbox is there; openLock checks it.
  lockEpoch( text ) {
    try {
      const epoch = ( JSON.parse( text ) || {} ).epoch;
      return this.validEpoch( epoch ) ? epoch : 0;
    } catch ( error ) {
      return 0;
    }
  },

  canWrite( key ) {
    return !!key.sign;
  },

  readOnly( key ) {
    return Object.assign( {} , key , { seed: null , sign: null } );
  },

  signed( body , collection , id ) {
    return this.join( body , this.utf8( collection ) , new Uint8Array( [ 0 ] ) , this.utf8( id ) );
  },

  // JSON text in, base64 collection envelope out (sealed and signed).
  sealCollection( key , id , text , nonce ) {
    const sodium = this.sodium;
    if ( !key.sign ) throw this.fail( "read_only" );
    const header = this.join( new Uint8Array( [ this.ENVELOPE_COLLECTION ] ) , key.id );
    nonce = nonce || sodium.randombytes_buf( this.NONCE_BYTES );
    const sealed = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt( this.utf8( text ) , this.associated( header , key.collection , id ) , null , nonce , key.enc );
    const body = this.join( header , nonce , sealed );
    return this.b64( this.join( body , sodium.crypto_sign_detached( this.signed( body , key.collection , id ) , key.sign ) ) );
  },

  // Base64 collection envelope in, JSON text out, after checking its
  // signature.
  openCollection( key , id , body ) {
    const sodium = this.sodium;
    const bytes = this.unb64( body );
    const header_end = 1 + this.KEY_ID_BYTES;
    if ( bytes.length < header_end + this.NONCE_BYTES + 16 + this.SIGNATURE_BYTES || bytes[ 0 ] !== this.ENVELOPE_COLLECTION ) throw this.fail( "corrupt" );
    if ( !sodium.memcmp( bytes.subarray( 1 , header_end ) , key.id ) ) throw this.fail( "wrong_key" );
    const signed_end = bytes.length - this.SIGNATURE_BYTES;
    const signed_part = bytes.subarray( 0 , signed_end );
    if ( !sodium.crypto_sign_verify_detached( bytes.subarray( signed_end ) , this.signed( signed_part , key.collection , id ) , key.verify ) ) throw this.fail( "corrupt" );
    const nonce = bytes.subarray( header_end , header_end + this.NONCE_BYTES );
    try {
      const plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt( null , signed_part.subarray( header_end + this.NONCE_BYTES ) , this.associated( bytes.subarray( 0 , header_end ) , key.collection , id ) , nonce , key.enc );
      return sodium.to_string( plain );
    } catch ( error ) {
      throw this.fail( "corrupt" );
    }
  },

  // What wraps a lockbox: the master key (for top-level collections, parent
  // "") or a parent collection's keys.
  holderParent( holder ) {
    return holder.master ? "" : holder.collection;
  },

  holderWrap( holder , write ) {
    const label = this.utf8( write ? "e2eedb/lock/wrap-w" : "e2eedb/lock/wrap-r" );
    if ( holder.master ) return this.sodium.crypto_generichash( 32 , label , holder.master );
    if ( !write ) return this.sodium.crypto_generichash( 32 , label , holder.read );
    return holder.seed ? this.sodium.crypto_generichash( 32 , label , holder.seed ) : null;
  },

  // What signs and checks the lockboxes a holder wraps: the
  // master key's own signing key, derived from it, or a collection's write
  // key and verify key. sign is null for a read-only holder.
  holderSigner( holder ) {
    const sodium = this.sodium;
    if ( holder.master ) {
      const pair = sodium.crypto_sign_seed_keypair( sodium.crypto_generichash( 32 , this.utf8( "e2eedb/lock/sign-seed" ) , holder.master ) );
      return { sign: pair.privateKey , verify: pair.publicKey };
    }
    return { sign: holder.sign || null , verify: holder.verify };
  },

  // What a lockbox's sig covers:
  // "e2eedb/lock/sign" || 0 || c || 0 || parent || 0 || key_id || nonce_r || read || nonce_w || write
  lockSigned( collection , parent , key_id , epoch , nonce_r , read , nonce_w , write ) {
    const zero = new Uint8Array( [ 0 ] );
    return this.join( this.utf8( "e2eedb/lock/sign" ) , zero , this.utf8( collection ) , zero , this.utf8( parent ) , zero , key_id , this.epochBytes( epoch ) , nonce_r , read , nonce_w , write );
  },

  lockAssociated( label , collection , parent ) {
    const zero = new Uint8Array( [ 0 ] );
    return this.join( this.utf8( label ) , zero , this.utf8( collection ) , zero , this.utf8( parent ) );
  },

  // The owner tag: says the master key made a collection's keys (key_id), so
  // the account's clients can tell its own folders from ones made through an
  // access token without asking the server. Only the master key makes or
  // checks it; the lockbox's sig does not cover it, so a re-wrap carries it.
  // own = BLAKE2b-256( key = M , "e2eedb/lock/own" || 0 || c || 0 || key_id )
  ownTag( master_key , collection , key_id ) {
    const zero = new Uint8Array( [ 0 ] );
    return this.b64( this.sodium.crypto_generichash( 32 , this.join( this.utf8( "e2eedb/lock/own" ) , zero , this.utf8( collection ) , zero , key_id ) , master_key.master ) );
  },

  // Whether lockbox text carries master_key's owner tag for collection.
  owns( master_key , text , collection ) {
    try {
      const box = JSON.parse( text );
      if ( !box || !box.own ) return false;
      const key_id = this.unb64( box.key_id );
      if ( key_id.length !== this.KEY_ID_BYTES ) return false;
      return this.sodium.memcmp( this.utf8( box.own ) , this.utf8( this.ownTag( master_key , collection , key_id ) ) );
    } catch ( error ) {
      return false;
    }
  },

  // The owner tag a lockbox carries, "" for none.
  lockOwn( text ) {
    try {
      return ( JSON.parse( text ) || {} ).own || "";
    } catch ( error ) {
      return "";
    }
  },

  // The lockbox text for key, wrapped by holder and signed. Both need their
  // write half. own is the owner tag to carry (ownTag), "" for none.
  sealLock( key , holder , nonce_r , nonce_w , own ) {
    const sodium = this.sodium;
    const wrap_write = this.holderWrap( holder , true );
    if ( !key.seed || !wrap_write ) throw this.fail( "read_only" );
    if ( !this.validEpoch( key.epoch ) ) throw this.fail( "corrupt" );
    const parent = this.holderParent( holder );
    nonce_r = nonce_r || sodium.randombytes_buf( this.NONCE_BYTES );
    nonce_w = nonce_w || sodium.randombytes_buf( this.NONCE_BYTES );
    const read = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt( this.join( key.read , key.verify ) , this.lockAssociated( "e2eedb/lock/read" , key.collection , parent ) , null , nonce_r , this.holderWrap( holder , false ) );
    const write = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt( key.seed , this.lockAssociated( "e2eedb/lock/write" , key.collection , parent ) , null , nonce_w , wrap_write );
    const box = {
      parent: parent , by: this.b64( holder.id ) , key_id: this.b64( key.id ) , epoch: key.epoch ,
      nonce_r: this.b64( nonce_r ) , read: this.b64( read ) , nonce_w: this.b64( nonce_w ) , write: this.b64( write ) ,
      sig: this.b64( sodium.crypto_sign_detached( this.lockSigned( key.collection , parent , key.id , key.epoch , nonce_r , read , nonce_w , write ) , this.holderSigner( holder ).sign ) ) ,
    };
    if ( own ) box.own = own;
    return JSON.stringify( box );
  },

  // collection's keys from its lockbox: the write half too when holder has
  // one, after checking the holder's signature. Errors: "wrong_key" (wrapped
  // by another key) or "corrupt" (changed, unsigned, or made for another
  // place).
  openLock( text , collection , holder ) {
    const sodium = this.sodium;
    let box;
    try {
      box = JSON.parse( text );
    } catch ( error ) {
      throw this.fail( "corrupt" );
    }
    const parent = this.holderParent( holder );
    if ( !box || box.parent !== parent ) throw this.fail( "corrupt" );
    if ( box.by !== this.b64( holder.id ) ) throw this.fail( "wrong_key" );
    if ( !this.validEpoch( box.epoch ) ) throw this.fail( "corrupt" );
    let opened , seed = null;
    let valid = false;
    try {
      const signed = this.lockSigned( collection , parent , this.unb64( box.key_id ) , box.epoch , this.unb64( box.nonce_r ) , this.unb64( box.read ) , this.unb64( box.nonce_w ) , this.unb64( box.write ) );
      valid = sodium.crypto_sign_verify_detached( this.unb64( box.sig ) , signed , this.holderSigner( holder ).verify );
    } catch ( error ) {
      valid = false;
    }
    if ( !valid ) throw this.fail( "corrupt" );
    try {
      opened = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt( null , this.unb64( box.read ) , this.lockAssociated( "e2eedb/lock/read" , collection , parent ) , this.unb64( box.nonce_r ) , this.holderWrap( holder , false ) );
      const wrap_write = this.holderWrap( holder , true );
      if ( wrap_write ) {
        seed = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt( null , this.unb64( box.write ) , this.lockAssociated( "e2eedb/lock/write" , collection , parent ) , this.unb64( box.nonce_w ) , wrap_write );
      }
    } catch ( error ) {
      throw this.fail( "corrupt" );
    }
    if ( opened.length !== 64 ) throw this.fail( "corrupt" );
    const key = this.collectionKey( collection , opened.subarray( 0 , 32 ) , opened.subarray( 32 ) , seed );
    if ( this.b64( key.id ) !== box.key_id ) throw this.fail( "corrupt" );
    key.epoch = box.epoch;
    return key;
  },

  // The one string to hand someone: a scoped API key and a collection's
  // keys. Only the API key part is ever sent to the server.
  makeToken( api_key , key ) {
    const sodium = this.sodium;
    const payload = { k: api_key , c: key.collection , r: this.b64( key.read ) , v: this.b64( key.verify ) };
    if ( key.seed ) payload.w = this.b64( key.seed );
    return this.TOKEN_PREFIX + sodium.to_base64( this.utf8( JSON.stringify( payload ) ) , sodium.base64_variants.URLSAFE_NO_PADDING );
  },

  // { api_key , key } from a token, or null if it is not one.
  parseToken( text ) {
    const sodium = this.sodium;
    text = ( text || "" ).trim();
    if ( !text.startsWith( this.TOKEN_PREFIX ) ) return null;
    try {
      const payload = JSON.parse( sodium.to_string( sodium.from_base64( text.slice( this.TOKEN_PREFIX.length ) , sodium.base64_variants.URLSAFE_NO_PADDING ) ) );
      if ( !payload.k || !payload.c ) return null;
      const key = this.collectionKey( payload.c , this.unb64( payload.r ) , this.unb64( payload.v ) , payload.w ? this.unb64( payload.w ) : null );
      return { api_key: payload.k , key: key };
    } catch ( error ) {
      return null;
    }
  },

  keyringAssociated( id ) {
    return this.join( this.utf8( "e2eedb/keyring" ) , id );
  },

  passphraseKey( passphrase , salt , ops , mem ) {
    const sodium = this.sodium;
    return sodium.crypto_pwhash( 32 , this.utf8( passphrase ) , salt , ops , mem , sodium.crypto_pwhash_ALG_ARGON2ID13 );
  },

  // The keyring text the server stores: the master key under a passphrase.
  wrap( key , passphrase ) {
    const sodium = this.sodium;
    const salt = sodium.randombytes_buf( sodium.crypto_pwhash_SALTBYTES );
    const nonce = sodium.randombytes_buf( this.NONCE_BYTES );
    const wrapping = this.passphraseKey( passphrase , salt , this.KEYRING_OPS , this.KEYRING_MEM );
    const wrapped = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt( key.master , this.keyringAssociated( key.id ) , null , nonce , wrapping );
    return JSON.stringify( {
      alg: "argon2id13" , ops: this.KEYRING_OPS , mem: this.KEYRING_MEM ,
      salt: this.b64( salt ) , nonce: this.b64( nonce ) , key_id: this.b64( key.id ) , wrapped: this.b64( wrapped ) ,
    } );
  },

  // The key a keyring holds, or an Error with code "wrong_key" (wrong
  // passphrase) or "corrupt".
  unwrap( text , passphrase ) {
    const sodium = this.sodium;
    const fail = ( code ) => {
      const error = new Error( I18n.get( "docs.error_" + ( code === "wrong_key" ? "passphrase" : code ) ) );
      error.code = code;
      return error;
    };
    let ring;
    try {
      ring = JSON.parse( text );
    } catch ( error ) {
      throw fail( "corrupt" );
    }
    if ( ring.alg !== "argon2id13" || !( ring.ops >= 1 && ring.ops <= this.MAX_OPS ) || !( ring.mem >= this.MIN_MEM && ring.mem <= this.MAX_MEM ) ) throw fail( "corrupt" );
    const id = this.unb64( ring.key_id );
    const wrapping = this.passphraseKey( passphrase , this.unb64( ring.salt ) , ring.ops , ring.mem );
    let master;
    try {
      master = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt( null , this.unb64( ring.wrapped ) , this.keyringAssociated( id ) , this.unb64( ring.nonce ) , wrapping );
    } catch ( error ) {
      throw fail( "wrong_key" );
    }
    const key = this.keyFrom( master );
    if ( !sodium.memcmp( key.id , id ) ) throw fail( "corrupt" );
    return key;
  },
};
