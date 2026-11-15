// The Documents screen: browse, read, edit, create and delete the account's
// documents, decrypted here in the browser. The server only ever sees what
// DocsCrypto sealed. app.js calls Docs.init( me ) for everyone signed in.
//
// The key lives in this object and nowhere else: not in storage, not in the
// URL, not in the activity log (the cards that show it are data-no-track). A
// reload, Lock, or signing out forgets it.
//
// Lists (collections, documents) are metadata the server already knows, so
// they show without the key; opening, editing and creating need it.
//
// Every collection has its own keys (README.md, "Crypto format"), kept in a
// lockbox beside it that its parent's keys open (the master key's, at the
// top level). keyFor finds them, giving a collection keys the first time
// something is written to it. Opened with an access token instead of signing
// in (openWithToken), this screen is all there is: the token's collection
// and those under it, read-only unless the token carries the write key.
const Docs = {
  // The master key, or null.
  key: null,
  // Collection keys opened so far: id -> DocsCrypto.collectionKey.
  folderKeys: new Map(),
  // The new keys of collections whose keys are being rotated (next_lock),
  // opened so far: what they are written with until it is done.
  folderNextKeys: new Map(),
  // Opened with an access token: { key , api_key }; null when signed in.
  scope: null,
  // Who this screen is: me.id when signed in. Names this device's epoch
  // memory (epochs) for the account.
  me: null,
  // The highest lockbox epochs this device has seen, by collection:
  // { lock , next }. Kept in IndexedDB (epochStore) so a reload remembers;
  // see checkLockEpoch.
  epochs: new Map(),
  epochsFor: null,
  epochsLoading: null,
  // Folders this tab was told it may write into although their keys are
  // not the master key's (askShared): collection + "\n" + key id.
  sharedAllowed: new Set(),
  // The account's keyring reply (GET /api/keyring), or null when none is set.
  keyring: null,
  collection: null,
  // Ids of the documents ticked in the list, for Move to.
  picked: new Set(),
  // The document in the editor: { collection , id , version , isNew , text }.
  open: null,
  // A #docs/<collection>/<id> link opened while locked, for unlockWith.
  pendingLink: null,
  // How long the last passphrase unlock or wrap took, in ms.
  lastPassphraseMs: null,
  pageSize: 50,
  // The vanilla-jsoneditor in place of #docs-editor-text (editorHost is the
  // box it draws in), or null when it did not load (the plain textarea is
  // used then).
  editor: null,
  editorHost: null,

  async init( me ) {
    this.me = me || null;
    Dom.show( Dom.get( "docs-panel" ) , true );
    // An access token's own collection: its keys are the token's.
    if ( this.scope ) this.folderKeys.set( this.scope.key.collection , this.scope.key );
    Dom.get( "docs-share-copy" ).addEventListener( "click" , () => Dom.copy( Dom.get( "docs-share-value" ) ) );
    Qr.toggle( Dom.get( "docs-share-qr-button" ) , Dom.get( "docs-share-qr" ) , Dom.get( "docs-share-value" ) );
    Dom.get( "docs-share-close" ).addEventListener( "click" , () => this.hideShared() );
    Dom.onSubmit( Dom.get( "docs-key-form" ) , this.onUnlockWithKey.bind( this ) );
    Dom.onSubmit( Dom.get( "docs-passphrase-unlock-form" ) , this.onUnlockWithPassphrase.bind( this ) );
    Dom.onSubmit( Dom.get( "docs-passphrase-form" ) , this.onSetPassphrase.bind( this ) );
    Dom.onSubmit( Dom.get( "docs-editor-form" ) , this.onSave.bind( this ) );
    Dom.onPress( Dom.get( "docs-generate-button" ) , this.onGenerate.bind( this ) );
    Dom.onPress( Dom.get( "docs-forget-device" ) , this.onForgetDevice.bind( this ) );
    Dom.onPress( Dom.get( "docs-new-key-use" ) , this.onUseNewKey.bind( this ) );
    Dom.get( "docs-new-key-copy" ).addEventListener( "click" , () => Dom.copy( Dom.get( "docs-new-key-value" ) ) );
    Dom.get( "docs-lock-button" ).addEventListener( "click" , () => this.lock() );
    Dom.get( "docs-new-button" ).addEventListener( "click" , () => this.startNew() );
    Dom.onPress( Dom.get( "docs-move-button" ) , () => this.moveDocsTo( Array.from( this.picked ) ) );
    Dom.get( "docs-pick-all" ).addEventListener( "change" , ( event ) => this.pickAll( event.target.checked ) );
    DocsTree.init();
    Dom.get( "docs-editor-format" ).addEventListener( "click" , () => this.format() );
    Dom.get( "docs-editor-copy" ).addEventListener( "click" , () => this.copyText() );
    this.setupEditor();
    Dom.onPress( Dom.get( "docs-editor-delete" ) , () => this.open && this.remove( this.open.collection , this.open.id ) );
    Dom.get( "docs-editor-close" ).addEventListener( "click" , () => this.closeEditor() );
    window.addEventListener( "hashchange" , () => {
      if ( Nav.current() === "docs" ) DocsTree.refresh();
    } );
    this.renderLock();
    this.showNothing();
    // A scoped key cannot read the keyring, and has no use for it.
    await Promise.all( [ DocsTree.refresh() , this.scope ? null : this.refreshKeyring() ] );
    if ( this.scope ) {
      // Now that the tree is here, the status line can name the collection.
      this.renderLock();
      await this.showCollection( this.scope.key.collection );
    }
    this.openLinked();
  },

  // ---- keys ----------------------------------------------------------------

  hasKey() {
    return this.key !== null || this.scope !== null;
  },

  // Whether this page may write: always with the master key, and with an
  // access token only if it carries the write key.
  canWrite() {
    return this.scope === null || DocsCrypto.canWrite( this.scope.key );
  },

  // collection's keys, from its lockbox. create: a collection without keys
  // gets them now (which needs write access to its parent), and one that
  // does not exist yet is made at the top level (master key only).
  // depth counts the folders walked up so far: a dishonest server's parent
  // cycle (A in B in A) would otherwise walk forever.
  //
  // create "share" also gives keys to a folder under a parent without
  // asking (prepareShare: sharing the parent is the point). Otherwise, with
  // the master key, a folder that sits under a parent and has no keys yet
  // gets them only once the person says so: where it sits is only the
  // server's word, and the new keys open for everyone the parent's open for.
  async keyFor( collection , create , depth = 0 ) {
    if ( this.folderKeys.has( collection ) ) return this.folderKeys.get( collection );
    if ( depth > 64 ) throw DocsCrypto.fail( "corrupt" );
    await this.loadEpochs();
    let folder = DocsTree.get( collection );
    if ( !folder ) {
      await DocsTree.refresh();
      folder = DocsTree.get( collection );
    }
    if ( !folder ) {
      if ( !create || !this.key ) throw DocsCrypto.fail( "no_folder" );
      return this.createTopLevel( collection );
    }
    // Given its first keys by a rotation still under way: those are its
    // new keys (nextKeyFor), and it has no others.
    if ( !folder.lock && folder.next_lock ) throw DocsCrypto.fail( "rotating" );
    if ( !folder.lock && create && create !== "share" && this.key && folder.parent !== "" ) {
      const parent = DocsTree.get( folder.parent );
      const question = this.say( "docs.keys_under_parent_question" , { name: folder.name , parent: parent ? parent.name : folder.parent } );
      if ( !( await Dom.confirm( question ) ) ) throw DocsCrypto.fail( "cancelled" );
    }
    const holder = await this.holderFor( folder.parent , create , depth + 1 );
    let key;
    if ( folder.lock ) {
      key = DocsCrypto.openLock( folder.lock , collection , holder );
      key.owned = this.ownedUnder( holder , folder.lock , collection );
      await this.checkLockEpoch( folder , key , depth );
    } else {
      if ( !create ) throw DocsCrypto.fail( "corrupt" );
      key = DocsCrypto.generateCollectionKey( collection , this.freshEpoch( collection ) );
      // Tagged as the owner's only at the top level, as the Go client does:
      // under a parent, a folder with no lockbox could be anyone's who holds
      // the parent's keys. Asked about above, so writing there asks no more.
      const own = folder.parent === "" ? this.ownTag( key ) : "";
      key.owned = own !== "";
      if ( !key.owned ) this.sharedAllowed.add( collection + "\n" + DocsCrypto.b64( key.id ) );
      try {
        const done = await Api.updateCollection( collection , { lock: DocsCrypto.sealLock( key , holder , null , null , own ) } );
        folder.lock = done.lock;
      } catch ( error ) {
        if ( !( error.payload && error.payload.error === "lock_exists" ) ) throw error;
        // Someone else gave it keys first: use theirs.
        await DocsTree.refresh();
        const now = DocsTree.get( collection );
        key = DocsCrypto.openLock( now.lock , collection , holder );
        key.owned = this.ownedUnder( holder , now.lock , collection );
        await this.checkLockEpoch( now , key , depth );
      }
      await this.noteEpoch( collection , "lock" , key.epoch );
    }
    this.folderKeys.set( collection , key );
    return key;
  },

  // Whether keys opened from lock (collection's) are the account's own: the
  // lockbox carries the master key's owner tag, and so does every lockbox
  // above it (holder is the master key, or keys that are owned). False
  // without the master key.
  ownedUnder( holder , lock , collection ) {
    if ( !this.key || !DocsCrypto.owns( this.key , lock , collection ) ) return false;
    return holder === this.key || holder.owned === true;
  },

  // ---- lockbox epochs (README.md, "Rotating keys") -------------------------
  //
  // Every lockbox carries a signed epoch, and a rotation's new lockbox one
  // more than the old. This device remembers the highest it has seen for
  // each collection, as a lock and as a next_lock, and refuses anything
  // below that, so a server cannot serve a lockbox from before a rotation
  // again once this device has seen the rotation. A device that never saw it
  // (new, or its storage cleared) cannot tell.

  epochAccount() {
    if ( this.scope ) return "token:" + DocsCrypto.b64( this.scope.key.id );
    return this.me && this.me.id !== undefined ? "user:" + this.me.id : null;
  },

  epochKey( collection ) {
    return this.epochAccount() + "\n" + collection;
  },

  // The epoch store: one IndexedDB object store, or null where there is
  // none (memory only then).
  async epochStore() {
    if ( this.epochDb !== undefined ) return this.epochDb;
    this.epochDb = await new Promise( ( resolve ) => {
      try {
        const request = indexedDB.open( "e2eedb-epochs" , 1 );
        request.onupgradeneeded = () => request.result.createObjectStore( "epochs" );
        request.onsuccess = () => resolve( request.result );
        request.onerror = () => resolve( null );
        request.onblocked = () => resolve( null );
      } catch ( error ) {
        resolve( null );
      }
    } );
    return this.epochDb;
  },

  // Reads what this device remembers for the account, once per account.
  async loadEpochs() {
    const account = this.epochAccount();
    if ( account === null || this.epochsFor === account ) return;
    if ( this.epochsLoading && this.epochsLoading.account === account ) return this.epochsLoading.done;
    const done = ( async () => {
      const found = new Map();
      const db = await this.epochStore();
      if ( db ) {
        await new Promise( ( resolve ) => {
          try {
            const range = IDBKeyRange.bound( account + "\n" , account + "\n\uffff" );
            const request = db.transaction( "epochs" , "readonly" ).objectStore( "epochs" ).openCursor( range );
            request.onsuccess = () => {
              const cursor = request.result;
              if ( !cursor ) return resolve();
              found.set( String( cursor.key ).slice( account.length + 1 ) , cursor.value );
              cursor.continue();
            };
            request.onerror = () => resolve();
          } catch ( error ) {
            resolve();
          }
        } );
      }
      // Anything seen while loading stays.
      for ( const [ collection , seen ] of this.epochs ) {
        const had = found.get( collection ) || { lock: 0 , next: 0 };
        found.set( collection , { lock: Math.max( had.lock || 0 , seen.lock || 0 ) , next: Math.max( had.next || 0 , seen.next || 0 ) } );
      }
      this.epochs = found;
      this.epochsFor = account;
    } )();
    this.epochsLoading = { account: account , done: done };
    return done;
  },

  epochOf( collection ) {
    const seen = this.epochs.get( collection ) || {};
    return { lock: seen.lock || 0 , next: seen.next || 0 };
  },

  // Remembers that collection had a lockbox (kind "lock" or "next") at epoch.
  async noteEpoch( collection , kind , epoch ) {
    const seen = this.epochOf( collection );
    if ( seen[ kind ] >= epoch ) return;
    seen[ kind ] = epoch;
    this.epochs.set( collection , seen );
    if ( this.epochAccount() === null ) return;
    const db = await this.epochStore();
    if ( !db ) return;
    await new Promise( ( resolve ) => {
      try {
        const done = db.transaction( "epochs" , "readwrite" );
        done.objectStore( "epochs" ).put( seen , this.epochKey( collection ) );
        done.oncomplete = () => resolve();
        done.onerror = () => resolve();
        done.onabort = () => resolve();
      } catch ( error ) {
        resolve();
      }
    } );
  },

  // An epoch for keys made now for collection: above any it has had here.
  freshEpoch( collection ) {
    const seen = this.epochOf( collection );
    return DocsCrypto.freshEpoch( Math.max( seen.lock , seen.next ) );
  },

  // Refuses keys opened from folder's lock when this device has seen newer:
  // a lock below the highest lock it saw, or below the highest next_lock it
  // saw unless that rotation is still shown as under way (a next_lock one
  // epoch on, which opens). Then remembers it.
  async checkLockEpoch( folder , key , depth ) {
    const seen = this.epochOf( folder.id );
    if ( key.epoch < seen.lock ) throw DocsCrypto.fail( "rolled_back" );
    if ( key.epoch < seen.next ) {
      const next = folder.next_lock ? await this.nextKeyFor( folder.id , depth ) : null;
      if ( !next || next.epoch !== key.epoch + 1 ) throw DocsCrypto.fail( "rolled_back" );
    }
    await this.noteEpoch( folder.id , "lock" , key.epoch );
  },

  // Forget this device: drops every epoch this device remembers, for every
  // account.
  async forgetDevice() {
    this.epochs = new Map();
    this.epochsFor = null;
    this.epochsLoading = null;
    const db = await this.epochStore();
    if ( !db ) return;
    await new Promise( ( resolve ) => {
      try {
        const done = db.transaction( "epochs" , "readwrite" );
        done.objectStore( "epochs" ).clear();
        done.oncomplete = () => resolve();
        done.onerror = () => resolve();
      } catch ( error ) {
        resolve();
      }
    } );
  },

  // collection's new keys while its keys are being rotated, from its
  // next_lock; null when they are not. They are wrapped for the parent's new
  // keys when the parent is being rotated too, else for its keys.
  async nextKeyFor( collection , depth = 0 ) {
    if ( this.folderNextKeys.has( collection ) ) return this.folderNextKeys.get( collection );
    if ( depth > 64 ) throw DocsCrypto.fail( "corrupt" );
    const folder = DocsTree.get( collection );
    if ( !folder || !folder.next_lock ) return null;
    const parent = folder.parent === "" ? null : DocsTree.get( folder.parent );
    await this.loadEpochs();
    const holder = parent && parent.next_lock ? await this.nextKeyFor( parent.id , depth + 1 ) : await this.holderFor( folder.parent , false , depth + 1 );
    const key = DocsCrypto.openLock( folder.next_lock , collection , holder );
    key.owned = this.ownedUnder( holder , folder.next_lock , collection );
    // A next_lock below one already seen is an older rotation's.
    const seen = this.epochOf( collection );
    if ( key.epoch < seen.next || key.epoch < seen.lock ) throw DocsCrypto.fail( "rolled_back" );
    await this.noteEpoch( collection , "next" , key.epoch );
    this.folderNextKeys.set( collection , key );
    return key;
  },

  // Forgets every collection key opened, for when they may have been
  // rotated. With an access token, its own collection's stay: they came
  // with it.
  forgetKeys() {
    this.folderKeys.clear();
    this.folderNextKeys.clear();
    if ( this.scope ) this.folderKeys.set( this.scope.key.collection , this.scope.key );
  },

  // The keys that open a collection envelope in collection: the ones it
  // names, old or new. Keys it names that are not held may have been rotated
  // in since, so the tree is fetched again once before it is wrong_key.
  async openingKey( collection , body ) {
    const named = DocsCrypto.envelopeKeyId( body );
    const matching = () => [ this.folderNextKeys.get( collection ) , this.folderKeys.get( collection ) ]
      .find( ( key ) => key && DocsCrypto.b64( key.id ) === named );
    let key = matching();
    if ( key ) return key;
    await this.loadKeys( collection );
    key = matching();
    if ( key ) return key;
    this.forgetKeys();
    await DocsTree.refresh();
    await this.loadKeys( collection );
    key = matching();
    if ( !key ) throw DocsCrypto.fail( "wrong_key" );
    return key;
  },

  // Opens what collection has: its keys and, mid-rotation, its new ones.
  async loadKeys( collection ) {
    await this.nextKeyFor( collection );
    const folder = DocsTree.get( collection );
    if ( folder && folder.lock ) await this.keyFor( collection , false );
  },

  // What wraps a collection under parent: the master key at the top level,
  // otherwise parent's keys.
  async holderFor( parent , create , depth = 0 ) {
    if ( parent !== "" ) return this.keyFor( parent , create , depth );
    if ( !this.key ) throw DocsCrypto.fail( "wrong_key" );
    return this.key;
  },

  // A lockbox for a new collection id under parent, and its keys. null when
  // there is no key to make one with: it gets keys when first written to.
  async newLock( id , parent ) {
    if ( !this.hasKey() ) return null;
    await this.loadEpochs();
    const holder = await this.holderFor( parent , true );
    const key = DocsCrypto.generateCollectionKey( id , this.freshEpoch( id ) );
    // The owner tag only under keys that are the account's own: a folder
    // made inside one an access key made stays the sharee's side.
    key.owned = !!this.key && ( holder === this.key || holder.owned === true );
    await this.noteEpoch( id , "lock" , key.epoch );
    return { key: key , lock: DocsCrypto.sealLock( key , holder , null , null , key.owned ? this.ownTag( key ) : "" ) };
  },

  // The owner tag for keys this screen made, "" without the master key.
  ownTag( key ) {
    return this.key ? DocsCrypto.ownTag( this.key , key.collection , key.id ) : "";
  },

  // Whether folder's keys were made through an access token rather than with
  // the master key: its lockbox, or one above it, has no owner tag. Only the
  // master key can tell; false without it, and for a folder with no keys
  // yet.
  madeByShare( folder ) {
    if ( !this.key || !( folder.lock || folder.next_lock ) ) return false;
    if ( !this.ownedLocks ) this.ownedLocks = new Map();
    const owns = ( at ) => {
      const lock = at.lock || at.next_lock || "";
      const cached = at.id + "\n" + lock;
      if ( !this.ownedLocks.has( cached ) ) this.ownedLocks.set( cached , lock !== "" && DocsCrypto.owns( this.key , lock , at.id ) );
      return this.ownedLocks.get( cached );
    };
    for ( let at = folder , steps = 0; at; at = at.parent === "" ? null : DocsTree.get( at.parent ) , steps++ ) {
      if ( steps > 64 || !owns( at ) ) return true;
    }
    return false;
  },

  // A top-level collection with keys, named after its id (or "id (2)"...).
  async createTopLevel( id ) {
    await this.loadEpochs();
    const key = DocsCrypto.generateCollectionKey( id , this.freshEpoch( id ) );
    key.owned = true;
    await this.noteEpoch( id , "lock" , key.epoch );
    const lock = DocsCrypto.sealLock( key , this.key , null , null , this.ownTag( key ) );
    for ( let n = 1; ; n++ ) {
      try {
        await Api.createCollection( { id: id , name: n === 1 ? id : id + " (" + n + ")" , lock: lock } );
        break;
      } catch ( error ) {
        if ( !( error.payload && error.payload.error === "name_taken" ) || n > 50 ) throw error;
      }
    }
    await DocsTree.refresh();
    this.folderKeys.set( id , key );
    return key;
  },

  // A collection's lockbox wrapped again for a new parent, for a move. null
  // when it has none (nothing to re-wrap).
  async rewrapLock( id , parent ) {
    const folder = DocsTree.get( id );
    if ( !folder || !folder.lock ) return null;
    const key = await this.keyFor( id , false );
    // The owner tag goes along as it was: a move does not change who made
    // the keys.
    return DocsCrypto.sealLock( key , await this.holderFor( parent , true ) , null , null , DocsCrypto.lockOwn( folder.lock ) );
  },

  // A body (base64 envelope) in, JSON text out: a private envelope with the
  // master key, a collection envelope with the collection's keys.
  async openBody( collection , id , body ) {
    if ( DocsCrypto.envelopeKind( body ) === DocsCrypto.ENVELOPE_MASTER ) {
      if ( !this.key ) throw DocsCrypto.fail( "wrong_key" );
      return DocsCrypto.open( this.key , collection , id , body );
    }
    return DocsCrypto.openCollection( await this.openingKey( collection , body ) , id , body );
  },

  // JSON text in, a collection envelope sealed and signed for collection/id
  // out: with its new keys while they are being rotated.
  //
  // With the master key, a folder whose keys are not the account's own
  // (made through an access key, or under one) is written to only once the
  // person says so, as the Go client needs AllowShared: whoever made those
  // keys reads what is written with them.
  async sealBody( collection , id , text ) {
    const key = ( await this.nextKeyFor( collection ) ) || ( await this.keyFor( collection , true ) );
    await this.askShared( collection , key );
    return DocsCrypto.sealCollection( key , id , text );
  },

  async askShared( collection , key ) {
    if ( !this.key || key.owned ) return;
    const allowed = collection + "\n" + DocsCrypto.b64( key.id );
    if ( this.sharedAllowed.has( allowed ) ) return;
    const folder = DocsTree.get( collection );
    if ( !( await Dom.confirm( this.say( "docs.write_shared_question" , { name: folder ? folder.name : collection } ) ) ) ) throw DocsCrypto.fail( "cancelled" );
    this.sharedAllowed.add( allowed );
  },

  // Runs send( sealed ) with text sealed for collection/id, and once more
  // with freshly fetched keys if the server says they were rotated since
  // (stale_key).
  async sealAndSend( collection , id , text , send ) {
    try {
      return await send( await this.sealBody( collection , id , text ) );
    } catch ( error ) {
      if ( !( error.status === 409 && error.payload && error.payload.error === "stale_key" ) ) throw error;
      this.forgetKeys();
      await DocsTree.refresh();
      return send( await this.sealBody( collection , id , text ) );
    }
  },

  // ---- links to a document -------------------------------------------------

  // /docs/<collection>/<id>: the page, plus the two names the API takes, so
  // the same link works for a person (it opens here) and for an agent (it
  // names GET /api/collections/<collection>/docs/<id>). Never the key. The
  // server answers the path with this page (routes.go).
  docUrl( collection , id ) {
    return window.location.origin + this.docPath( collection , id );
  },

  docPath( collection , id ) {
    return "/docs/" + encodeURIComponent( collection ) + "/" + encodeURIComponent( id );
  },

  linked() {
    const parts = window.location.pathname.split( "/" );
    if ( parts.length !== 4 || parts[ 1 ] !== "docs" || parts[ 2 ] === "" || parts[ 3 ] === "" ) return null;
    try {
      return { collection: decodeURIComponent( parts[ 2 ] ) , id: decodeURIComponent( parts[ 3 ] ) };
    } catch ( error ) {
      return null;
    }
  },

  // The address bar follows the open document, so it is always a link to it.
  showPath( path ) {
    if ( window.location.pathname === path ) return;
    history.replaceState( history.state , "" , path + ( path === "/" ? "#docs" : "" ) );
  },

  // Shows the linked document's collection, and opens the document once there
  // is a key. Locked, it waits: unlockWith opens it.
  async openLinked() {
    const link = this.linked();
    this.pendingLink = null;
    if ( !link ) return;
    if ( !DocsTree.folders || !DocsTree.folders.has( link.collection ) ) {
      App.showError( this.say( "docs.link_missing" , { id: link.id } ) );
      return;
    }
    if ( this.collection !== link.collection ) await this.showCollection( link.collection );
    if ( this.open && this.open.collection === link.collection && this.open.id === link.id ) return;
    if ( this.hasKey() ) {
      await this.openDoc( link.collection , link.id );
      return;
    }
    this.pendingLink = link;
    Dom.toast( this.say( "docs.unlock_to_open" , { id: link.id } ) , "ok" );
    Dom.reveal( Dom.get( "docs-unlock-card" ) );
  },

  async copyUrl( collection , id ) {
    const url = this.docUrl( collection , id );
    try {
      await navigator.clipboard.writeText( url );
    } catch ( error ) {
      // navigator.clipboard needs a secure context; plain http lands here.
      const field = Dom.el( "textarea" , { attrs: { readonly: "" , "aria-hidden": "true" } } );
      field.value = url;
      field.style.position = "fixed";
      field.style.opacity = "0";
      document.body.appendChild( field );
      field.select();
      const done = document.execCommand( "copy" );
      field.remove();
      if ( !done ) {
        window.prompt( I18n.get( "ui.copy_hint" ) , url );
        return;
      }
    }
    Dom.toast( this.say( "docs.url_copied" , { id: id } ) , "ok" );
  },

  // ---- formatting ----------------------------------------------------------

  size( bytes ) {
    if ( bytes < 1024 ) return bytes + " B";
    if ( bytes < 1024 * 1024 ) return ( bytes / 1024 ).toFixed( 1 ) + " KB";
    if ( bytes < 1024 * 1024 * 1024 ) return ( bytes / 1024 / 1024 ).toFixed( 1 ) + " MB";
    return ( bytes / 1024 / 1024 / 1024 ).toFixed( 1 ) + " GB";
  },

  say( key , values ) {
    let text = I18n.get( key );
    Object.entries( values || {} ).forEach( ( entry ) => {
      text = text.replace( "{" + entry[ 0 ] + "}" , () => String( entry[ 1 ] ) );
    } );
    return text;
  },

  // A refusal worded for this screen: a 409 names the version there now.
  failed( error ) {
    if ( error.status === 409 && error.payload && error.payload.error === "version_conflict" ) {
      return this.say( "docs.error_conflict" , { version: error.payload.current_version } );
    }
    if ( error.payload && error.payload.error === "rotating" ) return I18n.get( "docs.error_rotating" );
    if ( error.payload && error.payload.error === "doc_too_large" ) return this.say( "docs.error_too_large" , { size: this.size( error.payload.max_bytes ) } );
    if ( error.payload && error.payload.error === "quota_exceeded" ) return this.say( "docs.error_quota" , { size: this.size( error.payload.quota_bytes ) } );
    // With no cap of the share's own (0), the account's limit was hit:
    // the answer does not say what it is.
    if ( error.payload && error.payload.error === "share_quota_exceeded" ) {
      return error.payload.quota_bytes ? this.say( "docs.error_share_quota" , { size: this.size( error.payload.quota_bytes ) } ) : I18n.get( "docs.error_share_full" );
    }
    if ( error.payload && error.payload.error === "share_too_many_collections" ) {
      return error.payload.max_collections ? this.say( "docs.error_share_too_many" , { count: error.payload.max_collections } ) : I18n.get( "docs.error_share_full" );
    }
    return error.message;
  },

  // ---- unlocking -----------------------------------------------------------

  renderLock() {
    const unlocked = this.hasKey();
    Dom.show( Dom.get( "docs-locked" ) , !unlocked );
    Dom.show( Dom.get( "docs-unlocked" ) , unlocked );
    Dom.show( Dom.get( "docs-passphrase-card" ) , this.key !== null );
    Dom.show( Dom.get( "docs-passphrase-unlock-form" ) , !unlocked && this.keyring !== null );
    Dom.show( Dom.get( "docs-new-button" ) , this.canWrite() );
    Dom.show( Dom.get( "docs-folder-new" ) , this.scope === null );
    if ( this.scope ) {
      const name = DocsTree.nameOf( this.scope.key.collection );
      Dom.text( Dom.get( "docs-unlocked-text" ) , this.say( this.canWrite() ? "docs.scoped_write" : "docs.scoped_read" , { name: name } ) );
      Dom.text( Dom.get( "docs-lock-button" ) , I18n.get( "docs.scoped_leave" ) );
    } else if ( unlocked ) {
      Dom.text( Dom.get( "docs-unlocked-text" ) , this.say( "docs.unlocked" , { id: DocsCrypto.keyId( this.key ) } ) );
    }
    this.renderPassphraseStatus();
  },

  renderPassphraseStatus() {
    let text = I18n.get( "docs.passphrase_none" );
    if ( this.keyring ) {
      text = this.say( "docs.passphrase_set" , { when: new Date( this.keyring.updated_at ).toLocaleString() } );
      let ring = null;
      try { ring = JSON.parse( this.keyring.keyring ); } catch ( error ) { ring = null; }
      if ( this.key && ring && ring.key_id !== DocsCrypto.keyId( this.key ) ) text += " " + I18n.get( "docs.passphrase_other_key" );
    }
    Dom.text( Dom.get( "docs-passphrase-status" ) , text );
  },

  async refreshKeyring() {
    try {
      this.keyring = await Api.keyring();
    } catch ( error ) {
      if ( error.status !== 404 ) throw error;
      this.keyring = null;
    }
    this.renderLock();
  },

  unlockWith( key ) {
    this.key = key;
    this.forgetKeys();
    this.ownedLocks = null;
    this.sharedAllowed.clear();
    this.renderLock();
    // The tree can now mark folders made through an access key.
    DocsTree.render();
    // The document list can now say which ones this key opens.
    if ( this.collection ) this.refreshDocs();
    const link = this.pendingLink;
    this.pendingLink = null;
    if ( link ) this.openDoc( link.collection , link.id );
  },

  async onUnlockWithKey( event ) {
    event.preventDefault();
    const input = Dom.get( "docs-key-input" );
    Dom.clearFieldError( input );
    try {
      await DocsCrypto.load();
    } catch ( error ) {
      App.showError( error.message );
      return;
    }
    const key = DocsCrypto.parseKey( input.value );
    if ( key === null ) {
      Dom.fieldError( input , I18n.get( "docs.error_key_format" ) );
      return;
    }
    input.value = "";
    this.unlockWith( key );
  },

  // Argon2id holds the page for a few seconds; the pause first lets the
  // button show it is busy before that starts.
  pause() {
    return new Promise( ( resolve ) => window.setTimeout( resolve , 50 ) );
  },

  async onUnlockWithPassphrase( event ) {
    event.preventDefault();
    const input = Dom.get( "docs-passphrase-unlock-input" );
    Dom.clearFieldError( input );
    try {
      await DocsCrypto.load();
      await this.refreshKeyring();
      if ( this.keyring === null ) return;
      await this.pause();
      const started = performance.now();
      const key = DocsCrypto.unwrap( this.keyring.keyring , input.value );
      this.lastPassphraseMs = Math.round( performance.now() - started );
      input.value = "";
      this.unlockWith( key );
    } catch ( error ) {
      if ( error.code ) {
        Dom.fieldError( input , error.message );
        return;
      }
      App.showError( error.message );
    }
  },

  async onForgetDevice() {
    if ( !( await Dom.confirm( I18n.get( "docs.forget_device_question" ) ) ) ) return;
    await this.forgetDevice();
    Dom.toast( I18n.get( "docs.forget_device_done" ) , "ok" );
  },

  async onGenerate() {
    try {
      await DocsCrypto.load();
    } catch ( error ) {
      App.showError( error.message );
      return;
    }
    Dom.text( Dom.get( "docs-new-key-value" ) , DocsCrypto.generateKey() );
    Dom.show( Dom.get( "docs-new-key-box" ) , true );
  },

  onUseNewKey() {
    const key = DocsCrypto.parseKey( Dom.get( "docs-new-key-value" ).textContent );
    this.clearNewKey();
    if ( key ) this.unlockWith( key );
  },

  // Takes a generated master key out of the page, used or not.
  clearNewKey() {
    Dom.text( Dom.get( "docs-new-key-value" ) , "" );
    Dom.show( Dom.get( "docs-new-key-box" ) , false );
  },

  lock() {
    this.clearNewKey();
    if ( this.scope ) {
      App.leaveAccess();
      return;
    }
    this.key = null;
    this.forgetKeys();
    this.ownedLocks = null;
    this.sharedAllowed.clear();
    this.hideShared();
    this.closeEditor();
    this.renderLock();
    DocsTree.render();
    if ( this.collection ) this.refreshDocs();
  },

  async onSetPassphrase( event ) {
    event.preventDefault();
    const first = Dom.get( "docs-passphrase-new" );
    const again = Dom.get( "docs-passphrase-again" );
    Dom.clearFieldError( again );
    if ( first.value !== again.value ) {
      Dom.fieldError( again , I18n.get( "docs.error_passphrase_mismatch" ) );
      return;
    }
    try {
      await this.refreshKeyring();
      await this.pause();
      const started = performance.now();
      const text = DocsCrypto.wrap( this.key , first.value );
      this.lastPassphraseMs = Math.round( performance.now() - started );
      await Api.setKeyring( text , this.keyring ? this.keyring.version : 0 );
      first.value = "";
      again.value = "";
      Undo.saved( Dom.get( "docs-passphrase-form" ) );
      Dom.toast( I18n.get( "docs.passphrase_saved" ) , "ok" );
      await this.refreshKeyring();
    } catch ( error ) {
      App.showError( this.failed( error ) );
    }
  },

  // ---- lists ---------------------------------------------------------------

  async showCollection( id ) {
    // A folder the server puts in a loop of parents (A in B in A) is not
    // shown: its place makes no sense, so neither would its keys.
    if ( DocsTree.get( id ) && DocsTree.broken( id ) ) {
      App.showError( I18n.get( "docs.error_tree_broken" ) );
      return;
    }
    if ( this.collection !== id ) this.picked.clear();
    this.collection = id;
    DocsTree.reveal( id );
    DocsTree.render();
    this.renderHeading();
    Dom.show( Dom.get( "docs-list-body" ) , true );
    Dom.show( Dom.get( "docs-list-none" ) , false );
    await this.refreshDocs();
    // On a phone the list is below the tree: take the reader there.
    if ( !window.matchMedia( "(min-width: 992px)" ).matches ) Dom.reveal( Dom.get( "docs-list-card" ) , "start" );
  },

  // No folder chosen: the list says to pick one.
  showNothing() {
    this.collection = null;
    this.picked.clear();
    Dom.text( Dom.get( "docs-list-heading" ) , I18n.get( "docs.docs_heading_none" ) );
    Dom.show( Dom.get( "docs-list-body" ) , false );
    Dom.show( Dom.get( "docs-list-none" ) , true );
    Dom.show( Dom.get( "docs-new-button" ) , this.canWrite() );
    if ( typeof DocsTree !== "undefined" ) DocsTree.render();
  },

  renderHeading() {
    if ( !this.collection ) return;
    const heading = Dom.get( "docs-list-heading" );
    Dom.text( heading , this.say( "docs.docs_heading" , { name: DocsTree.nameOf( this.collection ) } ) );
    heading.title = DocsTree.path( this.collection ) + " (" + this.collection + ")";
  },

  // The badge a row gets when its body is sealed under a key this page does
  // not hold: another master key (a private envelope), or not its
  // collection's.
  keyBadge( row ) {
    if ( !this.hasKey() || !row.body ) return null;
    const named = DocsCrypto.envelopeKeyId( row.body );
    let mine = "";
    if ( DocsCrypto.envelopeKind( row.body ) === DocsCrypto.ENVELOPE_MASTER ) {
      mine = this.key ? DocsCrypto.keyId( this.key ) : "";
    } else {
      const at = row.collection || this.collection;
      const key = this.folderKeys.get( at );
      if ( !key ) return null;
      mine = DocsCrypto.b64( key.id );
      // Mid-rotation, its new keys open it too.
      const next = this.folderNextKeys.get( at );
      if ( next && named === DocsCrypto.b64( next.id ) ) return null;
    }
    if ( named === mine ) return null;
    return Dom.badge( I18n.get( "docs.other_key" ) , "warning" );
  },

  async refreshDocs() {
    const collection = this.collection;
    if ( !collection ) return;
    const body = Dom.get( "docs-table" ).querySelector( "tbody" );
    const seen = new Set();
    // With a key, the folder's keys first, so the rows can say which bodies
    // they open.
    if ( this.hasKey() ) {
      try { await this.loadKeys( collection ); } catch ( error ) { /* no keys yet, or not this page's */ }
    }
    const writable = this.canWrite();
    await Pager.load( "docs-table" , "docs" , ( offset ) => Api.docs( collection , offset , this.pageSize , this.hasKey() ) , ( row ) => {
      seen.add( row.id );
      const badge = this.keyBadge( row );
      const pick = Dom.el( "input" , {
        class: "form-check-input",
        attrs: { type: "checkbox" , "aria-label": this.say( "docs.pick_doc" , { id: row.id } ) },
        on: { change: ( event ) => this.pick( row.id , event.target.checked ) },
      } );
      pick.checked = this.picked.has( row.id );
      const tr = Dom.el( "tr" , { class: "docs-doc-row" , attrs: { "data-key": "doc-" + row.id , "data-id": row.id } , children: [
        Dom.el( "td" , { class: "docs-pick" , children: [ pick ] } ),
        Dom.el( "td" , { class: "font-monospace text-break" , children: [
          Dom.el( "i" , { class: "bi bi-grip-vertical text-body-tertiary me-1 docs-grip" , attrs: { "aria-hidden": "true" } } ),
          Dom.el( "span" , { text: row.id } ),
        ] } ),
        Dom.el( "td" , { children: [ Dom.el( "span" , { text: row.version } ) ].concat( badge ? [ document.createTextNode( " " ) , badge ] : [] ) } ),
        Dom.el( "td" , { text: this.size( row.size ) } ),
        Dom.el( "td" , { children: [ Dom.when( row.updated_at , "" ) ] } ),
        Dom.el( "td" , { children: [ Dom.rowActions( row.id , [
          Dom.el( "button" , {
            class: "btn btn-sm btn-outline-primary",
            text: I18n.get( "docs.open_button" ),
            attrs: { "aria-label": this.say( "docs.open_doc" , { id: row.id } ) },
            on: { click: () => this.openDoc( collection , row.id ) },
          } ),
          writable ? Dom.el( "button" , {
            class: "btn btn-sm btn-outline-secondary",
            text: I18n.get( "docs.move_to_button" ),
            attrs: { "aria-label": this.say( "docs.move_doc" , { id: row.id } ) },
            on: { click: () => this.moveDocsTo( [ row.id ] ) },
          } ) : null,
          Dom.el( "button" , {
            class: "btn btn-sm btn-outline-secondary",
            text: I18n.get( "docs.copy_url_button" ),
            attrs: { "aria-label": this.say( "docs.copy_url_doc" , { id: row.id } ) },
            on: { click: () => this.copyUrl( collection , row.id ) },
          } ),
          writable ? Dom.el( "button" , {
            class: "btn btn-sm btn-outline-danger",
            text: I18n.get( "docs.delete_button" ),
            attrs: { "aria-label": this.say( "docs.delete_doc" , { id: row.id } ) },
            on: { click: () => this.remove( collection , row.id ) },
          } ) : null,
        ].filter( Boolean ) , 1 ) ] } ),
      ] } );
      // Dragging a ticked row takes every ticked one with it.
      if ( writable ) Drag.attach( tr , {
        icon: "bi-file-earmark-lock",
        payload: () => ( { kind: "docs" , from: collection , ids: this.picked.has( row.id ) ? Array.from( this.picked ) : [ row.id ] } ),
        label: () => this.picked.has( row.id ) && this.picked.size > 1 ? this.say( "docs.drag_many" , { count: this.picked.size } ) : row.id,
        target: ( under , payload , point ) => DocsTree.dropTarget( under , payload , point ),
        drop: ( target , payload ) => DocsTree.onDrop( target , payload ),
        scroller: Dom.get( "docs-tree-scroll" ),
      } );
      body.appendChild( tr );
    } , 0 );
    // Ticks on documents that went away go with them.
    this.picked.forEach( ( id ) => { if ( !seen.has( id ) ) this.picked.delete( id ); } );
    this.renderPicked();
  },

  pick( id , on ) {
    if ( on ) this.picked.add( id );
    else this.picked.delete( id );
    this.renderPicked();
  },

  pickAll( on ) {
    Dom.get( "docs-table" ).querySelectorAll( "tbody tr[data-id]" ).forEach( ( tr ) => {
      const box = tr.querySelector( ".docs-pick input" );
      if ( box ) box.checked = on;
      this.pick( tr.dataset.id , on );
    } );
  },

  renderPicked() {
    const count = this.picked.size;
    const button = Dom.get( "docs-move-button" );
    Dom.show( button , count > 0 );
    Dom.text( button.querySelector( "span" ) , this.say( "docs.move_picked" , { count: count } ) );
    const all = Dom.get( "docs-pick-all" );
    const rows = Dom.get( "docs-table" ).querySelectorAll( "tbody tr[data-id]" ).length;
    all.checked = rows > 0 && count === rows;
    all.indeterminate = count > 0 && count < rows;
  },

  async afterChange( collection ) {
    await DocsTree.refresh();
    if ( this.collection === collection ) await this.refreshDocs();
  },

  // ---- moving documents ----------------------------------------------------

  // Asks where to, then moves ids out of the open folder.
  async moveDocsTo( ids ) {
    if ( !ids.length || !this.needKey() ) return;
    const from = this.collection;
    // The open folder is where they are already; its subfolders are fine.
    const options = DocsTree.choices( [] ).filter( ( option ) => option.value !== from );
    if ( !options.length ) {
      Dom.toast( I18n.get( "docs.move_nowhere" ) , "error" );
      return;
    }
    let chosen = null;
    await Dom.form( {
      title: ids.length === 1 ? this.say( "docs.move_doc_title" , { id: ids[ 0 ] } ) : this.say( "docs.move_many_title" , { count: ids.length } ),
      submit: I18n.get( "docs.move_button" ),
      fields: [ { name: "to" , label: I18n.get( "docs.move_into" ) , type: "select" , options: options } ],
      save: async ( values ) => { chosen = values.to; },
    } );
    if ( chosen ) await this.moveDocs( from , ids , chosen );
  },

  // Moves one document: opens it, seals it for its new place, and swaps them
  // on the server in one step. Answers the new version.
  async moveOne( from , id , to , ifVersion ) {
    const doc = await Api.doc( from , id );
    if ( ifVersion !== undefined && doc.version !== ifVersion ) {
      const error = new Error( "version_conflict" );
      error.status = 409;
      error.payload = { error: "version_conflict" , current_version: doc.version };
      throw error;
    }
    const text = await this.openBody( from , id , doc.body );
    const moved = await this.sealAndSend( to , id , text , ( sealed ) => Api.moveDoc( from , id , to , sealed , doc.version ) );
    return moved.doc.version;
  },

  // Moves ids from one folder to another, one by one, and records one undo
  // for all that moved. Stops at the first that fails and says which.
  async moveDocs( from , ids , to ) {
    if ( !this.needKey() || from === to ) return;
    const moved = [];
    let failure = null;
    for ( const id of ids ) {
      try {
        moved.push( { id: id , version: await this.moveOne( from , id , to ) } );
      } catch ( error ) {
        failure = this.say( "docs.move_failed" , { id: id , reason: error.code ? error.message : this.failed( error ) } );
        if ( error.status === 409 && error.payload && error.payload.live ) failure = this.say( "docs.move_taken" , { id: id } );
        break;
      }
    }
    if ( moved.length ) {
      const name = DocsTree.nameOf( to );
      const label = moved.length === 1
        ? this.say( "docs.undo_move" , { id: moved[ 0 ].id , name: name } )
        : this.say( "docs.undo_move_many" , { count: moved.length , name: name } );
      Undo.record( {
        label: label,
        toast: true,
        undo: async () => {
          if ( !this.hasKey() ) throw new Error( I18n.get( "docs.unlock_first" ) );
          for ( const entry of moved ) entry.version = await this.moveOne( to , entry.id , from , entry.version );
          await this.afterMove( from , to );
        },
        redo: async () => {
          if ( !this.hasKey() ) throw new Error( I18n.get( "docs.unlock_first" ) );
          for ( const entry of moved ) entry.version = await this.moveOne( from , entry.id , to , entry.version );
          await this.afterMove( from , to );
        },
      } );
      moved.forEach( ( entry ) => {
        this.picked.delete( entry.id );
        if ( this.open && this.open.collection === from && this.open.id === entry.id ) this.closeEditor();
      } );
    }
    if ( failure ) Dom.toast( failure , "error" );
    await this.afterMove( from , to );
  },

  async afterMove( from , to ) {
    await DocsTree.refresh();
    if ( this.collection === from || this.collection === to ) await this.refreshDocs();
  },

  // ---- the editor ----------------------------------------------------------

  needKey() {
    if ( this.hasKey() ) return true;
    Dom.toast( I18n.get( "docs.unlock_first" ) , "error" );
    Dom.reveal( Dom.get( "docs-unlock-card" ) );
    Dom.get( "docs-key-input" ).focus( { preventScroll: true } );
    return false;
  },

  // vanilla-jsoneditor (vendor/jsoneditor) beside the textarea, which it
  // hides: tree, text and table views, search, sort, transform, undo, and
  // Ctrl+S (Cmd+S) to save. It is an ES module, loaded here with import();
  // if it fails the textarea stays and still works. The view someone picks is
  // kept in this browser.
  //
  // Transform queries run as JSONQuery, JSONPath or JMESPath, never as
  // JavaScript or Lodash: those two compile with new Function(), which this
  // app's CSP (script-src 'self', no 'unsafe-eval') refuses.
  async setupEditor() {
    let lib;
    try {
      lib = await import( "/vendor/jsoneditor/jsoneditor.js" );
    } catch ( error ) {
      console.error( "JSON editor did not load; using the plain textarea" , error );
      return;
    }
    const area = Dom.get( "docs-editor-text" );
    const host = document.createElement( "div" );
    host.className = "docs-editor";
    host.setAttribute( "role" , "group" );
    host.setAttribute( "aria-labelledby" , "docs-editor-text-label" );
    area.after( host );
    const save = () => Dom.get( "docs-editor-form" ).requestSubmit();
    host.addEventListener( "keydown" , ( event ) => {
      if ( ( event.ctrlKey || event.metaKey ) && !event.altKey && event.key.toLowerCase() === "s" ) {
        event.preventDefault();
        event.stopPropagation();
        save();
      }
    } , true );
    const modes = [ "tree" , "text" , "table" ];
    let mode = "tree";
    try { if ( modes.includes( localStorage.getItem( "docs.editor_mode" ) ) ) mode = localStorage.getItem( "docs.editor_mode" ); } catch ( error ) { /* default */ }
    this.editor = lib.createJSONEditor( {
      target: host,
      props: {
        content: { text: area.value },
        mode: mode,
        indentation: 2,
        tabSize: 2,
        askToFormat: false,
        queryLanguages: [ lib.jsonQueryLanguage , lib.jsonpathQueryLanguage , lib.jmespathQueryLanguage ],
        onChange: () => this.clearTextError(),
        onChangeMode: ( picked ) => {
          try { localStorage.setItem( "docs.editor_mode" , picked ); } catch ( error ) { /* not kept */ }
        },
      },
    } );
    this.editorHost = host;
    area.hidden = true;
    // Format, fold and unfold are in the editor's own menu bar.
    Dom.show( Dom.get( "docs-editor-format" ) , false );
  },

  getText() {
    if ( !this.editor ) return Dom.get( "docs-editor-text" ).value;
    const content = this.editor.get();
    return content.text !== undefined ? content.text : JSON.stringify( content.json , null , 2 );
  },

  // set() starts the editor afresh: new content, no undo history from the
  // last document.
  setText( text ) {
    Dom.get( "docs-editor-text" ).value = text;
    if ( this.editor ) this.editor.set( { text: text } );
  },

  // A JSON problem, shown under the editor (the textarea itself is hidden).
  textError( message ) {
    const area = Dom.get( "docs-editor-text" );
    Dom.fieldError( area , message );
    if ( !this.editor ) return;
    this.editorHost.classList.add( "is-invalid" );
    const problem = Dom.get( area.id + "-problem" );
    if ( problem ) this.editorHost.after( problem );
  },

  clearTextError() {
    Dom.clearFieldError( Dom.get( "docs-editor-text" ) );
    if ( this.editor ) this.editorHost.classList.remove( "is-invalid" );
  },

  async copyText() {
    try {
      await navigator.clipboard.writeText( this.getText() );
      Dom.toast( I18n.get( "ui.copied" ) , "ok" );
    } catch ( error ) {
      if ( this.editor ) this.editor.focus();
      else Dom.get( "docs-editor-text" ).select();
      Dom.toast( I18n.get( "ui.copy_hint" ) , "ok" );
    }
  },

  showEditor( state , text , meta ) {
    this.open = state;
    const collection = Dom.get( "docs-editor-collection" );
    const id = Dom.get( "docs-editor-id" );
    collection.value = state.collection;
    id.value = state.id;
    // A document's place is part of its encryption: moving one is a new
    // document, so only a new one takes a collection and an id.
    collection.readOnly = !state.isNew;
    id.readOnly = !state.isNew;
    this.setText( text );
    this.clearTextError();
    Dom.text( Dom.get( "docs-editor-heading" ) , state.isNew ? I18n.get( "docs.editor_new" ) : this.say( "docs.editor_heading" , { id: state.id } ) );
    Dom.text( Dom.get( "docs-editor-meta" ) , meta || "" );
    Dom.show( Dom.get( "docs-editor-delete" ) , !state.isNew && this.canWrite() );
    Dom.show( Dom.get( "docs-editor-form" ).querySelector( "button[type=submit]" ) , this.canWrite() );
    Dom.show( Dom.get( "docs-editor-card" ) , true );
    Dom.reveal( Dom.get( "docs-editor-card" ) );
  },

  metaText( doc ) {
    return this.say( "docs.editor_meta" , { version: doc.version , size: this.size( doc.size ) , when: new Date( doc.updated_at ).toLocaleString() } );
  },

  async openDoc( collection , id ) {
    if ( !this.needKey() ) return;
    let doc;
    try {
      doc = await Api.doc( collection , id );
    } catch ( error ) {
      App.showError( this.failed( error ) );
      return;
    }
    let text;
    try {
      text = await this.openBody( collection , id , doc.body );
    } catch ( error ) {
      App.showError( error.message );
      return;
    }
    try {
      text = JSON.stringify( JSON.parse( text ) , null , 2 );
    } catch ( error ) { /* shown as it is */ }
    this.showEditor( { collection: collection , id: id , version: doc.version , isNew: false , text: text } , text , this.metaText( doc ) );
    this.showPath( this.docPath( collection , id ) );
  },

  startNew() {
    if ( !this.needKey() || !this.canWrite() ) return;
    this.showEditor( { collection: this.collection || "" , id: DocsCrypto.newId() , version: 0 , isNew: true , text: "" } , "{\n  \n}" , "" );
    if ( !this.collection ) Dom.get( "docs-editor-collection" ).focus( { preventScroll: true } );
    else if ( this.editor ) this.editor.focus();
    else Dom.get( "docs-editor-text" ).focus( { preventScroll: true } );
  },

  closeEditor() {
    if ( this.linked() ) this.showPath( "/" );
    this.open = null;
    this.setText( "" );
    Dom.show( Dom.get( "docs-editor-card" ) , false );
  },

  format() {
    try {
      const text = JSON.stringify( JSON.parse( this.getText() ) , null , 2 );
      // update() keeps the editor's undo history.
      if ( this.editor ) this.editor.update( { text: text } );
      else Dom.get( "docs-editor-text" ).value = text;
      this.clearTextError();
    } catch ( error ) {
      this.textError( this.say( "docs.error_json" , { reason: error.message } ) );
    }
  },

  // Seals text for collection/id and stores it; answers the new metadata.
  async write( collection , id , text , ifVersion ) {
    return this.sealAndSend( collection , id , text , ( sealed ) => Api.setDoc( collection , id , sealed , ifVersion ) );
  },

  async onSave( event ) {
    event.preventDefault();
    if ( !this.open || !this.needKey() ) return;
    const collection = Dom.get( "docs-editor-collection" ).value.trim();
    const id = Dom.get( "docs-editor-id" ).value.trim();
    let text;
    try {
      text = JSON.stringify( JSON.parse( this.getText() ) );
    } catch ( error ) {
      this.textError( this.say( "docs.error_json" , { reason: error.message } ) );
      return;
    }
    this.clearTextError();
    const was = this.open;
    // was.text is the document as opened, which need not be JSON: shown as
    // it is, and then compared as it is. A parse error here would carry its
    // start into the error report.
    const compact = ( raw ) => { try { return JSON.stringify( JSON.parse( raw ) ); } catch ( error ) { return raw; } };
    if ( !was.isNew && text === compact( was.text || "null" ) ) {
      Dom.toast( I18n.get( "ui.unchanged" ) , "ok" );
      return;
    }
    let saved;
    try {
      saved = await this.write( collection , id , text , was.isNew ? 0 : was.version );
    } catch ( error ) {
      if ( error.code ) {
        Dom.toast( error.message , "error" );
        return;
      }
      const reopen = error.status === 409 && !was.isNew
        ? { text: I18n.get( "docs.reopen_button" ) , run: () => this.openDoc( collection , id ) }
        : null;
      Dom.toast( this.failed( error ) , "error" , reopen );
      return;
    }
    // One version number, carried between the undo and redo steps, so each
    // one writes only over what the one before it left.
    const state = { version: saved.version };
    const previous = was.isNew ? null : compact( was.text );
    const label = this.say( was.isNew ? "docs.undo_create" : "docs.undo_edit" , { id: id } );
    Undo.record( {
      label: label,
      undo: async () => {
        const back = previous === null
          ? await Api.deleteDoc( collection , id , state.version )
          : await this.write( collection , id , previous , state.version );
        state.version = back.version;
        await this.afterUndo( collection , id , previous === null );
      },
      redo: async () => {
        const again = await this.write( collection , id , text , previous === null ? 0 : state.version );
        state.version = again.version;
        await this.afterUndo( collection , id , false );
      },
    } );
    Undo.saved( Dom.get( "docs-editor-form" ) );
    Dom.toast( I18n.get( "ui.saved" ) , "ok" );
    this.open = { collection: collection , id: id , version: saved.version , isNew: false , text: JSON.stringify( JSON.parse( text ) , null , 2 ) };
    this.showEditorState( saved );
    await DocsTree.refresh();
    if ( this.collection !== collection ) await this.showCollection( collection );
    else await this.refreshDocs();
  },

  // After a save, the editor stays on the document without moving the page.
  showEditorState( meta ) {
    Dom.get( "docs-editor-collection" ).readOnly = true;
    Dom.get( "docs-editor-id" ).readOnly = true;
    Dom.text( Dom.get( "docs-editor-heading" ) , this.say( "docs.editor_heading" , { id: meta.id } ) );
    Dom.text( Dom.get( "docs-editor-meta" ) , this.metaText( meta ) );
    Dom.show( Dom.get( "docs-editor-delete" ) , true );
  },

  // An undo or redo changed collection/id: the lists, and the editor if it
  // shows that document.
  async afterUndo( collection , id , gone ) {
    if ( this.open && this.open.collection === collection && this.open.id === id ) {
      if ( gone ) this.closeEditor();
      else if ( this.hasKey() ) await this.openDoc( collection , id );
    }
    await this.afterChange( collection );
  },

  // Deleting needs no key: the ciphertext is kept for the undo, which puts
  // the very same bytes back.
  async remove( collection , id ) {
    if ( !this.canWrite() ) return;
    let doc , gone;
    try {
      doc = await Api.doc( collection , id );
      gone = await Api.deleteDoc( collection , id , doc.version );
    } catch ( error ) {
      App.showError( this.failed( error ) );
      return;
    }
    const state = { version: gone.version };
    Undo.record( {
      label: this.say( "docs.undo_delete" , { id: id } ),
      toast: true,
      undo: async () => {
        const back = await Api.setDoc( collection , id , doc.body , 0 );
        state.version = back.version;
        await this.afterChange( collection );
      },
      redo: async () => {
        const again = await Api.deleteDoc( collection , id , state.version );
        state.version = again.version;
        await this.afterUndo( collection , id , true );
      },
    } );
    if ( this.open && this.open.collection === collection && this.open.id === id ) this.closeEditor();
    await this.afterChange( collection );
  },

  // ---- sharing a collection ------------------------------------------------

  // Share...: a scoped API key and the collection's keys, as one access
  // token, shown once. Needs the master key, and a signed-in session (the
  // server mints keys for sessions only). id null (the API keys card) asks
  // which collection, and shows the token on the Documents screen.
  async share( id ) {
    const picking = id === null;
    const elsewhere = Nav.current() !== "docs";
    const folder = picking ? null : DocsTree.get( id );
    if ( !picking && !folder ) return;
    if ( !this.key ) {
      if ( elsewhere ) Nav.show( "docs" );
      Dom.toast( I18n.get( "docs.share_needs_key" ) , "error" );
      Dom.reveal( Dom.get( "docs-unlock-card" ) );
      return;
    }
    const choices = picking ? DocsTree.choices( [] ) : [];
    if ( picking && !choices.length ) {
      Dom.toast( I18n.get( "docs.share_no_folders" ) , "error" );
      return;
    }
    const fields = [];
    if ( picking ) fields.push( { name: "collection" , label: I18n.get( "docs.share_collection" ) , type: "select" , options: choices , help: I18n.get( "docs.share_collection_help" ) } );
    fields.push(
      { name: "access" , label: I18n.get( "docs.share_access" ) , type: "select" , options: [
        { value: "read" , label: I18n.get( "docs.share_read" ) },
        { value: "write" , label: I18n.get( "docs.share_write" ) },
      ] },
      picking
        ? { name: "name" , label: I18n.get( "docs.share_name" ) , maxLength: 80 , help: I18n.get( "docs.share_name_blank_help" ) }
        : { name: "name" , label: I18n.get( "docs.share_name" ) , required: true , maxLength: 80 , value: this.say( "docs.share_name_default" , { name: folder.name } ).slice( 0 , 80 ) , help: I18n.get( "docs.share_name_help" ) },
      { name: "days" , label: I18n.get( "docs.share_days" ) , type: "number" , min: 0 , max: 3650 , value: 30 , help: I18n.get( "docs.share_days_help" ) },
    );
    let made = null;
    await Dom.form( {
      title: picking ? I18n.get( "docs.share_pick_title" ) : this.say( "docs.share_title" , { name: folder.name } ),
      submit: I18n.get( "docs.share_button" ),
      fields: fields,
      save: async ( values ) => {
        const at = picking ? values.collection : id;
        const chosen = DocsTree.get( at );
        if ( !chosen ) throw new Error( I18n.get( "docs.error_no_folder" ) );
        const name = values.name || this.say( "docs.share_name_default" , { name: chosen.name } ).slice( 0 , 80 );
        const key = await this.prepareShare( at );
        const created = await Api.createScopedKey( name , at , values.access , values.days );
        made = {
          name: chosen.name,
          token: DocsCrypto.makeToken( created.credential , values.access === "write" ? key : DocsCrypto.readOnly( key ) ),
          access: values.access,
        };
      },
    } );
    if ( !made ) return;
    // The token's box is on the Documents screen.
    if ( elsewhere ) Nav.show( "docs" );
    this.showShared( made.name , made );
    // The new key belongs in the API keys list too, where it is revoked.
    if ( Keys.me ) Keys.refresh().catch( () => {} );
  },

  // Gives id, and every collection under it, keys, and seals any private
  // envelope (which only the master key opens) again as a collection
  // envelope. Answers id's keys.
  //
  // A folder in it whose keys are not the account's own, or that has none
  // yet, could be one the server only says is in there: its private
  // envelopes are not sealed for the sharee, and sharing stops, naming it.
  async prepareShare( id ) {
    const order = DocsTree.subtree( id );
    for ( const at of order ) {
      const folder = DocsTree.get( at );
      const owned = folder.lock ? ( await this.keyFor( at , false ) ).owned : false;
      if ( !owned && ( await this.hasPrivate( at ) ) ) throw new Error( this.say( "docs.share_not_owned" , { name: folder.name } ) );
    }
    for ( const at of order ) {
      const key = await this.keyFor( at , "share" );
      let offset = 0;
      while ( offset !== null && offset !== undefined ) {
        const page = await Api.docs( at , offset , 200 , true );
        for ( const row of page.docs ) {
          if ( DocsCrypto.envelopeKind( row.body ) !== DocsCrypto.ENVELOPE_MASTER ) continue;
          const text = DocsCrypto.open( this.key , at , row.id , row.body );
          try {
            await Api.setDoc( at , row.id , DocsCrypto.sealCollection( key , row.id , text ) , row.version );
          } catch ( error ) {
            // Written meanwhile, and so already a collection envelope.
            if ( error.status !== 409 ) throw error;
          }
        }
        offset = page.next;
      }
    }
    return this.keyFor( id , false );
  },

  // Whether collection holds a private envelope.
  async hasPrivate( collection ) {
    let offset = 0;
    while ( offset !== null && offset !== undefined ) {
      const page = await Api.docs( collection , offset , 200 , true );
      if ( page.docs.some( ( row ) => DocsCrypto.envelopeKind( row.body ) === DocsCrypto.ENVELOPE_MASTER ) ) return true;
      offset = page.next;
    }
    return false;
  },

  // ---- rotating a collection's keys -----------------------------------------

  // Rotate keys...: new keys for id and every collection under it, every
  // collection envelope in them sealed again, and every access key reaching
  // into them revoked (README.md, "Rotating keys"). Needs the master key.
  // Safe to stop half way: running it again on the same collection finishes
  // it.
  async rotate( id ) {
    const folder = DocsTree.get( id );
    if ( !folder ) return;
    if ( !this.key ) {
      Dom.toast( I18n.get( "docs.rotate_needs_key" ) , "error" );
      Dom.reveal( Dom.get( "docs-unlock-card" ) );
      return;
    }
    const ids = DocsTree.subtree( id );
    const docs = ids.reduce( ( sum , at ) => sum + ( DocsTree.get( at ).count || 0 ) , 0 );
    const question = this.say( folder.next_lock ? "docs.rotate_resume_question" : ( ids.length > 1 ? "docs.rotate_question_tree" : "docs.rotate_question" ) ,
      { name: folder.name , folders: ids.length - 1 , docs: docs } );
    if ( !( await Dom.confirm( question ) ) ) return;
    Dom.toast( this.say( "docs.rotate_started" , { name: folder.name } ) , "ok" );
    let done;
    try {
      done = await this.rotateKeys( id );
    } catch ( error ) {
      Dom.toast( this.say( "docs.rotate_failed" , { name: folder.name , reason: this.failed( error ) } ) , "error" );
      await DocsTree.refresh();
      return;
    }
    await DocsTree.refresh();
    Dom.toast( this.say( done.revoked ? "docs.rotate_done_revoked" : "docs.rotate_done" ,
      { name: folder.name , folders: done.folders , docs: done.docs , revoked: done.revoked } ) , "ok" );
    if ( done.dropped || done.broken ) Dom.toast( this.say( "docs.rotate_dropped" , { dropped: done.dropped , broken: done.broken } ) , "error" );
    if ( Keys.me ) Keys.refresh().catch( () => {} );
    if ( this.collection ) this.refreshDocs();
  },

  // The rotation itself, as client.RotateKeys does it: new lockboxes,
  // parents first (or the ones a rotation already under way staged), every
  // collection envelope sealed again with the new keys, then the switch.
  // Answers { folders , docs , revoked , dropped , broken } (how many).
  //
  // Nothing an access key could plant in the subtree stops it: a folder
  // whose lockbox does not open gets new keys as if it had none (broken),
  // and a collection envelope no key opens is deleted (dropped). A lockbox
  // from before a rotation this device has seen ("rolled_back") still
  // stops it.
  async rotateKeys( id ) {
    this.forgetKeys();
    await DocsTree.refresh();
    const order = DocsTree.subtree( id );
    const olds = new Map();
    const news = new Map();
    const staged = [];
    let broken = 0;
    for ( const at of order ) {
      const folder = DocsTree.get( at );
      if ( folder.lock ) {
        try {
          olds.set( at , await this.keyFor( at , false ) );
        } catch ( error ) {
          // Its lockbox (or one above it) does not open: new keys as if it
          // had none. What the old ones sealed opens for nobody, and the
          // reseal pass drops it.
          if ( error.code !== "corrupt" && error.code !== "wrong_key" ) throw error;
          broken++;
        }
      }
      if ( folder.next_lock ) {
        news.set( at , await this.nextKeyFor( at ) );
        continue;
      }
      const holder = at === id ? await this.holderFor( folder.parent , false ) : news.get( folder.parent );
      // One epoch on from the keys they replace.
      const old = olds.get( at );
      if ( old && old.epoch >= DocsCrypto.MAX_EPOCH ) throw DocsCrypto.fail( "corrupt" );
      const key = DocsCrypto.generateCollectionKey( at , old ? old.epoch + 1 : this.freshEpoch( at ) );
      // The owner tag stays as it was: keys a sharee made are not the
      // account's, rotated or not. A folder with no keys yet gets it only
      // at the top level, as when it is first given keys.
      const tagged = folder.lock ? DocsCrypto.owns( this.key , folder.lock , at ) : folder.parent === "";
      key.owned = tagged && ( holder === this.key || holder.owned === true );
      news.set( at , key );
      staged.push( [ at , DocsCrypto.sealLock( key , holder , null , null , tagged ? this.ownTag( key ) : "" ) ] );
    }
    let revoked = 0;
    for ( let start = 0; start < staged.length; start += 200 ) {
      const reply = await Api.rotateCollection( id , Object.fromEntries( staged.slice( start , start + 200 ) ) );
      revoked += ( reply.revoked || [] ).length;
    }
    // Staged: a lockbox from before this rotation, on its own, is old now.
    for ( const [ at , key ] of news ) {
      this.folderNextKeys.set( at , key );
      await this.noteEpoch( at , "next" , key.epoch );
    }
    let docs = 0 , dropped = 0;
    for ( let pass = 0; ; pass++ ) {
      for ( const at of order ) {
        const done = await this.reseal( at , olds.get( at ) , news.get( at ) );
        docs += done.sealed;
        dropped += done.dropped;
      }
      try {
        const done = await Api.commitRotation( id );
        // Done: from now on only the new lockboxes are good here.
        for ( const [ at , key ] of news ) await this.noteEpoch( at , "lock" , key.epoch );
        this.forgetKeys();
        return { folders: done.collections.length , docs: docs , revoked: revoked , dropped: dropped , broken: broken };
      } catch ( error ) {
        // Something changed under this pass: the next one picks it up.
        if ( !( error.status === 409 && error.payload && error.payload.error === "rotate_incomplete" ) || pass >= 3 ) throw error;
      }
    }
  },

  // Seals every collection envelope in collection that next did not seal
  // again with next, each only if it has not changed since it was read.
  // One no key opens (sealed with neither old nor next, or failing its
  // signature) is deleted instead, if unchanged: no reader accepts it, and
  // the commit waits for every envelope to name next. Answers
  // { sealed , dropped } (how many).
  async reseal( collection , old , next ) {
    const next_id = DocsCrypto.b64( next.id );
    let count = 0 , dropped = 0;
    let offset = 0;
    while ( offset !== null && offset !== undefined ) {
      const page = await Api.docs( collection , offset , 200 , true );
      for ( const row of page.docs ) {
        if ( row.collection && row.collection !== collection ) throw DocsCrypto.fail( "corrupt" );
        if ( DocsCrypto.envelopeKind( row.body ) !== DocsCrypto.ENVELOPE_COLLECTION ) continue;
        const named = DocsCrypto.envelopeKeyId( row.body );
        if ( named === next_id ) continue;
        let text = null;
        if ( old && named === DocsCrypto.b64( old.id ) ) {
          try {
            text = DocsCrypto.openCollection( old , row.id , row.body );
          } catch ( error ) {
            if ( error.code !== "corrupt" ) throw error;
          }
        }
        try {
          if ( text === null ) {
            await Api.deleteDoc( collection , row.id , row.version );
            dropped++;
          } else {
            await Api.setDoc( collection , row.id , DocsCrypto.sealCollection( next , row.id , text ) , row.version );
            count++;
          }
        } catch ( error ) {
          // Changed or deleted meanwhile: the next pass looks again.
          if ( error.status !== 409 && error.status !== 404 ) throw error;
        }
      }
      offset = page.next;
    }
    return { sealed: count , dropped: dropped };
  },

  showShared( name , made ) {
    Qr.hide( Dom.get( "docs-share-qr" ) );
    Dom.text( Dom.get( "docs-share-for" ) , this.say( made.access === "write" ? "docs.share_made_write" : "docs.share_made_read" , { name: name } ) );
    Dom.text( Dom.get( "docs-share-value" ) , made.token );
    Dom.show( Dom.get( "docs-share-box" ) , true );
    Dom.reveal( Dom.get( "docs-share-box" ) );
  },

  hideShared() {
    Dom.text( Dom.get( "docs-share-value" ) , "" );
    Qr.hide( Dom.get( "docs-share-qr" ) );
    Dom.show( Dom.get( "docs-share-box" ) , false );
  },
};
