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
  // Opened with an access token: { key , api_key }; null when signed in.
  scope: null,
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
  async keyFor( collection , create ) {
    if ( this.folderKeys.has( collection ) ) return this.folderKeys.get( collection );
    let folder = DocsTree.get( collection );
    if ( !folder ) {
      await DocsTree.refresh();
      folder = DocsTree.get( collection );
    }
    if ( !folder ) {
      if ( !create || !this.key ) throw DocsCrypto.fail( "no_folder" );
      return this.createTopLevel( collection );
    }
    const holder = await this.holderFor( folder.parent , create );
    let key;
    if ( folder.lock ) {
      key = DocsCrypto.openLock( folder.lock , collection , holder );
    } else {
      if ( !create ) throw DocsCrypto.fail( "corrupt" );
      key = DocsCrypto.generateCollectionKey( collection );
      try {
        const done = await Api.updateCollection( collection , { lock: DocsCrypto.sealLock( key , holder ) } );
        folder.lock = done.lock;
      } catch ( error ) {
        if ( !( error.payload && error.payload.error === "lock_exists" ) ) throw error;
        // Someone else gave it keys first: use theirs.
        await DocsTree.refresh();
        key = DocsCrypto.openLock( DocsTree.get( collection ).lock , collection , holder );
      }
    }
    this.folderKeys.set( collection , key );
    return key;
  },

  // What wraps a collection under parent: the master key at the top level,
  // otherwise parent's keys.
  async holderFor( parent , create ) {
    if ( parent !== "" ) return this.keyFor( parent , create );
    if ( !this.key ) throw DocsCrypto.fail( "wrong_key" );
    return this.key;
  },

  // A lockbox for a new collection id under parent, and its keys. null when
  // there is no key to make one with: it gets keys when first written to.
  async newLock( id , parent ) {
    if ( !this.hasKey() ) return null;
    const holder = await this.holderFor( parent , true );
    const key = DocsCrypto.generateCollectionKey( id );
    return { key: key , lock: DocsCrypto.sealLock( key , holder ) };
  },

  // A top-level collection with keys, named after its id (or "id (2)"...).
  async createTopLevel( id ) {
    const key = DocsCrypto.generateCollectionKey( id );
    const lock = DocsCrypto.sealLock( key , this.key );
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
    return DocsCrypto.sealLock( key , await this.holderFor( parent , true ) );
  },

  // A body (base64 envelope) in, JSON text out: a private envelope with the
  // master key, a collection envelope with the collection's keys.
  async openBody( collection , id , body ) {
    if ( DocsCrypto.envelopeKind( body ) === DocsCrypto.ENVELOPE_MASTER ) {
      if ( !this.key ) throw DocsCrypto.fail( "wrong_key" );
      return DocsCrypto.open( this.key , collection , id , body );
    }
    return DocsCrypto.openCollection( await this.keyFor( collection , false ) , id , body );
  },

  // JSON text in, a collection envelope sealed and signed for collection/id
  // out.
  async sealBody( collection , id , text ) {
    return DocsCrypto.sealCollection( await this.keyFor( collection , true ) , id , text );
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
    if ( error.payload && error.payload.error === "doc_too_large" ) return this.say( "docs.error_too_large" , { size: this.size( error.payload.max_bytes ) } );
    if ( error.payload && error.payload.error === "quota_exceeded" ) return this.say( "docs.error_quota" , { size: this.size( error.payload.quota_bytes ) } );
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
    this.folderKeys.clear();
    this.renderLock();
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
    const value = Dom.get( "docs-new-key-value" );
    const key = DocsCrypto.parseKey( value.textContent );
    Dom.text( value , "" );
    Dom.show( Dom.get( "docs-new-key-box" ) , false );
    if ( key ) this.unlockWith( key );
  },

  lock() {
    if ( this.scope ) {
      App.leaveAccess();
      return;
    }
    this.key = null;
    this.folderKeys.clear();
    this.hideShared();
    this.closeEditor();
    this.renderLock();
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
      const key = this.folderKeys.get( row.collection || this.collection );
      if ( !key ) return null;
      mine = DocsCrypto.b64( key.id );
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
      try { await this.keyFor( collection , false ); } catch ( error ) { /* no keys yet, or not this page's */ }
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
    const moved = await Api.moveDoc( from , id , to , await this.sealBody( to , id , text ) , doc.version );
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
    return Api.setDoc( collection , id , await this.sealBody( collection , id , text ) , ifVersion );
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
    if ( !was.isNew && text === JSON.stringify( JSON.parse( was.text || "null" ) ) ) {
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
    const previous = was.isNew ? null : JSON.stringify( JSON.parse( was.text ) );
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
  async prepareShare( id ) {
    for ( const at of DocsTree.subtree( id ) ) {
      const key = await this.keyFor( at , true );
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
