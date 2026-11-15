// The Documents screen's folder tree: collections inside collections, shown
// as a tree you can open and close, rename in place, drag to reorder or nest,
// and drop documents onto. docs.js owns the documents; this owns the folders.
//
// A folder's id is what its documents are filed under and what their
// encryption is bound to, so it never changes: renaming, moving or
// reordering one is a change to the folder alone and needs no key. Moving a
// document into another folder does need it (Docs.moveDocs), because the
// document is sealed again for its new place.
//
// The tree is metadata the server already holds, so it shows while locked.
const DocsTree = {
  // id -> { id , name , parent , position , version , count , bytes , updated_at }
  folders: new Map(),
  // Folder ids that are open, remembered in this browser.
  opened: new Set(),
  // The last list reply, for the usage line.
  page: null,
  storageKey: "docs.tree.open",
  // A subtree bigger than this is deleted without an undo: putting it back
  // means holding every document's ciphertext in this tab meanwhile.
  undoMaxDocs: 2000,
  undoMaxBytes: 20 * 1024 * 1024,

  init() {
    this.opened = new Set( this.loadOpened() );
    Dom.onPress( Dom.get( "docs-folder-new" ) , () => this.create( "" ) );
    const tree = Dom.get( "docs-tree" );
    tree.addEventListener( "keydown" , ( event ) => this.onKey( event ) );
    // The top-level drop zone shows only while something is being dragged.
    const top = Dom.get( "docs-tree-top" );
    top.dataset.dropTop = "true";
  },

  // ---- data ----------------------------------------------------------------

  loadOpened() {
    try {
      const saved = JSON.parse( window.localStorage.getItem( this.storageKey ) || "[]" );
      return Array.isArray( saved ) ? saved : [];
    } catch ( error ) {
      return [];
    }
  },

  saveOpened() {
    try {
      window.localStorage.setItem( this.storageKey , JSON.stringify( Array.from( this.opened ) ) );
    } catch ( error ) { /* private window: forgotten on reload */ }
  },

  async refresh() {
    const folders = new Map();
    let page = null;
    let offset = 0;
    try {
      while ( offset !== null ) {
        page = await Api.allCollections( offset , 1000 );
        page.collections.forEach( ( entry ) => folders.set( entry.id , entry ) );
        offset = page.next === null || page.next === undefined ? null : page.next;
      }
    } catch ( error ) {
      App.showError( error.message );
      return;
    }
    this.folders = folders;
    this.page = page;
    // A folder that went away (deleted elsewhere) is no longer open.
    this.opened.forEach( ( id ) => { if ( !folders.has( id ) ) this.opened.delete( id ); } );
    this.render();
    this.renderUsage();
    if ( Docs.collection && !folders.has( Docs.collection ) ) Docs.showNothing();
    else if ( Docs.collection ) Docs.renderHeading();
  },

  renderUsage() {
    const page = this.page;
    if ( !page ) return;
    const usage = page.quota_bytes > 0
      ? Docs.say( "docs.usage_quota" , { used: Docs.size( page.used_bytes ) , quota: Docs.size( page.quota_bytes ) , count: page.doc_count } )
      : Docs.say( "docs.usage" , { used: Docs.size( page.used_bytes ) , count: page.doc_count } );
    Dom.text( Dom.get( "docs-usage" ) , usage );
  },

  get( id ) {
    return this.folders.get( id ) || null;
  },

  nameOf( id ) {
    const folder = this.get( id );
    return folder ? folder.name : id;
  },

  // parent's children, in their order.
  children( parent ) {
    return Array.from( this.folders.values() )
      .filter( ( folder ) => folder.parent === parent )
      .sort( ( a , b ) => a.position - b.position || ( a.id < b.id ? -1 : 1 ) );
  },

  // id and everything under it, parents first.
  subtree( id ) {
    const result = [];
    const walk = ( at ) => {
      result.push( at );
      this.children( at ).forEach( ( child ) => walk( child.id ) );
    };
    if ( this.get( id ) ) walk( id );
    return result;
  },

  // "Work / Invoices / 2026", for a folder picker and messages.
  path( id ) {
    const names = [];
    for ( let at = this.get( id ) ; at ; at = this.get( at.parent ) ) {
      names.unshift( at.name );
      if ( names.length > 64 ) break;
    }
    return names.join( " / " );
  },

  // The sibling after id, leaving out skip: where "after id" is "before that".
  nextSibling( id , skip ) {
    const folder = this.get( id );
    if ( !folder ) return "";
    const siblings = this.children( folder.parent ).filter( ( entry ) => entry.id !== skip );
    const index = siblings.findIndex( ( entry ) => entry.id === id );
    return index >= 0 && index + 1 < siblings.length ? siblings[ index + 1 ].id : "";
  },

  // Opens every folder above id, so it shows.
  reveal( id ) {
    let changed = false;
    for ( let at = this.get( this.get( id ) ? this.get( id ).parent : "" ) ; at ; at = this.get( at.parent ) ) {
      if ( !this.opened.has( at.id ) ) {
        this.opened.add( at.id );
        changed = true;
      }
    }
    if ( changed ) {
      this.saveOpened();
      this.render();
    }
  },

  // ---- drawing -------------------------------------------------------------

  render() {
    const tree = Dom.get( "docs-tree" );
    const focused = tree.contains( document.activeElement ) ? document.activeElement.closest( "[role=treeitem]" ) : null;
    const focusId = focused ? focused.dataset.id : null;
    const top = this.children( "" );
    tree.replaceChildren( ...top.map( ( folder , index ) => this.node( folder , 1 , index , top.length ) ) );
    Dom.show( Dom.get( "docs-tree-empty" ) , top.length === 0 );
    // One item takes the Tab key: the open folder, else the first.
    const items = this.items();
    const current = items.find( ( item ) => item.dataset.id === Docs.collection ) || items[ 0 ];
    if ( current ) current.tabIndex = 0;
    if ( focusId ) {
      const again = tree.querySelector( "[role=treeitem][data-id='" + CSS.escape( focusId ) + "']" );
      if ( again ) this.focusItem( again );
    }
  },

  node( folder , level , index , count ) {
    const kids = this.children( folder.id );
    const open = kids.length > 0 && this.opened.has( folder.id );
    const selected = Docs.collection === folder.id;
    const twisty = Dom.el( "span" , {
      class: "docs-twisty" + ( kids.length ? "" : " invisible" ),
      attrs: { "aria-hidden": "true" },
      children: [ Dom.el( "i" , { class: "bi " + ( open ? "bi-chevron-down" : "bi-chevron-right" ) } ) ],
    } );
    twisty.addEventListener( "click" , ( event ) => {
      event.stopPropagation();
      this.toggle( folder.id );
    } );
    const name = Dom.el( "span" , { class: "docs-node-name text-truncate" , text: folder.name , attrs: { title: this.path( folder.id ) } } );
    const row = Dom.el( "div" , {
      class: "docs-node-row" + ( selected ? " active" : "" ),
      children: [
        twisty,
        Dom.el( "i" , { class: "bi " + ( selected ? "bi-folder2-open" : "bi-folder" ) + " docs-node-icon" , attrs: { "aria-hidden": "true" } } ),
        name,
        Dom.el( "span" , { class: "badge rounded-pill docs-node-count" , text: folder.count , attrs: { title: Docs.say( "docs.folder_count" , { count: folder.count } ) } } ),
        this.menu( folder ),
      ],
    } );
    // Through the CSSOM: the page's CSP refuses style attributes.
    row.style.setProperty( "--docs-level" , String( level - 1 ) );
    row.addEventListener( "click" , () => this.select( folder.id ) );
    row.addEventListener( "dblclick" , ( event ) => {
      if ( event.target.closest( ".docs-node-name" ) ) this.rename( folder.id );
    } );
    const item = Dom.el( "li" , {
      class: "docs-node",
      attrs: {
        role: "treeitem",
        "data-id": folder.id,
        "data-key": "folder-" + folder.id,
        "aria-level": String( level ),
        "aria-setsize": String( count ),
        "aria-posinset": String( index + 1 ),
        "aria-selected": String( selected ),
        "aria-label": folder.name,
        tabindex: "-1",
      },
      children: [ row ],
    } );
    if ( kids.length ) {
      item.setAttribute( "aria-expanded" , String( open ) );
      if ( open ) {
        item.appendChild( Dom.el( "ul" , {
          class: "list-unstyled mb-0",
          attrs: { role: "group" },
          children: kids.map( ( child , childIndex ) => this.node( child , level + 1 , childIndex , kids.length ) ),
        } ) );
      }
    }
    // Read-only, or an access token's own folder: not draggable.
    const fixed = !Docs.canWrite() || ( Docs.scope && folder.id === Docs.scope.key.collection );
    if ( !fixed ) Drag.attach( row , {
      icon: "bi-folder",
      payload: () => ( { kind: "folder" , id: folder.id } ),
      label: () => folder.name,
      target: ( under , payload , point ) => this.dropTarget( under , payload , point ),
      drop: ( target , payload ) => this.onDrop( target , payload ),
      scroller: Dom.get( "docs-tree-scroll" ),
    } );
    return item;
  },

  // A folder's ... menu.
  menu( folder ) {
    const item = ( icon , key , run , danger ) => Dom.el( "button" , {
      class: "dropdown-item" + ( danger ? " text-danger" : "" ),
      attrs: { type: "button" },
      children: [
        Dom.el( "i" , { class: "bi " + icon + " me-2" , attrs: { "aria-hidden": "true" } } ),
        Dom.el( "span" , { text: I18n.get( key ) } ),
      ],
      on: { click: run },
    } );
    const label = Docs.say( "docs.folder_actions" , { name: folder.name } );
    const toggle = Dom.el( "button" , {
      class: "btn btn-sm docs-node-menu",
      attrs: { type: "button" , "data-bs-toggle": "dropdown" , "aria-expanded": "false" , "aria-label": label , title: label , tabindex: "-1" },
      children: [ Dom.el( "i" , { class: "bi bi-three-dots-vertical" , attrs: { "aria-hidden": "true" } } ) ],
    } );
    // Opened with an access token: only what it may do, and its own folder
    // keeps its name and place. Signed in: Share... too.
    const scoped = Docs.scope !== null;
    const root = scoped && folder.id === Docs.scope.key.collection;
    const writable = Docs.canWrite();
    const entries = [];
    if ( writable ) entries.push( item( "bi-folder-plus" , "docs.folder_new_inside" , () => this.create( folder.id ) ) );
    if ( writable && !root ) entries.push( item( "bi-pencil" , "docs.folder_rename" , () => this.rename( folder.id ) ) );
    if ( writable && !root ) entries.push( item( "bi-arrow-right-square" , "docs.folder_move" , () => this.moveTo( folder.id ) ) );
    if ( !scoped ) entries.push( item( "bi-share" , "docs.folder_share" , () => Docs.share( folder.id ) ) );
    if ( writable && !root ) {
      entries.push( Dom.el( "li" , { children: [ Dom.el( "hr" , { class: "dropdown-divider" } ) ] } ) );
      entries.push( item( "bi-trash" , "docs.folder_delete" , () => this.remove( folder.id ) , true ) );
    }
    if ( !entries.length ) return Dom.el( "span" );
    const list = Dom.el( "ul" , { class: "dropdown-menu dropdown-menu-end" , children:
      entries.map( ( entry ) => entry.tagName === "LI" ? entry : Dom.el( "li" , { children: [ entry ] } ) ) } );
    const holder = Dom.el( "div" , { class: "dropdown" , attrs: { "data-no-drag": "" } , children: [ toggle , list ] } );
    const menu = new bootstrap.Dropdown( toggle , { popperConfig: { strategy: "fixed" } } );
    holder.addEventListener( "click" , ( event ) => event.stopPropagation() );
    list.addEventListener( "click" , () => menu.hide() , true );
    return holder;
  },

  toggle( id , open ) {
    const want = open === undefined ? !this.opened.has( id ) : open;
    if ( want ) this.opened.add( id );
    else this.opened.delete( id );
    this.saveOpened();
    this.render();
  },

  select( id ) {
    Docs.showCollection( id );
  },

  // ---- keyboard ------------------------------------------------------------

  // The tree items showing now, top to bottom.
  // Closed folders' children are not drawn at all, so every item is showing.
  items() {
    return Array.from( Dom.get( "docs-tree" ).querySelectorAll( "[role=treeitem]" ) );
  },

  focusItem( item ) {
    Dom.get( "docs-tree" ).querySelectorAll( "[role=treeitem][tabindex='0']" ).forEach( ( other ) => { other.tabIndex = -1; } );
    item.tabIndex = 0;
    item.focus( { preventScroll: false } );
  },

  onKey( event ) {
    const item = event.target.closest( "[role=treeitem]" );
    // Keys typed in the rename field, or in a menu, are theirs.
    if ( !item || event.target !== item ) return;
    const id = item.dataset.id;
    const folder = this.get( id );
    const items = this.items();
    const index = items.indexOf( item );
    const go = ( next ) => {
      if ( next ) this.focusItem( next );
      event.preventDefault();
    };
    switch ( event.key ) {
      case "ArrowDown": return go( items[ index + 1 ] );
      case "ArrowUp": return go( items[ index - 1 ] );
      case "Home": return go( items[ 0 ] );
      case "End": return go( items[ items.length - 1 ] );
      case "ArrowRight":
        if ( this.children( id ).length && !this.opened.has( id ) ) {
          this.toggle( id , true );
          event.preventDefault();
          return;
        }
        if ( this.children( id ).length ) return go( item.querySelector( "[role=group] > [role=treeitem]" ) );
        return;
      case "ArrowLeft":
        if ( this.opened.has( id ) && this.children( id ).length ) {
          this.toggle( id , false );
          event.preventDefault();
          return;
        }
        if ( folder && folder.parent ) return go( Dom.get( "docs-tree" ).querySelector( "[role=treeitem][data-id='" + CSS.escape( folder.parent ) + "']" ) );
        return;
      case "Enter":
      case " ":
        event.preventDefault();
        this.select( id );
        return;
      case "F2":
        event.preventDefault();
        this.rename( id );
        return;
      case "Delete":
        event.preventDefault();
        this.remove( id );
        return;
      default:
        return;
    }
  },

  // ---- drag and drop -------------------------------------------------------

  // Where a drop over under would land. A folder goes before, into or after
  // another (by where on the row the pointer is), or to the top level over
  // the zone above the tree. Documents go into a folder.
  dropTarget( under , payload , point ) {
    const top = under.closest( "[data-drop-top]" );
    // Through an access token, nothing goes to the top level.
    if ( top ) return payload.kind === "folder" && Docs.scope === null ? { element: top , mode: "into" , parent: "" } : { element: top , mode: "no" };
    const row = under.closest( ".docs-node-row" );
    if ( !row ) return null;
    const id = row.closest( "[role=treeitem]" ).dataset.id;
    if ( payload.kind === "docs" ) {
      return { element: row , mode: id === payload.from ? "no" : "into" , id: id };
    }
    if ( this.subtree( payload.id ).includes( id ) ) return { element: row , mode: "no" };
    // An access token's own folder stays at the top: nothing goes beside it.
    if ( Docs.scope && id === Docs.scope.key.collection ) return { element: row , mode: "into" , id: id };
    const box = row.getBoundingClientRect();
    const share = ( point.clientY - box.top ) / box.height;
    const mode = share < 0.25 ? "before" : share > 0.75 ? "after" : "into";
    return { element: row , mode: mode , id: id };
  },

  async onDrop( target , payload ) {
    if ( payload.kind === "docs" ) {
      await Docs.moveDocs( payload.from , payload.ids , target.id );
      return;
    }
    const target_folder = target.id ? this.get( target.id ) : null;
    let parent , before;
    if ( target.parent === "" ) {
      parent = "";
      before = "";
    } else if ( target.mode === "into" ) {
      parent = target.id;
      before = "";
    } else if ( target.mode === "before" ) {
      parent = target_folder.parent;
      before = target.id;
    } else {
      parent = target_folder.parent;
      before = this.nextSibling( target.id , payload.id );
    }
    await this.move( payload.id , parent , before );
    if ( target.mode === "into" && parent ) this.toggle( parent , true );
  },

  // ---- changes -------------------------------------------------------------

  failed( error ) {
    const code = error.payload && error.payload.error;
    if ( code === "too_deep" ) return Docs.say( "docs.error_too_deep" , { depth: error.payload.max_depth } );
    if ( code === "too_many_collections" ) return Docs.say( "docs.error_too_many" , { count: error.payload.max_collections } );
    if ( code === "name_taken" ) return I18n.get( "docs.error_name_taken" );
    if ( code === "collection_cycle" ) return I18n.get( "docs.error_cycle" );
    return Docs.failed( error );
  },

  // Makes a folder in parent ("" for the top level), asking for its name.
  async create( parent ) {
    const title = parent ? Docs.say( "docs.folder_new_in" , { name: this.nameOf( parent ) } ) : I18n.get( "docs.folder_new" );
    let made = null;
    await Dom.form( {
      title: title,
      submit: I18n.get( "docs.folder_create" ),
      fields: [ { name: "name" , label: I18n.get( "docs.folder_name" ) , required: true , maxLength: 128 } ],
      save: async ( values ) => {
        try {
          // With a key, the folder gets its own keys now; without, the
          // first write gives it them.
          const change = { name: values.name , parent: parent };
          if ( Docs.hasKey() ) {
            change.id = DocsCrypto.newId();
            const fresh = await Docs.newLock( change.id , parent );
            change.lock = fresh.lock;
            Docs.folderKeys.set( change.id , fresh.key );
          }
          made = await Api.createCollection( change );
        } catch ( error ) {
          throw new Error( error.code ? error.message : this.failed( error ) );
        }
      },
    } );
    if ( !made ) return;
    const folder = made;
    const state = { id: folder.id , version: folder.version };
    Undo.record( {
      label: Docs.say( "docs.undo_folder_create" , { name: folder.name } ),
      undo: async () => {
        await Api.deleteCollection( state.id , state.version );
        await this.afterUndo();
      },
      redo: async () => {
        const again = await Api.createCollection( Object.assign( { id: state.id , name: folder.name , parent: parent } , folder.lock ? { lock: folder.lock } : {} ) );
        state.version = again.version;
        await this.afterUndo();
      },
    } );
    if ( parent ) this.opened.add( parent );
    this.saveOpened();
    await this.refresh();
    Docs.showCollection( folder.id );
  },

  // Renames a folder where it sits: Enter saves, Escape cancels, and leaving
  // the field saves.
  rename( id ) {
    // An access token's own folder keeps its name: the server refuses it.
    if ( !Docs.canWrite() || ( Docs.scope !== null && id === Docs.scope.key.collection ) ) return;
    const folder = this.get( id );
    const item = Dom.get( "docs-tree" ).querySelector( "[role=treeitem][data-id='" + CSS.escape( id ) + "']" );
    if ( !folder || !item ) return;
    const name = item.querySelector( ":scope > .docs-node-row .docs-node-name" );
    const input = Dom.el( "input" , {
      class: "form-control form-control-sm docs-node-input",
      attrs: { type: "text" , maxlength: "128" , "aria-label": Docs.say( "docs.folder_rename_label" , { name: folder.name } ) , "data-no-drag": "" },
    } );
    input.value = folder.name;
    name.replaceWith( input );
    input.focus();
    input.select();
    let done = false;
    const finish = async ( save ) => {
      if ( done ) return;
      const value = input.value.trim();
      if ( !save || value === "" || value === folder.name ) {
        done = true;
        this.render();
        this.focusById( id );
        return;
      }
      input.disabled = true;
      try {
        await this.update( id , { name: value } , { name: folder.name } , Docs.say( "docs.undo_folder_rename" , { name: value } ) );
        done = true;
        await this.refresh();
        this.focusById( id );
      } catch ( error ) {
        input.disabled = false;
        input.focus();
        Dom.toast( this.failed( error ) , "error" );
      }
    };
    input.addEventListener( "keydown" , ( event ) => {
      event.stopPropagation();
      if ( event.key === "Enter" ) {
        event.preventDefault();
        finish( true );
      } else if ( event.key === "Escape" ) {
        event.preventDefault();
        finish( false );
      }
    } );
    input.addEventListener( "click" , ( event ) => event.stopPropagation() );
    input.addEventListener( "blur" , () => { if ( !input.disabled ) finish( true ); } );
  },

  focusById( id ) {
    const item = Dom.get( "docs-tree" ).querySelector( "[role=treeitem][data-id='" + CSS.escape( id ) + "']" );
    if ( item ) this.focusItem( item );
  },

  // Changes a folder and records the undo: back holds what to put back.
  async update( id , change , back , label ) {
    const done = await Api.updateCollection( id , change );
    const state = { version: done.version };
    Undo.record( {
      label: label,
      undo: async () => {
        const again = await Api.updateCollection( id , Object.assign( { if_version: state.version } , back ) );
        state.version = again.version;
        await this.afterUndo();
      },
      redo: async () => {
        const again = await Api.updateCollection( id , Object.assign( { if_version: state.version } , change ) );
        state.version = again.version;
        await this.afterUndo();
      },
    } );
    return done;
  },

  // Moves a folder under parent, in front of before ("" for the end).
  async move( id , parent , before ) {
    const folder = this.get( id );
    if ( !folder ) return;
    const back = { parent: folder.parent , before: this.nextSibling( id ) };
    if ( back.parent === parent && back.before === before ) return;
    const label = Docs.say( "docs.undo_folder_move" , { name: folder.name } );
    const change = { parent: parent , before: before };
    try {
      // A folder with its own keys has them wrapped again for its new
      // parent; the undo puts back the lockbox it had, made for the old one.
      if ( folder.lock && parent !== folder.parent ) {
        if ( !Docs.hasKey() ) {
          Dom.toast( I18n.get( "docs.unlock_first" ) , "error" );
          return;
        }
        change.lock = await Docs.rewrapLock( id , parent );
        back.lock = folder.lock;
      }
      await this.update( id , change , back , label );
    } catch ( error ) {
      Dom.toast( error.code ? error.message : this.failed( error ) , "error" );
      return;
    }
    await this.refresh();
    this.reveal( id );
  },

  // Every folder as a choice for a picker, in tree order, each labelled with
  // its whole path ("Work / Invoices / Q1") so one whose parent is left out
  // still says where it is. Leaves out those in skip and everything under them.
  choices( skip ) {
    const result = [];
    const walk = ( parent ) => {
      this.children( parent ).forEach( ( folder ) => {
        if ( skip.includes( folder.id ) ) return;
        result.push( { value: folder.id , label: this.path( folder.id ) } );
        walk( folder.id );
      } );
    };
    walk( "" );
    return result;
  },

  // Move to...: the same as dragging, for a keyboard or a small screen.
  async moveTo( id ) {
    const folder = this.get( id );
    if ( !folder ) return;
    const top = { value: "" , label: I18n.get( "docs.folder_top" ) };
    const options = [ top ].concat( this.choices( this.subtree( id ) ) );
    let chosen = null;
    await Dom.form( {
      title: Docs.say( "docs.folder_move_title" , { name: folder.name } ),
      submit: I18n.get( "docs.move_button" ),
      fields: [ { name: "parent" , label: I18n.get( "docs.move_into" ) , type: "select" , options: options , value: folder.parent } ],
      save: async ( values ) => { chosen = values.parent; },
    } );
    if ( chosen === null || chosen === folder.parent ) return;
    await this.move( id , chosen , "" );
    if ( chosen ) this.toggle( chosen , true );
  },

  // Deletes a folder, its subfolders and their documents, once asked. The
  // undo puts back the same folders under the same ids, and the very same
  // ciphertext, so it needs no key.
  async remove( id ) {
    const folder = this.get( id );
    if ( !folder ) return;
    const ids = this.subtree( id );
    const docs = ids.reduce( ( sum , at ) => sum + ( this.get( at ).count || 0 ) , 0 );
    const bytes = ids.reduce( ( sum , at ) => sum + ( this.get( at ).bytes || 0 ) , 0 );
    const undoable = docs <= this.undoMaxDocs && bytes <= this.undoMaxBytes;
    let question = Docs.say( ids.length > 1 ? "docs.folder_delete_question_tree" : "docs.folder_delete_question" ,
      { name: folder.name , folders: ids.length - 1 , docs: docs } );
    if ( !undoable ) question += " " + I18n.get( "docs.folder_delete_no_undo" );
    if ( !( await Dom.confirm( question ) ) ) return;

    // What it takes to put it all back, read before it goes.
    const kept = [];
    const shape = ids.map( ( at ) => {
      const entry = this.get( at );
      return { id: entry.id , name: entry.name , parent: entry.parent , before: this.nextSibling( entry.id ) , lock: entry.lock || "" };
    } );
    try {
      if ( undoable ) {
        for ( const at of ids ) {
          let offset = 0;
          while ( offset !== null ) {
            const page = await Api.docs( at , offset , 1000 , true );
            page.docs.forEach( ( row ) => kept.push( { collection: at , id: row.id , body: row.body } ) );
            offset = page.next === null || page.next === undefined ? null : page.next;
          }
        }
      }
      await Api.deleteCollection( id , folder.version );
    } catch ( error ) {
      App.showError( this.failed( error ) );
      return;
    }
    if ( undoable ) {
      const state = { version: 1 };
      Undo.record( {
        label: Docs.say( "docs.undo_folder_delete" , { name: folder.name } ),
        toast: true,
        undo: async () => {
          for ( const entry of shape ) {
            // The top one goes back in front of its old neighbour, if that is still there.
            const before = entry.id === id && this.get( entry.before ) ? entry.before : "";
            const made = await Api.createCollection( Object.assign( { id: entry.id , name: entry.name , parent: entry.parent , before: before } , entry.lock ? { lock: entry.lock } : {} ) );
            if ( entry.id === id ) state.version = made.version;
          }
          for ( const doc of kept ) await Api.setDoc( doc.collection , doc.id , doc.body , 0 );
          await this.afterUndo();
        },
        redo: async () => {
          await Api.deleteCollection( id , state.version );
          await this.afterUndo();
        },
      } );
    }
    if ( ids.includes( Docs.collection ) ) Docs.showNothing();
    if ( Docs.open && ids.includes( Docs.open.collection ) ) Docs.closeEditor();
    await this.refresh();
  },

  async afterUndo() {
    await this.refresh();
    if ( Docs.collection ) await Docs.refreshDocs();
  },
};
