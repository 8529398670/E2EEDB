// Drag and drop on Pointer Events, so a mouse, a pen and a finger all work.
// HTML5 drag and drop does not work on touch screens at all.
//
//   Drag.attach( row , {
//     payload: () => ( { kind: "folder" , id } ),   // what is being dragged
//     label:   () => "Invoices",                   // shown beside the pointer
//     target:  ( element , payload , event ) => ( { element , mode } ) or null,
//     drop:    ( target , payload ) => { ... },
//     scroller: element,                           // scrolled near its edges
//   } );
//
// A mouse starts a drag after moving a few pixels. A finger has to hold still
// for a moment first (a long press), so an ordinary swipe still scrolls the
// page. target is asked on every move with the element under the pointer and
// answers where a drop would land: { element , mode } where mode is "before",
// "after" or "into", or { element , mode: "no" } for a place it may not go,
// or null for nowhere. Escape cancels. The click that ends a drag is swallowed,
// so dropping does not also open whatever was under the pointer.
const Drag = {
  // Movement that turns a press into a drag, and how long a finger holds.
  threshold: 6,
  holdMs: 350,
  // Room near an edge of the scroller (or the window) that scrolls it.
  edge: 40,
  active: null,

  attach( source , options ) {
    source.classList.add( "drag-source" );
    source.addEventListener( "pointerdown" , ( event ) => this.press( source , options , event ) );
    // A long press on Android opens the context menu; on iOS, the callout.
    source.addEventListener( "contextmenu" , ( event ) => {
      if ( this.active || source._pending ) event.preventDefault();
    } );
  },

  press( source , options , event ) {
    if ( this.active || event.button !== 0 || event.isPrimary === false ) return;
    // Buttons, fields and links inside the source keep their own press.
    if ( event.target.closest( "button, input, select, textarea, a, .dropdown-menu, [data-no-drag]" ) ) return;
    const touch = event.pointerType !== "mouse";
    const start = { x: event.clientX , y: event.clientY };
    let timer = null;
    let started = false;
    const cleanup = () => {
      window.clearTimeout( timer );
      source._pending = false;
      source.classList.remove( "drag-pending" );
      window.removeEventListener( "pointermove" , move , true );
      window.removeEventListener( "pointerup" , up , true );
      window.removeEventListener( "pointercancel" , cancel , true );
    };
    const begin = ( at ) => {
      started = true;
      cleanup();
      this.begin( source , options , event.pointerId , at , touch );
    };
    const move = ( next ) => {
      if ( next.pointerId !== event.pointerId ) return;
      const far = Math.hypot( next.clientX - start.x , next.clientY - start.y ) > this.threshold;
      // A finger that moves before the hold is up is scrolling, not dragging.
      if ( touch && far ) cleanup();
      else if ( !touch && far ) begin( next );
    };
    const up = () => cleanup();
    const cancel = () => cleanup();
    source._pending = true;
    window.addEventListener( "pointermove" , move , true );
    window.addEventListener( "pointerup" , up , true );
    window.addEventListener( "pointercancel" , cancel , true );
    if ( touch ) {
      source.classList.add( "drag-pending" );
      timer = window.setTimeout( () => {
        if ( !started ) begin( { clientX: start.x , clientY: start.y } );
      } , this.holdMs );
    }
  },

  begin( source , options , pointerId , at , touch ) {
    const payload = options.payload();
    if ( !payload ) return;
    const ghost = Dom.el( "div" , { class: "drag-ghost shadow" , children: [
      Dom.el( "i" , { class: "bi " + ( options.icon || "bi-grip-vertical" ) + " me-2" , attrs: { "aria-hidden": "true" } } ),
      Dom.el( "span" , { text: options.label() } ),
    ] } );
    document.body.appendChild( ghost );
    document.body.classList.add( "drag-on" );
    // What is being dragged, for CSS that shows a drop zone only to some.
    document.body.dataset.drag = payload.kind || "";
    source.classList.add( "drag-from" );
    const state = this.active = { source , options , payload , ghost , pointerId , target: null , point: at , frame: 0 };
    if ( touch && navigator.vibrate ) {
      try { navigator.vibrate( 15 ); } catch ( error ) { /* not allowed here */ }
    }

    const move = ( event ) => {
      if ( event.pointerId !== pointerId ) return;
      event.preventDefault();
      state.point = event;
      this.follow( event );
    };
    // Stops the page scrolling under a finger that is dragging. It has to be
    // a non-passive touchmove: pointer events alone cannot do it.
    const still = ( event ) => event.preventDefault();
    const up = ( event ) => {
      if ( event.pointerId !== pointerId ) return;
      const target = state.target;
      this.end();
      if ( target && target.mode !== "no" ) {
        // The click this release makes lands on whatever is under it.
        this.swallowClick();
        options.drop( target , payload );
      } else {
        this.swallowClick();
      }
    };
    const key = ( event ) => {
      if ( event.key !== "Escape" ) return;
      event.preventDefault();
      event.stopPropagation();
      this.end();
    };
    const cancel = ( event ) => {
      if ( event.pointerId === pointerId ) this.end();
    };
    state.unbind = () => {
      window.removeEventListener( "pointermove" , move , true );
      window.removeEventListener( "pointerup" , up , true );
      window.removeEventListener( "pointercancel" , cancel , true );
      window.removeEventListener( "touchmove" , still , { capture: true } );
      window.removeEventListener( "keydown" , key , true );
    };
    window.addEventListener( "pointermove" , move , true );
    window.addEventListener( "pointerup" , up , true );
    window.addEventListener( "pointercancel" , cancel , true );
    window.addEventListener( "touchmove" , still , { capture: true , passive: false } );
    window.addEventListener( "keydown" , key , true );
    this.follow( at );
    this.scrollLoop();
  },

  follow( point ) {
    const state = this.active;
    if ( !state ) return;
    state.ghost.style.transform = "translate(" + ( point.clientX + 14 ) + "px," + ( point.clientY + 14 ) + "px)";
    const under = document.elementFromPoint( point.clientX , point.clientY );
    const target = under ? state.options.target( under , state.payload , point ) : null;
    this.mark( target );
  },

  // Shows where a drop would land: drop-before, drop-after, drop-into or
  // drop-no on the target element.
  mark( target ) {
    const state = this.active;
    const old = state.target;
    if ( old && ( !target || old.element !== target.element || old.mode !== target.mode ) ) {
      old.element.classList.remove( "drop-before" , "drop-after" , "drop-into" , "drop-no" );
    }
    state.target = target;
    if ( target ) target.element.classList.add( "drop-" + target.mode );
    state.ghost.classList.toggle( "drag-ghost-no" , Boolean( target && target.mode === "no" ) );
  },

  // Scrolls the scroller, or the window, while the pointer is near an edge.
  scrollLoop() {
    const state = this.active;
    if ( !state ) return;
    const point = state.point;
    const speed = ( distance ) => Math.ceil( ( this.edge - distance ) / 4 );
    const scroller = state.options.scroller;
    let moved = false;
    if ( scroller && scroller.scrollHeight > scroller.clientHeight ) {
      const box = scroller.getBoundingClientRect();
      if ( point.clientX >= box.left && point.clientX <= box.right ) {
        if ( point.clientY - box.top < this.edge && point.clientY >= box.top ) {
          scroller.scrollTop -= speed( point.clientY - box.top );
          moved = true;
        } else if ( box.bottom - point.clientY < this.edge && point.clientY <= box.bottom ) {
          scroller.scrollTop += speed( box.bottom - point.clientY );
          moved = true;
        }
      }
    }
    if ( !moved ) {
      if ( point.clientY < this.edge ) window.scrollBy( 0 , -speed( point.clientY ) );
      else if ( window.innerHeight - point.clientY < this.edge ) window.scrollBy( 0 , speed( window.innerHeight - point.clientY ) );
      else moved = null;
    }
    if ( moved !== null ) this.follow( point );
    state.frame = window.requestAnimationFrame( () => this.scrollLoop() );
  },

  end() {
    const state = this.active;
    if ( !state ) return;
    this.mark( null );
    window.cancelAnimationFrame( state.frame );
    state.unbind();
    state.ghost.remove();
    state.source.classList.remove( "drag-from" );
    document.body.classList.remove( "drag-on" );
    delete document.body.dataset.drag;
    this.active = null;
  },

  swallowClick() {
    const stop = ( event ) => {
      event.preventDefault();
      event.stopPropagation();
    };
    window.addEventListener( "click" , stop , { capture: true , once: true } );
    // A release that makes no click (a finger, sometimes) must not eat the next one.
    window.setTimeout( () => window.removeEventListener( "click" , stop , { capture: true } ) , 0 );
  },
};
