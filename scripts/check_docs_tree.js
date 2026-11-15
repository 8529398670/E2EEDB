#!/usr/bin/env node
// Holds the Documents screen's folder tree (static/js/docs_tree.js) to a
// server that reports a loop of parents (A in B in A, or A in itself): the
// walks up and down the tree end, and the folder shows as broken instead
// of hanging the tab.
//
// Run by the tests, or on its own: node scripts/check_docs_tree.js
const fs = require( "fs" );
const path = require( "path" );
const vm = require( "vm" );

const root = path.join( __dirname , ".." );
const page = { console };
vm.createContext( page );
vm.runInContext( fs.readFileSync( path.join( root , "static" , "js" , "docs_tree.js" ) , "utf8" ) + "\nglobalThis.DocsTree = DocsTree;" , page );
const tree = page.DocsTree;
tree.saveOpened = () => {};
tree.render = () => {};

let failed = 0;
function check( name , ok ) {
  if ( !ok ) {
    failed += 1;
    console.error( "FAIL " + name );
  }
}

const folder = ( id , parent ) => [ id , { id: id , name: id.toUpperCase() , parent: parent , position: 0 } ];
tree.page = { max_depth: 16 };
tree.folders = new Map( [
  folder( "top" , "" ) , folder( "kid" , "top" ),
  folder( "a" , "b" ) , folder( "b" , "a" ) , folder( "self" , "self" ),
  // Under a parent the page does not have, as an access key's folder is.
  folder( "shared" , "owners" ) , folder( "inner" , "shared" ),
] );

const done = ( label , fn ) => {
  const started = Date.now();
  const result = fn();
  check( label + " ends" , Date.now() - started < 1000 );
  return result;
};

check( "a sound folder is not broken" , !tree.broken( "kid" ) );
check( "path of a sound folder" , tree.path( "kid" ) === "TOP / KID" );
check( "an access key's folder is not broken" , !tree.broken( "inner" ) && tree.path( "inner" ) === "SHARED / INNER" );
for ( const id of [ "a" , "b" , "self" ] ) {
  check( id + " in a loop is broken" , done( "broken " + id , () => tree.broken( id ) ) );
  const ids = done( "subtree " + id , () => tree.subtree( id ) );
  check( "subtree of " + id + " lists each once" , new Set( ids ).size === ids.length && ids.length <= 2 );
  done( "path " + id , () => tree.path( id ) );
  done( "reveal " + id , () => tree.reveal( id ) );
}
tree.opened = new Set();
tree.reveal( "kid" );
check( "reveal opens what is above" , tree.opened.has( "top" ) && !tree.opened.has( "kid" ) );

// A chain deeper than the server allows stops, too.
tree.page = { max_depth: 3 };
tree.folders = new Map( [ folder( "d1" , "" ) , folder( "d2" , "d1" ) , folder( "d3" , "d2" ) , folder( "d4" , "d3" ) , folder( "d5" , "d4" ) , folder( "d6" , "d5" ) ] );
check( "too deep is broken" , tree.broken( "d6" ) );
check( "deep subtree is cut at max_depth + 1" , tree.subtree( "d1" ).length === 4 );

if ( failed > 0 ) process.exit( 1 );
console.log( "ok: the folder tree survives a loop of parents" );
