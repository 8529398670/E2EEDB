package client

import (
	errors "errors"
	regexp "regexp"
)

// The id patterns the server takes (server/docstore). Ids go into each
// envelope's associated data as collection || 0 || id, and into URL paths,
// so a client checks every one before using it: a NUL in an id would make
// that join ambiguous, and an id from a link or a server reply could hold
// anything.
var (
	collectionIDPattern = regexp.MustCompile( `^[A-Za-z0-9_-]{1,64}$` )
	docIDPattern        = regexp.MustCompile( `^[A-Za-z0-9_-]{1,128}$` )
)

// ErrBadID: a collection or document id outside what the server takes.
var ErrBadID = errors.New( "e2eedb: not a valid collection or document id" )

// ValidCollectionID is whether id may name a collection: 1-64 of
// A-Z a-z 0-9 _ -.
func ValidCollectionID( id string ) bool { return collectionIDPattern.MatchString( id ) }

// ValidDocID is whether id may name a document: 1-128 of A-Z a-z 0-9 _ -.
func ValidDocID( id string ) bool { return docIDPattern.MatchString( id ) }

// checkIDs is ErrBadID unless collection and id are both valid.
func checkIDs( collection string , id string ) ( err error ) {
	if ValidCollectionID( collection ) == false || ValidDocID( id ) == false { err = ErrBadID }
	return
}
