// Package client is the Go client for e2eedb: it encrypts JSON documents
// before they leave the process and decrypts them after they come back, so
// the server only ever holds ciphertext.
//
//	key , _ := client.GenerateKey()                 // once; store it as a secret
//	store , _ := client.New( "https://docs.example.com" , apiKey , key )
//	meta , err := store.Set( ctx , "invoices" , client.NewID() , invoice )
//	_ , err = store.Get( ctx , "invoices" , meta.ID , &invoice )
//
// Every account has one master key. Services hold it directly; a person can
// also unlock it with a passphrase in the browser, whose keyring only a
// signed-in browser reaches (WrapKey and UnwrapKey are its format). Each collection also has its own keys,
// wrapped in a lockbox the server stores: the master key opens every one,
// and an access token (NewScoped) opens one collection and the collections
// under it, read-only or read and write. The server sees collection names,
// document ids, sizes, versions and when things changed -- never contents or
// keys.
//
// The package depends only on the standard library and golang.org/x/crypto.
package client

import (
	bytes "bytes"
	context "context"
	rand "crypto/rand"
	base64 "encoding/base64"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	io "io"
	http "net/http"
	url "net/url"
	strconv "strconv"
	strings "strings"
	sync "sync"
	time "time"
)

// Errors the server answers with, beside ErrWrongKey and ErrCorrupt.
var (
	ErrNotFound    = errors.New( "e2eedb: no such document" )
	ErrConflict    = errors.New( "e2eedb: version conflict" )
	ErrTooLarge    = errors.New( "e2eedb: document too large" )
	ErrQuota       = errors.New( "e2eedb: quota exceeded" )
	ErrSyncExpired = errors.New( "e2eedb: sync expired, start again from 0" )
)

// ConflictError is ErrConflict with the version the server has now (0 and
// Live false when there is no live document).
type ConflictError struct {
	Current int64
	Live    bool
}

func ( conflict *ConflictError ) Error() string {
	return fmt.Sprintf( "e2eedb: version conflict (current version %d)" , conflict.Current )
}
func ( conflict *ConflictError ) Unwrap() error { return ErrConflict }

// APIError is any other refusal: the HTTP status and the server's message.
type APIError struct {
	Status  int
	Message string
}

func ( api *APIError ) Error() string {
	return fmt.Sprintf( "e2eedb: %d %s" , api.Status , api.Message )
}

// Meta is what the server knows about a document.
type Meta struct {
	Collection string    `json:"collection"`
	ID         string    `json:"id"`
	Version    int64     `json:"version"`
	Seq        int64     `json:"seq"`
	UpdatedAt  time.Time `json:"updated_at"`
	Size       int       `json:"size"`
	Deleted    bool      `json:"deleted"`
}

// Collection is one collection (folder). ID is what documents are filed
// under and never changes; Name, Parent and Position can. Parent "" is the
// top level. Count and Bytes are its own live documents, not its
// subfolders', and are only filled in by Collections.
type Collection struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Parent    string    `json:"parent"`
	Position  int       `json:"position"`
	Version   int64     `json:"version"`
	Count     int       `json:"count"`
	Bytes     int64     `json:"bytes"`
	UpdatedAt time.Time `json:"updated_at"`
	// Lock is the collection's lockbox ("" for none yet): its keys, wrapped
	// for its parent or the master key. The client opens it; the server
	// cannot.
	Lock string `json:"lock,omitempty"`
	// ByKey is set when the folder was made through an access token (a
	// scoped API key), not by the account itself.
	ByKey string `json:"by_key,omitempty"`
}

// NewCollection is what CreateCollection makes. Every field is optional: ID
// defaults to a random one, Name to the ID, Parent to the top level, and
// Before (the sibling to go in front of) to the end.
type NewCollection struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	Parent string `json:"parent,omitempty"`
	Before string `json:"before,omitempty"`
}

// Changes is one page of the sync feed.
type Changes struct {
	Changes   []Meta `json:"changes"`
	NextSince int64  `json:"next_since"`
	More      bool   `json:"more"`
}

// Client talks to one e2eedb server as one account, with that account's
// master key, or with an access token for one collection (NewScoped). It is
// safe for concurrent use.
type Client struct {
	base   string
	apiKey string
	key    *Key           // the master key; nil for a scoped client
	scope  *CollectionKey // a scoped client's collection
	http   *http.Client

	mutex sync.Mutex
	keys  map[ string ]*CollectionKey // opened lockboxes, by collection
	// byShare is the collections seen to have been made through an access
	// token (Collection.ByKey), which a master-key client does not write
	// into unless asked to (AllowShared).
	byShare map[ string ]bool
}

// Option changes how a Client is made.
type Option func( *Client )

// WithHTTPClient uses your own http.Client (timeouts, proxies, TLS).
func WithHTTPClient( client *http.Client ) Option {
	return func( target *Client ) { target.http = client }
}

// New makes a client. baseURL is the server's origin, apiKey an API key from
// its Account screen, masterKey the base64 key from GenerateKey.
func New( baseURL string , apiKey string , masterKey string , options ...Option ) ( client *Client , err error ) {
	key , err := ParseKey( masterKey )
	if err != nil { return }
	client = newClient( baseURL , apiKey , key , options )
	return
}

// NewScoped makes a client from an access token (NewAccessToken; the
// browser's Share dialog makes them): it reaches one collection and the
// collections under it, and writes only if the token carries the write key.
func NewScoped( baseURL string , token string , options ...Option ) ( client *Client , err error ) {
	api_key , key , err := ParseAccessToken( token )
	if err != nil { return }
	client = newClient( baseURL , api_key , nil , options )
	client.scope = key
	client.keys[ key.collection ] = key
	return
}

func newClient( baseURL string , apiKey string , key *Key , options []Option ) ( client *Client ) {
	client = &Client{ base: strings.TrimRight( baseURL , "/" ) , apiKey: apiKey , key: key , http: &http.Client{ Timeout: 30 * time.Second } , keys: map[ string ]*CollectionKey{} , byShare: map[ string ]bool{} }
	for _ , option := range options {
		option( client )
	}
	return
}

// Key is the client's master key; nil for a scoped client.
func ( client *Client ) Key() *Key { return client.key }

// Scope is a scoped client's collection keys; nil with a master key.
func ( client *Client ) Scope() *CollectionKey { return client.scope }

// NewID is a random document id: 22 URL-safe characters.
func NewID() string {
	raw := make( []byte , 16 )
	if _ , err := rand.Read( raw ); err != nil { panic( err ) }
	return base64.RawURLEncoding.EncodeToString( raw )
}

// WriteOption makes a write conditional.
type WriteOption func( *writeOptions )

type writeOptions struct {
	ifVersion   *int64
	allowShared bool
}

// AllowShared lets a master-key client write into a collection that was made
// through an access token. Without it such a write is ErrSharedCollection:
// someone holding a read/write access token can make a folder inside the one
// shared with them, and a service writing to a collection by id must not
// end up sealing its documents with keys that person holds.
func AllowShared() WriteOption {
	return func( options *writeOptions ) { options.allowShared = true }
}

// ErrSharedCollection: the collection written to was made through an access
// token, so its keys are known to that token's holder. Pass AllowShared to
// write there anyway.
var ErrSharedCollection = errors.New( "e2eedb: this collection was made through an access token; pass AllowShared to write into it" )

// writeKey is the key a write to collection seals with, refusing a
// collection made through an access token unless options allow it.
func ( client *Client ) writeKey( ctx context.Context , collection string , options []WriteOption ) ( key *CollectionKey , err error ) {
	if key , err = client.CollectionKey( ctx , collection , true ); err != nil { return }
	if client.key != nil && client.madeByShare( collection ) && writeOpts( options ).allowShared == false {
		key , err = nil , ErrSharedCollection
	}
	return
}

// IfVersion writes only if the document is at version n.
func IfVersion( n int64 ) WriteOption {
	return func( options *writeOptions ) { options.ifVersion = &n }
}

// MustNotExist creates only: it fails with a ConflictError if there is a
// live document there already.
func MustNotExist() WriteOption { return IfVersion( 0 ) }

func writeOpts( options []WriteOption ) ( result writeOptions ) {
	for _ , option := range options {
		option( &result )
	}
	return
}

func docPath( collection string , id string ) string {
	return "/api/collections/" + url.PathEscape( collection ) + "/docs/" + url.PathEscape( id )
}

// Set encrypts value as JSON and stores it at collection/id.
func ( client *Client ) Set( ctx context.Context , collection string , id string , value any , options ...WriteOption ) ( meta Meta , err error ) {
	plaintext , err := json.Marshal( value )
	if err != nil { return }
	key , err := client.writeKey( ctx , collection , options )
	if err != nil { return }
	envelope , err := key.Seal( id , plaintext )
	if err != nil { return }
	request := map[string]any{ "body": b64.EncodeToString( envelope ) }
	if opts := writeOpts( options ); opts.ifVersion != nil {
		request[ "if_version" ] = *opts.ifVersion
	}
	err = client.call( ctx , http.MethodPost , docPath( collection , id ) , request , &meta )
	return
}

// Get fetches collection/id and decodes it into out (any json.Unmarshal
// target; a *json.RawMessage keeps the JSON as it is).
func ( client *Client ) Get( ctx context.Context , collection string , id string , out any ) ( meta Meta , err error ) {
	var reply struct {
		Meta
		Body string `json:"body"`
	}
	if err = client.call( ctx , http.MethodGet , docPath( collection , id ) , nil , &reply ); err != nil { return }
	meta = reply.Meta
	err = client.open( ctx , collection , id , meta , reply.Body , out )
	return
}

// open decrypts body as collection/id: where it was asked for, never where
// the server's reply says it is, so a server cannot answer with a document
// from somewhere else. A reply naming another place is ErrCorrupt.
func ( client *Client ) open( ctx context.Context , collection string , id string , meta Meta , body string , out any ) ( err error ) {
	if meta.Collection != collection || meta.ID != id { return ErrCorrupt }
	envelope , err := b64.DecodeString( body )
	if err != nil { return ErrCorrupt }
	plaintext , err := client.openEnvelope( ctx , collection , id , envelope )
	if err != nil { return }
	err = json.Unmarshal( plaintext , out )
	return
}

// openEnvelope opens either kind: a private envelope with the master key, a
// collection envelope with the collection's keys.
func ( client *Client ) openEnvelope( ctx context.Context , collection string , id string , envelope []byte ) ( plaintext []byte , err error ) {
	switch EnvelopeKind( envelope ) {
	case EnvelopeMaster:
		if client.key == nil {
			// Only the master key opens a private envelope, until its owner
			// shares the collection (PrepareShare seals it again).
			err = ErrWrongKey
			return
		}
		plaintext , err = client.key.Open( collection , id , envelope )
	case EnvelopeCollection:
		key , key_err := client.CollectionKey( ctx , collection , false )
		if key_err != nil { return nil , key_err }
		plaintext , err = key.Open( id , envelope )
	default:
		err = ErrCorrupt
	}
	return
}

// Delete deletes collection/id. Syncing clients see it as a change with
// Deleted set.
func ( client *Client ) Delete( ctx context.Context , collection string , id string , options ...WriteOption ) ( meta Meta , err error ) {
	request := map[string]any{}
	if opts := writeOpts( options ); opts.ifVersion != nil {
		request[ "if_version" ] = *opts.ifVersion
	}
	err = client.call( ctx , http.MethodPost , docPath( collection , id ) + "/delete" , request , &meta )
	return
}

// List is one page of a collection's documents, metadata only, by id.
// next is the offset of the following page, or -1 after the last.
func ( client *Client ) List( ctx context.Context , collection string , offset int , limit int ) ( docs []Meta , next int , err error ) {
	var reply struct {
		Docs []Meta `json:"docs"`
		Next *int   `json:"next"`
	}
	path := "/api/collections/" + url.PathEscape( collection ) + "/docs?" + pageQuery( offset , limit )
	if err = client.call( ctx , http.MethodGet , path , nil , &reply ); err != nil { return }
	docs = reply.Docs
	next = -1
	if reply.Next != nil { next = *reply.Next }
	return
}

// Each calls fn with every document in a collection, decrypted, a page at a
// time. Returning an error from fn stops it and is returned.
func ( client *Client ) Each( ctx context.Context , collection string , fn func( meta Meta , data json.RawMessage ) error ) ( err error ) {
	offset := 0
	for offset >= 0 {
		var reply struct {
			Docs []struct {
				Meta
				Body string `json:"body"`
			} `json:"docs"`
			Next *int `json:"next"`
		}
		path := "/api/collections/" + url.PathEscape( collection ) + "/docs?include_body=true&" + pageQuery( offset , 200 )
		if err = client.call( ctx , http.MethodGet , path , nil , &reply ); err != nil { return }
		for _ , row := range reply.Docs {
			var data json.RawMessage
			if err = client.open( ctx , collection , row.ID , row.Meta , row.Body , &data ); err != nil { return }
			if err = fn( row.Meta , data ); err != nil { return }
		}
		offset = -1
		if reply.Next != nil { offset = *reply.Next }
	}
	return
}

// Collections is every collection (folder), each parent's children together
// in their order.
func ( client *Client ) Collections( ctx context.Context ) ( collections []Collection , err error ) {
	offset := 0
	for offset >= 0 {
		var reply struct {
			Collections []Collection `json:"collections"`
			Next        *int         `json:"next"`
		}
		if err = client.call( ctx , http.MethodGet , "/api/collections?" + pageQuery( offset , 1000 ) , nil , &reply ); err != nil { return }
		collections = append( collections , reply.Collections... )
		offset = -1
		if reply.Next != nil { offset = *reply.Next }
	}
	return
}

func collectionPath( id string ) string {
	return "/api/collections/" + url.PathEscape( id )
}

// CreateCollection makes a folder. Writing a document into a collection id
// with no folder also makes one, at the top level, named after the id.
func ( client *Client ) CreateCollection( ctx context.Context , folder NewCollection ) ( collection Collection , err error ) {
	if folder.ID == "" { folder.ID = NewID() }
	holder , err := client.holder( ctx , nil , folder.Parent , true )
	if err != nil { return }
	key , err := generateCollectionKey( folder.ID )
	if err != nil { return }
	lock , err := sealLock( key , holder )
	if err != nil { return }
	request := map[string]any{ "id": folder.ID , "lock": lock }
	if folder.Name != "" { request[ "name" ] = folder.Name }
	if folder.Parent != "" { request[ "parent" ] = folder.Parent }
	if folder.Before != "" { request[ "before" ] = folder.Before }
	if err = client.call( ctx , http.MethodPost , "/api/collections" , request , &collection ); err != nil { return }
	client.remember( key )
	return
}

// RenameCollection gives a folder a new name. Its id, and so its documents,
// stay as they are.
func ( client *Client ) RenameCollection( ctx context.Context , id string , name string ) ( collection Collection , err error ) {
	err = client.call( ctx , http.MethodPost , collectionPath( id ) , map[string]any{ "name": name } , &collection )
	return
}

// MoveCollection puts a folder under parent ("" for the top level), in front
// of the sibling before ("" for the end).
//
// A collection with its own keys gets its lockbox wrapped again for the new
// parent, so that parent's keys reach it: that needs write access to the
// collection and to its new parent (the master key, for the top level).
func ( client *Client ) MoveCollection( ctx context.Context , id string , parent string , before string ) ( collection Collection , err error ) {
	request := map[string]any{ "parent": parent , "before": before }
	tree , err := client.tree( ctx )
	if err != nil { return }
	if entry , found := tree[ id ]; found && entry.Lock != "" && entry.Parent != parent {
		key , key_err := client.resolve( ctx , tree , id , false )
		if key_err != nil { return collection , key_err }
		holder , holder_err := client.holder( ctx , tree , parent , true )
		if holder_err != nil { return collection , holder_err }
		lock , lock_err := sealLock( key , holder )
		if lock_err != nil { return collection , lock_err }
		request[ "lock" ] = lock
	}
	err = client.call( ctx , http.MethodPost , collectionPath( id ) , request , &collection )
	return
}

// DeleteCollection deletes a folder, every folder under it and every
// document in them, and answers the ids of the folders removed.
func ( client *Client ) DeleteCollection( ctx context.Context , id string ) ( removed []string , err error ) {
	var reply struct {
		Collections []string `json:"collections"`
	}
	err = client.call( ctx , http.MethodPost , collectionPath( id ) + "/delete" , map[string]any{} , &reply )
	removed = reply.Collections
	return
}

// MoveDoc moves collection/id into the folder to, keeping its id. The
// document is opened and sealed again for its new place (its encryption is
// bound to where it is), then moved in one step on the server. Without an
// IfVersion option it only moves the version it read. A live document
// already at the destination is a ConflictError.
func ( client *Client ) MoveDoc( ctx context.Context , collection string , id string , to string , options ...WriteOption ) ( meta Meta , err error ) {
	var current struct {
		Meta
		Body string `json:"body"`
	}
	if err = client.call( ctx , http.MethodGet , docPath( collection , id ) , nil , &current ); err != nil { return }
	envelope , err := b64.DecodeString( current.Body )
	if err != nil { return meta , ErrCorrupt }
	plaintext , err := client.openEnvelope( ctx , collection , id , envelope )
	if err != nil { return }
	key , err := client.writeKey( ctx , to , options )
	if err != nil { return }
	sealed , err := key.Seal( id , plaintext )
	if err != nil { return }
	if_version := current.Version
	if opts := writeOpts( options ); opts.ifVersion != nil { if_version = *opts.ifVersion }
	request := map[string]any{ "to_collection": to , "body": b64.EncodeToString( sealed ) , "if_version": if_version }
	var reply struct {
		Doc Meta `json:"doc"`
	}
	err = client.call( ctx , http.MethodPost , docPath( collection , id ) + "/move" , request , &reply )
	meta = reply.Doc
	return
}

// Changes is what changed after since (0 for everything), oldest first, up
// to limit (1-1000). Keep calling with NextSince while More is true; save
// NextSince for the next sync. ErrSyncExpired means start again from 0.
func ( client *Client ) Changes( ctx context.Context , since int64 , limit int ) ( changes Changes , err error ) {
	path := "/api/changes?since=" + strconv.FormatInt( since , 10 ) + "&limit=" + strconv.Itoa( limit )
	err = client.call( ctx , http.MethodGet , path , nil , &changes )
	return
}

func pageQuery( offset int , limit int ) string {
	return "offset=" + strconv.Itoa( offset ) + "&limit=" + strconv.Itoa( limit )
}

// call sends one request and decodes the reply into out, or turns a refusal
// into the matching error.
func ( client *Client ) call( ctx context.Context , method string , path string , body any , out any ) ( err error ) {
	var reader io.Reader
	if body != nil {
		encoded , marshal_err := json.Marshal( body )
		if marshal_err != nil { return marshal_err }
		reader = bytes.NewReader( encoded )
	}
	request , err := http.NewRequestWithContext( ctx , method , client.base + path , reader )
	if err != nil { return }
	request.Header.Set( "Authorization" , "Bearer " + client.apiKey )
	request.Header.Set( "Accept" , "application/json" )
	if body != nil {
		request.Header.Set( "Content-Type" , "application/json" )
	}
	response , err := client.http.Do( request )
	if err != nil { return }
	defer response.Body.Close()
	raw , err := io.ReadAll( io.LimitReader( response.Body , 64 << 20 ) )
	if err != nil { return }
	if response.StatusCode >= 200 && response.StatusCode < 300 {
		if out != nil {
			err = json.Unmarshal( raw , out )
		}
		return
	}
	var refusal struct {
		Error          string `json:"error"`
		CurrentVersion int64  `json:"current_version"`
		Live           bool   `json:"live"`
	}
	json.Unmarshal( raw , &refusal )
	switch {
	case response.StatusCode == http.StatusConflict && refusal.Error == "version_conflict":
		err = &ConflictError{ Current: refusal.CurrentVersion , Live: refusal.Live }
	case response.StatusCode == http.StatusNotFound && strings.HasPrefix( path , "/api/" ) && refusal.Error == "no such document":
		err = ErrNotFound
	case refusal.Error == "doc_too_large":
		err = ErrTooLarge
	case refusal.Error == "quota_exceeded":
		err = ErrQuota
	case refusal.Error == "sync_expired":
		err = ErrSyncExpired
	case response.StatusCode == http.StatusForbidden && refusal.Error == "read_only":
		err = ErrReadOnly
	default:
		message := refusal.Error
		if message == "" { message = strings.TrimSpace( string( raw ) ) }
		err = &APIError{ Status: response.StatusCode , Message: message }
	}
	return
}
