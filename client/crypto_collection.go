package client

// Collection keys (README.md, "Crypto format"). Every collection
// has its own read key and its own write (signing) key. The master key opens
// the top-level collections' lockboxes, and each collection's keys open its
// children's, so a collection key reaches its own subtree and nothing else.
// A read key opens documents; only the write key can sign one a reader will
// accept, so a read-only holder cannot forge a document even with the
// server's help.
//
//	read key  rk (32 random bytes)
//	  enc     = BLAKE2b-256( key = rk , "e2eedb/collection/enc" )
//	  key_id  = BLAKE2b-128( key = rk , "e2eedb/collection/kid" )
//	write key ws (32 random bytes, an Ed25519 seed) -> verify key vk
//
// Like crypto.go, every primitive is libsodium's, so the browser
// (static/js/docs_crypto.js) reads and writes the same bytes; Ed25519 is
// crypto_sign_seed_keypair / crypto_sign_detached.

import (
	ed25519 "crypto/ed25519"
	hmac "crypto/hmac"
	rand "crypto/rand"
	base64 "encoding/base64"
	binary "encoding/binary"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	strings "strings"
	time "time"

	chacha20poly1305 "golang.org/x/crypto/chacha20poly1305"
)

const (
	// EnvelopeCollection is the first byte of a collection envelope: sealed
	// by a collection's read key and signed by its write key. Every write
	// uses it unless asked for a private envelope (Key.Seal).
	EnvelopeCollection = 0x02

	signatureLen          = ed25519.SignatureSize
	envelopeCollectionMin = headerSize + nonceSize + chacha20poly1305.Overhead + signatureLen

	collectionEncLabel = "e2eedb/collection/enc"
	collectionKIDLabel = "e2eedb/collection/kid"
	wrapReadLabel      = "e2eedb/lock/wrap-r"
	wrapWriteLabel     = "e2eedb/lock/wrap-w"
	lockReadLabel      = "e2eedb/lock/read"
	lockWriteLabel     = "e2eedb/lock/write"
	lockSignLabel      = "e2eedb/lock/sign"
	lockSeedLabel      = "e2eedb/lock/sign-seed"
	lockOwnLabel       = "e2eedb/lock/own"

	// AccessTokenPrefix starts every access token (NewAccessToken).
	AccessTokenPrefix = "e2eedb-ck."
)

// ErrReadOnly: the key in hand can read here but not write (no write key),
// or the server refused a write for the same reason.
var ErrReadOnly = errors.New( "e2eedb: this key is read-only" )

// CollectionKey is one collection's keys: always the read half, and the
// write half when the holder may write. It opens that collection's documents
// and, through their lockboxes, its sub-collections'.
type CollectionKey struct {
	collection string
	read       [32]byte
	enc        [chacha20poly1305.KeySize]byte
	id         [keyIDSize]byte
	verify     ed25519.PublicKey
	sign       ed25519.PrivateKey // nil: read-only
	// epoch is the lockbox epoch these keys carry (README.md,
	// "Lockboxes"); 0 for keys from an access token, which name none.
	epoch      uint64
	// owned is whether these keys are the master key's own: their lockbox
	// carries its owner tag, and so does every lockbox above it. Set when
	// they are opened or made; always false for a scoped client.
	owned      bool
}

// maxEpoch is the highest epoch a lockbox may carry: the largest integer a
// browser's numbers hold exactly.
const maxEpoch = 1 << 53 - 1

// freshEpoch is the epoch for keys made now: the time in seconds, or one
// more than above (the highest this client has seen for the collection)
// when that is later. Each rotation then adds one, so a collection made
// again under an old id starts above anything it had before.
func freshEpoch( above uint64 ) uint64 {
	return max( uint64( time.Now().Unix() ) , above + 1 )
}

// Epoch is the lockbox epoch of these keys: when they were made, plus one
// for every rotation since. 0 for keys from an access token.
func ( key *CollectionKey ) Epoch() uint64 { return key.epoch }

func newCollectionKey( collection string , read []byte , verify []byte , seed []byte ) ( key *CollectionKey , err error ) {
	if len( read ) != 32 || len( verify ) != ed25519.PublicKeySize || ( seed != nil && len( seed ) != ed25519.SeedSize ) {
		err = ErrCorrupt
		return
	}
	key = &CollectionKey{ collection: collection , verify: append( ed25519.PublicKey{} , verify... ) }
	copy( key.read[ : ] , read )
	copy( key.enc[ : ] , generichash( chacha20poly1305.KeySize , read , collectionEncLabel ) )
	copy( key.id[ : ] , generichash( keyIDSize , read , collectionKIDLabel ) )
	if seed != nil {
		key.sign = ed25519.NewKeyFromSeed( seed )
		if string( key.sign.Public().( ed25519.PublicKey ) ) != string( key.verify ) {
			key , err = nil , ErrCorrupt
		}
	}
	return
}

// generateCollectionKey makes fresh keys for collection, to carry epoch.
func generateCollectionKey( collection string , epoch uint64 ) ( key *CollectionKey , err error ) {
	read := make( []byte , 32 )
	seed := make( []byte , ed25519.SeedSize )
	if _ , err = rand.Read( read ); err != nil { return }
	if _ , err = rand.Read( seed ); err != nil { return }
	verify := ed25519.NewKeyFromSeed( seed ).Public().( ed25519.PublicKey )
	if key , err = newCollectionKey( collection , read , verify , seed ); err == nil {
		key.epoch = epoch
	}
	return
}

// Collection is the collection these keys belong to.
func ( key *CollectionKey ) Collection() string { return key.collection }

// CanWrite is whether this holds the write half.
func ( key *CollectionKey ) CanWrite() bool { return key.sign != nil }

// ID is the read key's public id, base64, as an envelope names it.
func ( key *CollectionKey ) ID() string { return b64.EncodeToString( key.id[ : ] ) }

// ReadOnly is the same keys without the write half.
func ( key *CollectionKey ) ReadOnly() ( result *CollectionKey ) {
	copied := *key
	copied.sign = nil
	result = &copied
	return
}

func ( key *CollectionKey ) header() []byte {
	return append( []byte{ EnvelopeCollection } , key.id[ : ]... )
}

// signed is what a collection envelope's signature covers: the envelope before the signature,
// then where the document lives.
func signed( body []byte , collection string , id string ) []byte {
	data := append( append( []byte{} , body... ) , collection... )
	data = append( data , 0 )
	return append( data , id... )
}

// Seal encrypts and signs plaintext as document id in this collection.
func ( key *CollectionKey ) Seal( id string , plaintext []byte ) ( envelope []byte , err error ) {
	nonce := make( []byte , nonceSize )
	if _ , err = rand.Read( nonce ); err != nil { return }
	envelope , err = key.sealWithNonce( id , plaintext , nonce )
	return
}

func ( key *CollectionKey ) sealWithNonce( id string , plaintext []byte , nonce []byte ) ( envelope []byte , err error ) {
	if key.sign == nil {
		err = ErrReadOnly
		return
	}
	aead , err := chacha20poly1305.NewX( key.enc[ : ] )
	if err != nil { return }
	header := key.header()
	body := append( append( header , nonce... ) , aead.Seal( nil , nonce , plaintext , associated( header , key.collection , id ) )... )
	envelope = append( body , ed25519.Sign( key.sign , signed( body , key.collection , id ) )... )
	return
}

// Open checks the signature and decrypts a collection envelope written as id
// in this collection.
func ( key *CollectionKey ) Open( id string , envelope []byte ) ( plaintext []byte , err error ) {
	if len( envelope ) < envelopeCollectionMin || envelope[ 0 ] != EnvelopeCollection {
		err = ErrCorrupt
		return
	}
	header := envelope[ :headerSize ]
	if string( header[ 1: ] ) != string( key.id[ : ] ) {
		err = ErrWrongKey
		return
	}
	body := envelope[ :len( envelope ) - signatureLen ]
	if ed25519.Verify( key.verify , signed( body , key.collection , id ) , envelope[ len( body ): ] ) == false {
		err = ErrCorrupt
		return
	}
	aead , err := chacha20poly1305.NewX( key.enc[ : ] )
	if err != nil { return }
	nonce := body[ headerSize : headerSize + nonceSize ]
	plaintext , err = aead.Open( nil , nonce , body[ headerSize + nonceSize: ] , associated( header , key.collection , id ) )
	if err != nil {
		err = ErrCorrupt
	}
	return
}

// EnvelopeKind is an envelope's first byte: EnvelopeMaster or
// EnvelopeCollection, 0 if empty.
func EnvelopeKind( envelope []byte ) byte {
	if len( envelope ) == 0 { return 0 }
	return envelope[ 0 ]
}

// A lockHolder wraps lockboxes: the master key (for top-level collections)
// or a parent collection's keys. parent is what the lockbox records.
type lockHolder interface {
	lockParent() string
	ID() string // which key wraps it, so a wrong one is ErrWrongKey
	wrapRead() []byte
	wrapWrite() []byte // nil: cannot wrap or unwrap write halves
	lockSigner() ed25519.PrivateKey // nil: cannot sign lockboxes
	lockVerifier() ed25519.PublicKey
}

func ( key *Key ) lockParent() string { return "" }
func ( key *Key ) wrapRead() []byte   { return generichash( 32 , key.master[ : ] , wrapReadLabel ) }
func ( key *Key ) wrapWrite() []byte  { return generichash( 32 , key.master[ : ] , wrapWriteLabel ) }

// The master key signs top-level lockboxes with a key of its own, derived
// from it: lock_seed = BLAKE2b-256( key = M , "e2eedb/lock/sign-seed" ).
func ( key *Key ) lockSigner() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed( generichash( ed25519.SeedSize , key.master[ : ] , lockSeedLabel ) )
}
func ( key *Key ) lockVerifier() ed25519.PublicKey {
	return key.lockSigner().Public().( ed25519.PublicKey )
}

func ( key *CollectionKey ) lockParent() string { return key.collection }
func ( key *CollectionKey ) wrapRead() []byte   { return generichash( 32 , key.read[ : ] , wrapReadLabel ) }
func ( key *CollectionKey ) wrapWrite() []byte {
	if key.sign == nil { return nil }
	return generichash( 32 , key.sign.Seed() , wrapWriteLabel )
}

// A collection signs its children's lockboxes with its write key, and they
// are checked against its verify key, which read-only holders have too.
func ( key *CollectionKey ) lockSigner() ed25519.PrivateKey { return key.sign }
func ( key *CollectionKey ) lockVerifier() ed25519.PublicKey { return key.verify }

// lockbox is the text the server stores beside a collection. Byte fields are
// standard base64.
type lockbox struct {
	Parent string `json:"parent"`
	By     string `json:"by"`
	KeyID  string `json:"key_id"`
	// Epoch says how new these keys are (freshEpoch; a rotation's are one
	// more than the ones they replace). The sig covers it.
	Epoch  uint64 `json:"epoch"`
	NonceR string `json:"nonce_r"`
	Read   string `json:"read"`
	NonceW string `json:"nonce_w"`
	Write  string `json:"write"`
	Sig    string `json:"sig"`
	// Own is the owner's tag (Key.ownTag): set when the master key made
	// these keys, so its clients can tell the folders the account made from
	// ones made through an access token without asking the server.
	Own string `json:"own,omitempty"`
}

// ownTag is what says the master key made collection's keys (key_id): a MAC
// only the master key can make or check.
//
//	own = BLAKE2b-256( key = M , "e2eedb/lock/own" || 0 || c || 0 || key_id (16) )
//
// The lockbox's sig does not cover it, so whoever re-wraps a lockbox for a
// move (a write-key holder) carries it over as it is; it names the keys, not
// the parent, so it stays true. Nobody without M can make one for other keys.
func ( key *Key ) ownTag( collection string , key_id []byte ) string {
	message := lockOwnLabel + "\x00" + collection + "\x00" + string( key_id )
	return b64.EncodeToString( generichash( 32 , key.master[ : ] , message ) )
}

// owns is whether lockbox text holds this master key's tag for collection.
func ( key *Key ) owns( text string , collection string ) bool {
	var box lockbox
	if json.Unmarshal( []byte( text ) , &box ) != nil || box.Own == "" { return false }
	key_id , err := b64.DecodeString( box.KeyID )
	if err != nil || len( key_id ) != keyIDSize { return false }
	return hmac.Equal( []byte( box.Own ) , []byte( key.ownTag( collection , key_id ) ) )
}

// lockOwn is the owner's tag a lockbox carries, "" for none.
func lockOwn( text string ) string {
	var box lockbox
	json.Unmarshal( []byte( text ) , &box )
	return box.Own
}

func lockAD( label string , collection string , parent string ) []byte {
	data := append( []byte( label ) , 0 )
	data = append( data , collection... )
	data = append( data , 0 )
	return append( data , parent... )
}

// lockSigned is what a lockbox's sig covers: where it belongs, which keys it
// holds and how new they are, and both wrapped halves.
//
//	"e2eedb/lock/sign" || 0 || c || 0 || parent || 0 || key_id (16) || epoch (8, big-endian) || nonce_r || read || nonce_w || write
func lockSigned( collection string , parent string , key_id []byte , epoch uint64 , nonce_r []byte , read []byte , nonce_w []byte , write []byte ) []byte {
	data := append( []byte( lockSignLabel ) , 0 )
	data = append( append( data , collection... ) , 0 )
	data = append( append( data , parent... ) , 0 )
	data = append( data , key_id... )
	data = binary.BigEndian.AppendUint64( data , epoch )
	for _ , part := range [][]byte{ nonce_r , read , nonce_w , write } {
		data = append( data , part... )
	}
	return data
}

// sealLock wraps key's halves for holder and signs them. Both must be able
// to write. own is the owner's tag to carry (Key.ownTag), "" for none.
func sealLock( key *CollectionKey , holder lockHolder , own string ) ( text string , err error ) {
	nonce_r := make( []byte , nonceSize )
	nonce_w := make( []byte , nonceSize )
	if _ , err = rand.Read( nonce_r ); err != nil { return }
	if _ , err = rand.Read( nonce_w ); err != nil { return }
	text , err = sealLockWith( key , holder , nonce_r , nonce_w , own )
	return
}

func sealLockWith( key *CollectionKey , holder lockHolder , nonce_r []byte , nonce_w []byte , own string ) ( text string , err error ) {
	wrap_write := holder.wrapWrite()
	if key.sign == nil || wrap_write == nil {
		err = ErrReadOnly
		return
	}
	if key.epoch < 1 || key.epoch > maxEpoch {
		err = fmt.Errorf( "%w: lockbox epoch %d" , ErrCorrupt , key.epoch )
		return
	}
	parent := holder.lockParent()
	read_aead , err := chacha20poly1305.NewX( holder.wrapRead() )
	if err != nil { return }
	write_aead , err := chacha20poly1305.NewX( wrap_write )
	if err != nil { return }
	read := read_aead.Seal( nil , nonce_r , append( append( []byte{} , key.read[ : ]... ) , key.verify... ) , lockAD( lockReadLabel , key.collection , parent ) )
	write := write_aead.Seal( nil , nonce_w , key.sign.Seed() , lockAD( lockWriteLabel , key.collection , parent ) )
	box := lockbox{
		Parent: parent , By: holder.ID() , KeyID: key.ID() , Epoch: key.epoch ,
		NonceR: b64.EncodeToString( nonce_r ) , Read: b64.EncodeToString( read ) ,
		NonceW: b64.EncodeToString( nonce_w ) , Write: b64.EncodeToString( write ) ,
		Sig: b64.EncodeToString( ed25519.Sign( holder.lockSigner() , lockSigned( key.collection , parent , key.id[ : ] , key.epoch , nonce_r , read , nonce_w , write ) ) ) ,
		Own: own ,
	}
	encoded , err := json.Marshal( box )
	text = string( encoded )
	return
}

// openLock opens collection's lockbox with holder: the read half always, the
// write half when holder has one. A lockbox wrapped by another key is
// ErrWrongKey; one made for another place, or changed, is ErrCorrupt.
func openLock( text string , collection string , holder lockHolder ) ( key *CollectionKey , err error ) {
	var box lockbox
	if err = json.Unmarshal( []byte( text ) , &box ); err != nil {
		err = ErrCorrupt
		return
	}
	parent := holder.lockParent()
	if box.Parent != parent {
		err = fmt.Errorf( "%w: lockbox is for another parent" , ErrCorrupt )
		return
	}
	if box.By != holder.ID() {
		err = ErrWrongKey
		return
	}
	if box.Epoch < 1 || box.Epoch > maxEpoch {
		err = fmt.Errorf( "%w: lockbox epoch" , ErrCorrupt )
		return
	}
	nonce_r , nonce_r_err := b64.DecodeString( box.NonceR )
	read , read_err := b64.DecodeString( box.Read )
	if errors.Join( nonce_r_err , read_err ) != nil || len( nonce_r ) != nonceSize {
		err = ErrCorrupt
		return
	}
	key_id , id_err := b64.DecodeString( box.KeyID )
	nonce_w , nonce_w_err := b64.DecodeString( box.NonceW )
	write , write_err := b64.DecodeString( box.Write )
	sig , sig_err := b64.DecodeString( box.Sig )
	if errors.Join( id_err , nonce_w_err , write_err , sig_err ) != nil || len( sig ) != signatureLen ||
		ed25519.Verify( holder.lockVerifier() , lockSigned( collection , parent , key_id , box.Epoch , nonce_r , read , nonce_w , write ) , sig ) == false {
		err = fmt.Errorf( "%w: lockbox signature" , ErrCorrupt )
		return
	}
	read_aead , err := chacha20poly1305.NewX( holder.wrapRead() )
	if err != nil { return }
	opened , err := read_aead.Open( nil , nonce_r , read , lockAD( lockReadLabel , collection , parent ) )
	if err != nil || len( opened ) != 32 + ed25519.PublicKeySize {
		err = ErrCorrupt
		return
	}
	var seed []byte
	if wrap_write := holder.wrapWrite(); wrap_write != nil {
		if len( nonce_w ) != nonceSize {
			err = ErrCorrupt
			return
		}
		write_aead , aead_err := chacha20poly1305.NewX( wrap_write )
		if aead_err != nil { return nil , aead_err }
		if seed , err = write_aead.Open( nil , nonce_w , write , lockAD( lockWriteLabel , collection , parent ) ); err != nil {
			err = ErrCorrupt
			return
		}
	}
	key , err = newCollectionKey( collection , opened[ :32 ] , opened[ 32: ] , seed )
	if err == nil && key.ID() != box.KeyID {
		key , err = nil , ErrCorrupt
	}
	if err == nil {
		key.epoch = box.Epoch
	}
	return
}

// accessToken is what NewAccessToken encodes.
type accessToken struct {
	APIKey     string `json:"k"`
	Collection string `json:"c"`
	Read       string `json:"r"`
	Verify     string `json:"v"`
	Write      string `json:"w,omitempty"`
}

// NewAccessToken is the one string to hand someone: a scoped API key (made
// on the Account screen, or by the browser's Share dialog) together with a
// collection's keys. With a read-only key it carries only the read half.
// Only the API key part is ever sent to the server.
func NewAccessToken( apiKey string , key *CollectionKey ) ( token string , err error ) {
	if apiKey == "" {
		err = errors.New( "e2eedb: an access token needs an API key" )
		return
	}
	payload := accessToken{
		APIKey: apiKey , Collection: key.collection ,
		Read: b64.EncodeToString( key.read[ : ] ) , Verify: b64.EncodeToString( key.verify ) ,
	}
	if key.sign != nil {
		payload.Write = b64.EncodeToString( key.sign.Seed() )
	}
	encoded , err := json.Marshal( payload )
	if err != nil { return }
	token = AccessTokenPrefix + base64.RawURLEncoding.EncodeToString( encoded )
	return
}

// ParseAccessToken splits an access token into its API key and collection
// keys.
func ParseAccessToken( token string ) ( apiKey string , key *CollectionKey , err error ) {
	bad := errors.New( "e2eedb: not an access token" )
	rest , found := strings.CutPrefix( strings.TrimSpace( token ) , AccessTokenPrefix )
	if found == false { return "" , nil , bad }
	raw , err := base64.RawURLEncoding.DecodeString( rest )
	if err != nil { return "" , nil , bad }
	var payload accessToken
	if err = json.Unmarshal( raw , &payload ); err != nil || payload.APIKey == "" || payload.Collection == "" {
		return "" , nil , bad
	}
	read , read_err := b64.DecodeString( payload.Read )
	verify , verify_err := b64.DecodeString( payload.Verify )
	var seed []byte
	var seed_err error
	if payload.Write != "" {
		seed , seed_err = b64.DecodeString( payload.Write )
	}
	if errors.Join( read_err , verify_err , seed_err ) != nil {
		return "" , nil , bad
	}
	if key , err = newCollectionKey( payload.Collection , read , verify , seed ); err != nil {
		return "" , nil , bad
	}
	apiKey = payload.APIKey
	return
}
