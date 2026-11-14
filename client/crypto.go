package client

// The client's crypto: this file (the master key, its private envelope and
// the keyring) and crypto_collection.go (collection keys, their envelope and
// lockboxes) are the only files in this package that touch it.
// Every primitive is libsodium's, so the browser viewer (static/js/
// docs_crypto.js, libsodium.js) reads and writes exactly the same bytes:
//
//	crypto_generichash (keyed BLAKE2b)      = blake2b.New( size , key )
//	crypto_aead_xchacha20poly1305_ietf_*    = chacha20poly1305.NewX
//	crypto_pwhash (ALG_ARGON2ID13)          = argon2.IDKey( ... , threads 1 )
//
// README.md, "Crypto format", is the specification; change both sides or
// neither.

import (
	rand "crypto/rand"
	base64 "encoding/base64"
	json "encoding/json"
	errors "errors"
	fmt "fmt"

	argon2 "golang.org/x/crypto/argon2"
	blake2b "golang.org/x/crypto/blake2b"
	chacha20poly1305 "golang.org/x/crypto/chacha20poly1305"
)

const (
	// KeySize is the master key's length in bytes.
	KeySize = 32

	// EnvelopeMaster is the first byte of a private envelope: sealed by the
	// master key alone, so it can never be shared or opened by a scoped key.
	EnvelopeMaster = 0x01

	keyIDSize   = 16
	nonceSize   = chacha20poly1305.NonceSizeX
	headerSize  = 1 + keyIDSize
	envelopeMin = headerSize + nonceSize + chacha20poly1305.Overhead

	encLabel     = "e2eedb/master/enc"
	keyIDLabel   = "e2eedb/master/kid"
	keyringLabel = "e2eedb/keyring"

	// Argon2id cost for a new keyring: 2 passes over 32 MiB, above OWASP's
	// minimum for Argon2id and about 3.5 s in the browser's plain-JS
	// libsodium. A keyring records its own cost, so a keyring made with other
	// settings opens too.
	keyringOps = 2
	keyringMem = 32 * 1024 * 1024
	saltSize   = 16

	// What an unwrap accepts. A keyring comes from the server, which must not
	// be able to make a client spend unbounded time or memory.
	maxKeyringOps = 10
	minKeyringMem = 8 * 1024 * 1024
	maxKeyringMem = 1024 * 1024 * 1024
)

var (
	// ErrWrongKey: the document (or keyring) was sealed under another master
	// key, or the passphrase is wrong.
	ErrWrongKey = errors.New( "e2eedb: encrypted with a different key" )
	// ErrCorrupt: not an envelope this client reads, or it fails
	// authentication -- changed, or moved to another collection or id.
	ErrCorrupt = errors.New( "e2eedb: ciphertext is damaged or not where it was written" )
)

var b64 = base64.StdEncoding

// Key is a master key and the keys derived from it.
type Key struct {
	master [KeySize]byte
	enc    [chacha20poly1305.KeySize]byte
	id     [keyIDSize]byte
}

// GenerateKey makes a new random master key, base64-encoded. Keep it secret
// and keep a copy: nothing, the server included, can recover documents
// without it (or a passphrase set with SetPassphrase).
func GenerateKey() ( encoded string , err error ) {
	raw := make( []byte , KeySize )
	if _ , err = rand.Read( raw ); err != nil { return }
	encoded = b64.EncodeToString( raw )
	return
}

// ParseKey reads a base64 master key.
func ParseKey( encoded string ) ( key *Key , err error ) {
	raw , err := b64.DecodeString( encoded )
	if err != nil || len( raw ) != KeySize {
		err = fmt.Errorf( "e2eedb: a master key is %d bytes of standard base64" , KeySize )
		return
	}
	key = deriveKey( raw )
	return
}

func deriveKey( master []byte ) ( key *Key ) {
	key = &Key{}
	copy( key.master[ : ] , master )
	copy( key.enc[ : ] , generichash( chacha20poly1305.KeySize , master , encLabel ) )
	copy( key.id[ : ] , generichash( keyIDSize , master , keyIDLabel ) )
	return
}

// generichash is crypto_generichash( size , message , key ).
func generichash( size int , key []byte , message string ) ( sum []byte ) {
	hash , err := blake2b.New( size , key )
	if err != nil { panic( err ) } // sizes and key length are fixed above
	hash.Write( []byte( message ) )
	sum = hash.Sum( nil )
	return
}

// ID is the key's public id, base64: what an envelope names to say which key
// sealed it. It reveals nothing about the key.
func ( key *Key ) ID() string { return b64.EncodeToString( key.id[ : ] ) }

func ( key *Key ) header() ( header []byte ) {
	header = append( []byte{ EnvelopeMaster } , key.id[ : ]... )
	return
}

// associated binds a ciphertext to its place: the header, the collection and
// the id. A server that moves a body to another document makes it fail to
// open rather than show up somewhere it was never written.
func associated( header []byte , collection string , id string ) ( data []byte ) {
	data = append( append( []byte{} , header... ) , collection... )
	data = append( data , 0 )
	data = append( data , id... )
	return
}

// Seal encrypts plaintext for collection/id into a private envelope, which
// only this master key opens. Clients write collection envelopes
// (CollectionKey.Seal) by default; this is the other option.
func ( key *Key ) Seal( collection string , id string , plaintext []byte ) ( envelope []byte , err error ) {
	nonce := make( []byte , nonceSize )
	if _ , err = rand.Read( nonce ); err != nil { return }
	envelope , err = key.sealWithNonce( collection , id , plaintext , nonce )
	return
}

func ( key *Key ) sealWithNonce( collection string , id string , plaintext []byte , nonce []byte ) ( envelope []byte , err error ) {
	aead , err := chacha20poly1305.NewX( key.enc[ : ] )
	if err != nil { return }
	header := key.header()
	envelope = append( append( header , nonce... ) , aead.Seal( nil , nonce , plaintext , associated( header , collection , id ) )... )
	return
}

// Open decrypts a private envelope written for collection/id.
func ( key *Key ) Open( collection string , id string , envelope []byte ) ( plaintext []byte , err error ) {
	if len( envelope ) < envelopeMin || envelope[ 0 ] != EnvelopeMaster {
		err = ErrCorrupt
		return
	}
	header := envelope[ :headerSize ]
	if string( header[ 1: ] ) != string( key.id[ : ] ) {
		err = ErrWrongKey
		return
	}
	aead , err := chacha20poly1305.NewX( key.enc[ : ] )
	if err != nil { return }
	nonce := envelope[ headerSize : headerSize + nonceSize ]
	plaintext , err = aead.Open( nil , nonce , envelope[ headerSize + nonceSize: ] , associated( header , collection , id ) )
	if err != nil {
		err = ErrCorrupt
	}
	return
}

// keyring is the wrapped master key the server stores (README.md,
// "Keyring"). Byte fields are standard base64.
type keyring struct {
	Alg     string `json:"alg"`
	Ops     uint64 `json:"ops"`
	Mem     uint64 `json:"mem"`
	Salt    string `json:"salt"`
	Nonce   string `json:"nonce"`
	KeyID   string `json:"key_id"`
	Wrapped string `json:"wrapped"`
}

const keyringAlg = "argon2id13"

// passphraseKey is crypto_pwhash( 32 , passphrase , salt , ops , mem ,
// ALG_ARGON2ID13 ). The passphrase is taken as its UTF-8 bytes, as typed.
func passphraseKey( passphrase string , salt []byte , ops uint64 , mem uint64 ) ( key []byte ) {
	key = argon2.IDKey( []byte( passphrase ) , salt , uint32( ops ) , uint32( mem / 1024 ) , 1 , chacha20poly1305.KeySize )
	return
}

// WrapKey seals the master key under a passphrase, as the keyring text the
// server stores.
func ( key *Key ) WrapKey( passphrase string ) ( text string , err error ) {
	salt := make( []byte , saltSize )
	nonce := make( []byte , nonceSize )
	if _ , err = rand.Read( salt ); err != nil { return }
	if _ , err = rand.Read( nonce ); err != nil { return }
	text , err = key.wrapWith( passphrase , salt , nonce , keyringOps , keyringMem )
	return
}

func ( key *Key ) wrapWith( passphrase string , salt []byte , nonce []byte , ops uint64 , mem uint64 ) ( text string , err error ) {
	if passphrase == "" {
		err = errors.New( "e2eedb: the passphrase is empty" )
		return
	}
	aead , err := chacha20poly1305.NewX( passphraseKey( passphrase , salt , ops , mem ) )
	if err != nil { return }
	wrapped := aead.Seal( nil , nonce , key.master[ : ] , append( []byte( keyringLabel ) , key.id[ : ]... ) )
	encoded , err := json.Marshal( keyring{
		Alg: keyringAlg , Ops: ops , Mem: mem ,
		Salt: b64.EncodeToString( salt ) , Nonce: b64.EncodeToString( nonce ) ,
		KeyID: key.ID() , Wrapped: b64.EncodeToString( wrapped ) ,
	} )
	text = string( encoded )
	return
}

// UnwrapKey opens keyring text with a passphrase. A wrong passphrase is
// ErrWrongKey.
func UnwrapKey( text string , passphrase string ) ( key *Key , err error ) {
	var ring keyring
	if err = json.Unmarshal( []byte( text ) , &ring ); err != nil {
		err = ErrCorrupt
		return
	}
	if ring.Alg != keyringAlg || ring.Ops < 1 || ring.Ops > maxKeyringOps || ring.Mem < minKeyringMem || ring.Mem > maxKeyringMem {
		err = fmt.Errorf( "%w: unsupported keyring parameters" , ErrCorrupt )
		return
	}
	salt , salt_err := b64.DecodeString( ring.Salt )
	nonce , nonce_err := b64.DecodeString( ring.Nonce )
	id , id_err := b64.DecodeString( ring.KeyID )
	wrapped , wrapped_err := b64.DecodeString( ring.Wrapped )
	if errors.Join( salt_err , nonce_err , id_err , wrapped_err ) != nil || len( salt ) != saltSize || len( nonce ) != nonceSize || len( id ) != keyIDSize {
		err = ErrCorrupt
		return
	}
	aead , err := chacha20poly1305.NewX( passphraseKey( passphrase , salt , ring.Ops , ring.Mem ) )
	if err != nil { return }
	master , err := aead.Open( nil , nonce , wrapped , append( []byte( keyringLabel ) , id... ) )
	if err != nil || len( master ) != KeySize {
		err = ErrWrongKey
		return
	}
	key = deriveKey( master )
	if string( key.id[ : ] ) != string( id ) {
		key = nil
		err = ErrCorrupt
	}
	return
}

// Export is the master key, base64, for storing where the service keeps its
// secrets.
func ( key *Key ) Export() string { return b64.EncodeToString( key.master[ : ] ) }
