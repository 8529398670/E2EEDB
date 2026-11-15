package docstore

import (
	bytes "bytes"
	base64 "encoding/base64"
	json "encoding/json"
	errors "errors"
)

// ErrBadLock: a lockbox that is not one. The server cannot open a lockbox,
// but it checks the shape of every one it is given (README.md, "Lockboxes"):
// one it could not read a key id from would wedge a rotation and turn off
// the stale_key check for its folder.
var ErrBadLock = errors.New( "bad_lock" )

// The sizes of a lockbox's byte fields, decoded.
const (
	lockKeyIDBytes = 16
	lockNonceBytes = 24
	// rk (32) and vk (32), sealed.
	lockReadBytes  = 32 + 32 + 16
	// ws (32), sealed.
	lockWriteBytes = 32 + 16
	lockSigBytes   = 64
	lockOwnBytes   = 32
	// lockMaxEpoch is what a browser's numbers hold exactly.
	lockMaxEpoch   = 1<<53 - 1
)

// lockbox is the shape of a lockbox, as far as the server reads it.
type lockbox struct {
	Parent *string `json:"parent"`
	By     string  `json:"by"`
	KeyID  string  `json:"key_id"`
	Epoch  uint64  `json:"epoch"`
	NonceR string  `json:"nonce_r"`
	Read   string  `json:"read"`
	NonceW string  `json:"nonce_w"`
	Write  string  `json:"write"`
	Sig    string  `json:"sig"`
	Own    string  `json:"own,omitempty"`
}

// checkLock is ErrBadLock unless lock is a lockbox for a folder under
// parent ("" for the top level): one JSON object, nothing after it, with
// every field the format has and each one the right size.
func checkLock( lock string , parent string ) ( err error ) {
	err = ErrBadLock
	if len( lock ) == 0 || len( lock ) > LockMaxBytes { return }
	decoder := json.NewDecoder( bytes.NewReader( []byte( lock ) ) )
	decoder.DisallowUnknownFields()
	var box lockbox
	if decoder.Decode( &box ) != nil || decoder.More() { return }
	if box.Parent == nil || *box.Parent != parent { return }
	if box.Epoch < 1 || box.Epoch > lockMaxEpoch { return }
	fields := []struct {
		text string
		size int
	}{
		{ box.By , lockKeyIDBytes } , { box.KeyID , lockKeyIDBytes } ,
		{ box.NonceR , lockNonceBytes } , { box.Read , lockReadBytes } ,
		{ box.NonceW , lockNonceBytes } , { box.Write , lockWriteBytes } ,
		{ box.Sig , lockSigBytes } ,
	}
	if box.Own != "" { fields = append( fields , struct {
		text string
		size int
	}{ box.Own , lockOwnBytes } ) }
	for _ , field := range fields {
		decoded , decode_err := base64.StdEncoding.Strict().DecodeString( field.text )
		if decode_err != nil || len( decoded ) != field.size { return }
	}
	err = nil
	return
}
