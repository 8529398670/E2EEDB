package client

// Lockbox epochs (README.md, "Rotating keys"). Every lockbox carries a
// signed epoch, and the lockbox a rotation stages carries one more than the
// keys it replaces. The client remembers the highest epoch it has seen for
// each collection, as a lock and as a next_lock, and refuses a lockbox below
// that (ErrRolledBack): a server cannot hand back the keys from before a
// rotation, which a revoked access token still holds, once this client has
// seen the rotation. Without WithState that memory lasts as long as the
// Client; a client with none (new, or its state file gone) cannot tell.

import (
	context "context"
	json "encoding/json"
	errors "errors"
	fmt "fmt"
	os "os"
	filepath "path/filepath"
)

// ErrRolledBack: the server answered with a collection's keys from before a
// change this client has already seen (a key rotation). They are refused.
var ErrRolledBack = errors.New( "e2eedb: the server sent a collection's keys from before a rotation this client has seen" )

// epochMark is the highest epochs seen for one collection.
type epochMark struct {
	Lock uint64 `json:"lock"`
	Next uint64 `json:"next"`
}

// WithState keeps the epochs this client has seen in a file at path (made
// with mode 0600, written atomically), so a restart still refuses a rolled
// back lockbox. One file can hold several accounts' and tokens'.
func WithState( path string ) Option {
	return func( target *Client ) { target.statePath = path }
}

// stateAccount names this client's part of the state file: its master
// key, or its access token's collection keys.
func ( client *Client ) stateAccount() string {
	if client.key != nil { return "key:" + client.key.ID() }
	return "token:" + client.scope.ID()
}

func readState( path string ) ( all map[ string ]map[ string ]epochMark , err error ) {
	all = map[ string ]map[ string ]epochMark{}
	raw , err := os.ReadFile( path )
	if errors.Is( err , os.ErrNotExist ) { return all , nil }
	if err != nil { return }
	if err = json.Unmarshal( raw , &all ); err != nil {
		err = fmt.Errorf( "e2eedb: state file %s: %w" , path , err )
	}
	return
}

// loadState reads what the state file remembers for this client.
func ( client *Client ) loadState() ( err error ) {
	if client.statePath == "" { return }
	all , err := readState( client.statePath )
	if err != nil { return }
	client.mutex.Lock()
	defer client.mutex.Unlock()
	for id , mark := range all[ client.stateAccount() ] {
		client.marks[ id ] = mark
	}
	return
}

// saveState writes this client's epochs into the state file, keeping what
// is already there (the higher of each), through a temporary file renamed
// over it. The collections in aborted take this client's Next as it is:
// it called their rotation off (AbortRotation).
func ( client *Client ) saveState( aborted ...string ) ( err error ) {
	client.stateMutex.Lock()
	defer client.stateMutex.Unlock()
	all , err := readState( client.statePath )
	if err != nil { return }
	account := client.stateAccount()
	mine := all[ account ]
	if mine == nil { mine = map[ string ]epochMark{} }
	client.mutex.Lock()
	for id , mark := range client.marks {
		had := mine[ id ]
		mine[ id ] = epochMark{ Lock: max( had.Lock , mark.Lock ) , Next: max( had.Next , mark.Next ) }
	}
	for _ , id := range aborted {
		entry := mine[ id ]
		entry.Next = entry.Lock
		mine[ id ] = entry
	}
	client.mutex.Unlock()
	all[ account ] = mine
	encoded , err := json.Marshal( all )
	if err != nil { return }
	temp , err := os.CreateTemp( filepath.Dir( client.statePath ) , ".e2eedb-state-*" )
	if err != nil { return }
	defer os.Remove( temp.Name() )
	if err = temp.Chmod( 0o600 ); err == nil {
		if _ , err = temp.Write( encoded ); err == nil {
			err = temp.Sync()
		}
	}
	if close_err := temp.Close(); err == nil { err = close_err }
	if err != nil { return }
	err = os.Rename( temp.Name() , client.statePath )
	return
}

// mark is the highest epochs seen for collection.
func ( client *Client ) mark( collection string ) epochMark {
	client.mutex.Lock()
	defer client.mutex.Unlock()
	return client.marks[ collection ]
}

// freshEpochFor is the epoch for keys made now for collection.
func ( client *Client ) freshEpochFor( collection string ) uint64 {
	mark := client.mark( collection )
	return freshEpoch( max( mark.Lock , mark.Next ) )
}

// noteEpoch remembers that collection had a lockbox (next: a next_lock) at
// epoch.
func ( client *Client ) noteEpoch( collection string , next bool , epoch uint64 ) ( err error ) {
	client.mutex.Lock()
	mark := client.marks[ collection ]
	changed := false
	if next && epoch > mark.Next {
		mark.Next , changed = epoch , true
	} else if next == false && epoch > mark.Lock {
		mark.Lock , changed = epoch , true
	}
	client.marks[ collection ] = mark
	client.mutex.Unlock()
	if changed && client.statePath != "" {
		err = client.saveState()
	}
	return
}

// checkLock refuses key, opened from entry's lock, when this client has
// seen newer: a lock below the highest lock seen, or below the highest
// next_lock seen unless that rotation is still shown as under way (a
// next_lock one epoch on, which opens). Then it remembers the epoch.
func ( client *Client ) checkLock( ctx context.Context , tree map[ string ]Collection , entry Collection , key *CollectionKey ) ( err error ) {
	mark := client.mark( entry.ID )
	if key.epoch < mark.Lock {
		return fmt.Errorf( "%w: %s has keys of epoch %d, after %d" , ErrRolledBack , entry.ID , key.epoch , mark.Lock )
	}
	if key.epoch < mark.Next {
		var next *CollectionKey
		if entry.NextLock != "" {
			if next , err = client.resolveNext( ctx , tree , entry.ID ); err != nil { return }
		}
		if next == nil || next.epoch != key.epoch + 1 {
			return fmt.Errorf( "%w: %s has keys of epoch %d, after a rotation to %d" , ErrRolledBack , entry.ID , key.epoch , mark.Next )
		}
	}
	err = client.noteEpoch( entry.ID , false , key.epoch )
	return
}
