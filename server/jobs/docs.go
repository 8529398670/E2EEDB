package jobs

import (
	errors "errors"
	fmt "fmt"
	time "time"

	config "github.com/8529398670/E2EEDB/server/config"
	db "github.com/8529398670/E2EEDB/server/db"
	docstore "github.com/8529398670/E2EEDB/server/docstore"
	models "github.com/8529398670/E2EEDB/server/models"
)

// Docs registers the document store's hourly sweep: tombstones past
// docs.tombstone_days, and the documents of accounts that have been deleted.
// See docstore.Sweep.
func Docs( registry *Registry , docs *docstore.Store , store *db.Store , settings *config.Holder ) {
	registry.Register( "docs" , housekeepingInterval , func() ( note string , err error ) {
		limits := settings.Get().Docs.Limits()
		exists := func( user_id uint64 ) bool {
			_ , get_err := models.GetUser( store , user_id )
			// Only a definite "no such user" removes anything: a read that
			// failed for another reason keeps the documents for next time.
			return errors.Is( get_err , db.ErrNotFound ) == false
		}
		swept , err := docs.Sweep( time.Now() , limits.TombstoneDays , exists )
		note = fmt.Sprintf( "purged %d tombstones, cleared %d deleted accounts" , swept.Tombstones , swept.Accounts )
		return
	} )
}
