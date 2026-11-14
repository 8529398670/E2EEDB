// Package routes contains one file per group of endpoints, plus this file,
// which is the only place that knows the full URL map.
//
// The API here stays deliberately small: it covers logging in, managing who
// can log in, issuing the API keys that let non-browser callers in, and
// reading the UI's text. Everything else an app does belongs in a new file in
// this package (server side) and in static/js/ (browser side) -- see
// references/architecture.md for where the line sits and why.
package routes

import (
	errors "errors"

	fiber "github.com/gofiber/fiber/v3"

	config "github.com/8529398670/E2EEDB/server/config"
	db "github.com/8529398670/E2EEDB/server/db"
	docstore "github.com/8529398670/E2EEDB/server/docstore"
	errorpage "github.com/8529398670/E2EEDB/server/errorpage"
	jobs "github.com/8529398670/E2EEDB/server/jobs"
	language "github.com/8529398670/E2EEDB/server/language"
	logs "github.com/8529398670/E2EEDB/server/logs"
	models "github.com/8529398670/E2EEDB/server/models"
	security "github.com/8529398670/E2EEDB/server/security"
	static "github.com/8529398670/E2EEDB/server/static"
	stream "github.com/8529398670/E2EEDB/server/stream"
)

// Handlers carries the dependencies every route group needs. Passing this in
// rather than reaching for package-level globals is what makes the handlers
// testable and keeps the wiring visible in main.go.
type Handlers struct {
	Store *db.Store
	// Settings is the running configuration: read it through cfg(), once per
	// request, since config.yaml can change while the server runs.
	Settings *config.Holder
	Guard    *security.Guard
	Language *language.Language
	Static   *static.Server
	// Codes counts wrong two-factor codes per account, wherever they are
	// typed. Six digits with a window of three steps would otherwise fall to
	// a patient guesser.
	Codes *models.AttemptGuard[ uint64 ]
	// Version is reported to MCP clients as serverInfo.version.
	Version string
	// Logs is the activity log (server/logs), set by main.go after New. Nil
	// or switched off, nothing is logged and its routes are not registered.
	Logs *logs.Logger
	// Jobs is the background job registry (server/jobs), set by main.go.
	Jobs *jobs.Registry
	// LogStream is who has the Logs screen open with Live on, set by main.go.
	LogStream *stream.Hub
	// ErrorPages is what a browser gets while the app is in maintenance mode,
	// set by main.go. Nil is fine: everyone gets the JSON answer.
	ErrorPages *errorpage.Pages
	// OpenAPI is config/openapi.json, set by main.go.
	OpenAPI []byte
	// Docs is the end-to-end encrypted document store, set by main.go. See
	// docs.go.
	Docs *docstore.Store

	uiEventBudget eventBudget
	readiness     readiness
}

func New( store *db.Store , settings *config.Holder , guard *security.Guard , lang *language.Language , static_server *static.Server , version string ) ( handlers *Handlers ) {
	handlers = &Handlers{
		Store:    store,
		Settings: settings,
		Guard:    guard,
		Language: lang,
		Static:   static_server,
		Codes:    models.NewAttemptGuard[ uint64 ]( models.AttemptMaxFailures ),
		Version:  version,
	}
	return
}

// Register wires every route. Read it top to bottom to see the whole surface
// of this server.
func ( handlers *Handlers ) Register( app *fiber.App ) {
	// Resolve the session once, before anything else looks at the request.
	app.Use( handlers.Guard.LoadUser )
	app.Use( handlers.Guard.RestrictScopedKeys )

	// Next, because it needs to know who is asking and has to come before
	// every route below. See maintenance.go.
	app.Use( handlers.Maintenance )

	// Public: the login link's page and the call it makes, and the UI's text
	// (needed to render the signed-out page at all). Opening a login link
	// only shows a page; the link is spent by the POST that page sends when
	// the person confirms. See auth.go.
	app.Get( "/login/*" , handlers.ShowLoginPage )
	// A link to one document, /docs/<collection>/<id>: the ordinary app
	// page, which reads the path and opens it (static/js/docs.js). Only
	// names, never the key, so it is safe to paste anywhere.
	app.Get( "/docs/*" , handlers.Static.ServeIndex )
	app.Post( "/api/login" , handlers.RedeemLoginLink )
	app.Post( "/api/login/two-factor" , handlers.FinishSignIn )
	app.Get( "/api/language" , handlers.GetLanguage )
	app.Get( "/api/health" , handlers.GetHealth )
	app.Get( "/api/ready" , handlers.GetReady )


	// Any signed-in user.
	account := app.Group( "/api" , handlers.Guard.RequireLogin )
	account.Get( "/me" , handlers.GetMe )
	account.Post( "/account/rename" , handlers.RenameAccount )
	account.Post( "/account/shortcuts" , handlers.SetMyShortcuts )
	account.Post( "/account/themes" , handlers.SetMyThemes )
	account.Post( "/account/theme" , handlers.SetMyTheme )
	// A key may make its owner a login link, but only a key carrying the
	// account's full role (see CreateMyLoginLink), and revoking the key voids
	// the link if it is still unused (see models.RevokeAPIKey).
	account.Post( "/account/login-link" , handlers.CreateMyLoginLink )
	account.Post( "/account/login-link/cancel" , handlers.CancelMyLoginLink )
	// Passwords and 2FA change how an account signs in, so setting them needs
	// a session, like the PIN: a key that could set a password could turn
	// itself into a session.
	account.Post( "/account/two-factor/start" , handlers.RequireTwoFactor , handlers.Guard.RequireSession , handlers.StartTwoFactor )
	account.Post( "/account/two-factor/confirm" , handlers.RequireTwoFactor , handlers.Guard.RequireSession , handlers.ConfirmTwoFactor )
	account.Post( "/account/two-factor/disable" , handlers.RequireTwoFactor , handlers.Guard.RequireSession , handlers.DisableTwoFactor )
	// Your own signed-in devices. A key may list and end them too; through
	// a key there is no current device, so revoke-others ends them all.
	account.Get( "/account/sessions" , handlers.ListMySessions )
	account.Post( "/account/sessions/revoke-others" , handlers.RevokeMyOtherSessions )
	account.Post( "/account/sessions/:session_id/label" , handlers.LabelMySession )
	account.Post( "/account/sessions/:session_id/revoke" , handlers.RevokeMySession )
	account.Post( "/logout" , handlers.Logout )
	account.Get( "/team" , handlers.ListTeam )
	account.Get( "/openapi.json" , handlers.GetOpenAPI )
	// The document store: always the caller's own account, through a
	// session or any API key. See docs.go.
	account.Get( "/collections" , handlers.ListCollections )
	account.Post( "/collections" , handlers.CreateCollection )
	account.Post( "/collections/:collection" , handlers.UpdateCollection )
	account.Post( "/collections/:collection/delete" , handlers.DeleteCollection )
	account.Get( "/collections/:collection/docs" , handlers.ListDocs )
	account.Get( "/collections/:collection/docs/:doc_id" , handlers.GetDoc )
	account.Post( "/collections/:collection/docs/:doc_id" , handlers.SetDoc )
	account.Post( "/collections/:collection/docs/:doc_id/delete" , handlers.DeleteDoc )
	account.Post( "/collections/:collection/docs/:doc_id/move" , handlers.MoveDoc )
	account.Get( "/changes" , handlers.ListChanges )
	account.Get( "/keyring" , handlers.GetKeyring )
	account.Post( "/keyring" , handlers.SetKeyring )
	// What someone did on the page, sent by track.js. Theirs to send, the
	// owner's to read (below).
	if handlers.Logs.Enabled() {
		account.Post( "/logs/events" , handlers.RecordUIEvents )
	}

	// API keys: any signed-in user manages their own.
	//
	// Note the group prefix. A group's middleware is mounted on a path
	// *prefix*, not on the routes written under it, so it applies to every
	// route registered after it whose path starts with that prefix. Mounting
	// these two on "/api" would put RequireSession in front of /api/admin/users
	// as well, and an admin-scoped API key would then be refused there. That is
	// also why the prefix is exactly "/api/keys": a future "/api/keysets" would
	// pick up this middleware by sharing the string, so keep new routes off
	// these prefixes unless they want these rules.
	keys := app.Group( "/api/keys" , handlers.RequireAPIKeys , handlers.Guard.RequireLogin , handlers.Guard.RequireSession )
	keys.Get( "" , handlers.ListMyAPIKeys )
	keys.Post( "" , handlers.CreateMyAPIKey )
	keys.Post( "/:key_id/rename" , handlers.RenameMyAPIKey )
	keys.Post( "/:key_id/expiry" , handlers.SetMyAPIKeyExpiry )
	keys.Post( "/:key_id/revoke" , handlers.RevokeMyAPIKey )
	keys.Post( "/:key_id/delete" , handlers.DeleteMyAPIKey )
	keys.Post( "/:key_id/restore" , handlers.RestoreMyAPIKey )


	// Admin only: deciding who gets in. Note this is the *only* thing admin
	// rights gate in the base template -- see architecture.md on defaulting
	// new features to "any signed-in user".
	//
	// An admin-scoped key may do all of it, creating accounts and handing out
	// login links included. Every link records the key that made it, and
	// revoking or deleting that key voids the links it made that can still be
	// used (models.RevokeAPIKey), so revoking a leaked key still ends what it
	// could hand out. Who may delete or demote whom (the owner rules) is
	// enforced in the models.
	admin := app.Group( "/api/admin" , handlers.Guard.RequireAdmin )
	admin.Get( "/users" , handlers.ListUsers )
	admin.Post( "/users" , handlers.CreateUser )
	admin.Post( "/users/:user_id/reissue-login" , handlers.ReissueLogin )
	admin.Post( "/users/:user_id/cancel-login-link" , handlers.CancelLoginLink )
	admin.Post( "/users/:user_id/rename" , handlers.RenameUser )
	admin.Post( "/users/:user_id/role" , handlers.SetUserRole )
	admin.Post( "/users/:user_id/disabled" , handlers.SetUserDisabled )
	admin.Post( "/users/:user_id/revoke-access" , handlers.RevokeAccess )
	admin.Post( "/users/:user_id/delete" , handlers.DeleteUser )
	admin.Post( "/users/:user_id/reset-two-factor" , handlers.ResetTwoFactor )
	// An account's devices, like your own list above.
	admin.Get( "/users/:user_id/sessions" , handlers.ListUserSessions )
	admin.Post( "/users/:user_id/sessions/:session_id/revoke" , handlers.RevokeUserSession )
	// The themes everyone starts from. Not a credential, so a key may.
	admin.Get( "/theme-defaults" , handlers.GetThemeDefaults )
	admin.Post( "/theme-defaults" , handlers.SetThemeDefaults )


	// Admin view of every key in the app -- "who has standing access" -- and
	// the ability to revoke or delete someone else's. Its own prefix for the
	// same reason as above: mounted on "/api/admin" it would gate the account
	// routes too.
	admin_keys := app.Group( "/api/admin/keys" , handlers.RequireAPIKeys , handlers.Guard.RequireAdmin , handlers.Guard.RequireSession )
	admin_keys.Get( "" , handlers.ListAllAPIKeys )
	admin_keys.Post( "" , handlers.CreateAPIKeyForUser )
	admin_keys.Post( "/:key_id/rename" , handlers.RenameAnyAPIKey )
	admin_keys.Post( "/:key_id/expiry" , handlers.SetAnyAPIKeyExpiry )
	admin_keys.Post( "/:key_id/revoke" , handlers.RevokeAnyAPIKey )
	admin_keys.Post( "/:key_id/delete" , handlers.DeleteAnyAPIKey )
	admin_keys.Post( "/:key_id/restore" , handlers.RestoreAnyAPIKey )


	// config.yaml, as the owner's Settings screen: the owner only, from a
	// browser session, like the activity log below. See settings.go.
	owner_settings := app.Group( "/api/owner/settings" , handlers.Guard.RequireOwner )
	owner_settings.Get( "" , handlers.GetSettings )
	owner_settings.Post( "" , handlers.SaveSettings )


	// The activity log: the owner only, from a browser session -- not other
	// admins, not any API key (see Guard.RequireOwner). Its own prefix, so
	// nothing else picks up RequireOwner by sharing the string.
	if handlers.Logs.Enabled() {
		owner_logs := app.Group( "/api/owner/logs" , handlers.Guard.RequireOwner )
		owner_logs.Get( "/stream" , handlers.StreamLogs )
		owner_logs.Get( "/days" , handlers.ListLogDays )
		owner_logs.Get( "/days/:date" , handlers.GetLogDay )
		owner_logs.Get( "/days/:date/download" , handlers.DownloadLogDay )
		owner_logs.Post( "/days/:date/delete" , handlers.DeleteLogDay )
		owner_logs.Post( "/prune" , handlers.PruneLogs )
		owner_logs.Get( "/ip-names" , handlers.ListIPNames )
		owner_logs.Post( "/ip-names" , handlers.SetIPName )
		owner_logs.Post( "/ip-names/delete" , handlers.DeleteIPName )
	}

	// Background jobs: the owner only, from a browser session, like the log.
	owner_jobs := app.Group( "/api/owner/jobs" , handlers.Guard.RequireOwner )
	owner_jobs.Get( "" , handlers.ListJobs )
	owner_jobs.Post( "/:name/run" , handlers.RunJob )




	// Any other /api/ path is a JSON 404, not a static page.
	app.Get( "/api/*" , func( c fiber.Ctx ) ( err error ) {
		err = c.Status( fiber.StatusNotFound ).JSON( fiber.Map{ "error": "not found" } )
		return
	} )

	// Catch-all static serving. Must be registered last -- it matches every
	// remaining path, so anything added after this line never runs.
	app.Get( "/*" , handlers.Static.Handler )
}

func ( handlers *Handlers ) cfg() ( cfg *config.Config ) {
	cfg = handlers.Settings.Get()
	return
}


// badRequest / notFound keep error bodies uniform, so the frontend has one
// shape to handle and no handler accidentally leaks internal detail.
func badRequest( c fiber.Ctx , message string ) ( err error ) {
	err = c.Status( fiber.StatusBadRequest ).JSON( fiber.Map{ "error": message } )
	return
}

func notFound( c fiber.Ctx , message string ) ( err error ) {
	err = c.Status( fiber.StatusNotFound ).JSON( fiber.Map{ "error": message } )
	return
}

func forbidden( c fiber.Ctx , message string ) ( err error ) {
	err = c.Status( fiber.StatusForbidden ).JSON( fiber.Map{ "error": message } )
	return
}

// conflict is 409: the request was fine but the record has moved on -- an
// undo whose window has passed, or a rename that expected a name someone else
// has since changed. extra carries the current state, so the caller can show
// it.
func conflict( c fiber.Ctx , message string , extra fiber.Map ) ( err error ) {
	body := fiber.Map{ "error": message }
	for name , value := range extra {
		body[ name ] = value
	}
	err = c.Status( fiber.StatusConflict ).JSON( body )
	return
}

func tooMany( c fiber.Ctx , code string ) ( err error ) {
	err = c.Status( fiber.StatusTooManyRequests ).JSON( fiber.Map{ "error": code } )
	return
}

// restoreRefused answers each way a restore can be refused.
func restoreRefused( c fiber.Ctx , refusal error ) ( err error ) {
	err = restoreRefusal( refusal ).send( c )
	return
}

// restoreRefusal is restoreRefused for a helper an MCP tool shares.
func restoreRefusal( cause error ) ( refused *refusal ) {
	switch {
	case errors.Is( cause , models.ErrRestoreGone ):
		refused = refuse( fiber.StatusNotFound , cause.Error() )
	case errors.Is( cause , models.ErrRestoreForbidden ):
		refused = refuse( fiber.StatusForbidden , cause.Error() )
	case errors.Is( cause , models.ErrRestoreExpired ):
		refused = refuse( fiber.StatusConflict , cause.Error() )
	case errors.Is( cause , models.ErrAPIKeyLimit ):
		refused = refuse( fiber.StatusConflict , "its owner already has the maximum number of live API keys" )
	case errors.Is( cause , models.ErrOwnerProtected ):
		refused = refuse( fiber.StatusForbidden , "nobody can restore the owner account's keys" )
	case errors.Is( cause , models.ErrOwnerRequired ):
		refused = refuse( fiber.StatusForbidden , "only the owner can restore an admin account's keys" )
	default:
		refused = internalFailure( cause )
	}
	return
}

// serverError ends a request that failed on our side. It writes nothing:
// handing cause back up is what gets it to the log, and to the ErrorHandler
// (server/middleware/errors.go), which answers with the generic message and a
// reference the person can quote. The cause itself never reaches them.
func serverError( _ fiber.Ctx , cause error ) ( err error ) {
	err = cause
	if err == nil {
		err = errors.New( "internal error" )
	}
	return
}
