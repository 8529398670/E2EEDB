package routes

import (
	errors "errors"

	fiber "github.com/gofiber/fiber/v3"

	logs "github.com/8529398670/E2EEDB/server/logs"
	models "github.com/8529398670/E2EEDB/server/models"
	security "github.com/8529398670/E2EEDB/server/security"
)


type renameRequest struct {
	DisplayName string `json:"display_name"`
	// Expect is optional: the name the caller expects to replace. The
	// frontend always sends it, so its undo cannot overwrite a rename made
	// elsewhere.
	Expect    *string `json:"expect"`
	CSRFToken string  `json:"csrf_token"`
}

// GetMe is the frontend's first call on every page load: it answers "who am
// I, what may I do, and what CSRF token do I echo back". Handing the token
// out here means no page needs a hidden form field or a template variable.
//
// "role" is the *effective* role, not the account's: a request made with a
// user-scoped API key belonging to an admin reports "user", because that is
// what it may actually do. account_role reports the account itself, for the
// rare caller that needs to tell the two apart. Reporting the account's role
// as "role" would have a client believe it has permissions the server will
// refuse to act on.
func ( handlers *Handlers ) GetMe( c fiber.Ctx ) ( err error ) {
	payload , row_err := handlers.meRow( security.ActorFrom( c ) )
	if row_err != nil {
		err = serverError( c , row_err )
		return
	}
	err = c.JSON( payload )
	return
}

// meRow is GetMe's answer, shared with the MCP whoami tool so the two cannot
// describe the same caller differently.
func ( handlers *Handlers ) meRow( actor *security.Actor ) ( payload fiber.Map , err error ) {
	user := actor.User

	// is_owner tells the UI which account-management buttons to offer; the
	// server checks ownership again on every request that depends on it.
	owner_id , err := models.OwnerID( handlers.Store )
	if err != nil { return }
	login_link , err := models.LiveLoginLink( handlers.Store , user.ID )
	if err != nil { return }

	themes , themes_custom , err := handlers.myThemes( user )
	if err != nil { return }
	payload = fiber.Map{
		"authenticated":    true,
		"id":               user.ID,
		"display_name":     user.DisplayName,
		"role":             actor.Role,
		"account_role":     user.Role,
		"is_owner":         user.ID == owner_id,
		"login_link":       login_link,
		"maintenance":      handlers.cfg().MaintenanceMode(),
		"version":          handlers.Version,
		"announcement":     handlers.cfg().Announcement,
		"repo":             handlers.cfg().Repo,
		"description":      handlers.cfg().Description,
		"show_about":       handlers.cfg().ShowAbout,
		"openapi_url":      handlers.openAPIURL(),
		"shortcuts":        myShortcuts( user ),
		"themes":           themes,
		"themes_custom":    themes_custom,
		"theme_id":         user.ThemeID,
		"two_factor":         user.TwoFactorOn(),
		"two_factor_enabled": handlers.cfg().TwoFactorEnabled,
		"auth":             actor.Method(),
		"api_keys_enabled": handlers.cfg().APIKeysEnabled,
		// Whether track.js sends anything, and whether it sends clicks.
		"logs_enabled":   handlers.Logs.Enabled(),
		"logs_ui_clicks": handlers.Logs.Enabled() && handlers.cfg().Logs.UIClicks,
	}
	// Only a session has a CSRF token. A key-authenticated request has no
	// ambient credential to protect, so there is nothing to hand back -- see
	// Guard.CheckCSRF.
	if actor.Session != nil {
		payload[ "csrf_token" ] = actor.Session.CSRFToken
	}
	if actor.APIKey != nil {
		payload[ "api_key_id" ] = actor.APIKey.ID
		payload[ "api_key_name" ] = actor.APIKey.Name
	}
	return
}

// myShortcuts is never null, so the frontend can read it without checking.
func myShortcuts( user *models.User ) ( result map[string]string ) {
	result = user.Shortcuts
	if result == nil { result = map[string]string{} }
	return
}

func ( handlers *Handlers ) RenameAccount( c fiber.Ctx ) ( err error ) {
	var body renameRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	payload , refused := handlers.renameAccount( c , body.DisplayName , body.Expect )
	if refused != nil {
		err = refused.send( c )
		return
	}
	err = c.JSON( payload )
	return
}

// renameAccount is RenameAccount after the request is read, for it and the
// MCP rename_account tool.
func ( handlers *Handlers ) renameAccount( c fiber.Ctx , display_name string , expect *string ) ( payload fiber.Map , refused *refusal ) {
	if models.ValidDisplayName( display_name ) == false {
		refused = refuse( fiber.StatusBadRequest , "display name must be 1-80 characters" )
		return
	}
	user := security.UserFrom( c )
	rename_err := models.RenameUser( handlers.Store , user.ID , display_name , expect )
	var conflict_err *models.RenameConflictError
	if errors.As( rename_err , &conflict_err ) {
		refused = refuse( fiber.StatusConflict , conflict_err.Error() , fiber.Map{ "display_name": conflict_err.Current } )
		return
	}
	if rename_err != nil {
		refused = internalFailure( rename_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "renamed own account" , fiber.Map{ "name": display_name } )
	payload = fiber.Map{ "ok": true , "display_name": display_name }
	return
}


// CreateMyLoginLink mints a login link for the caller's own account: the way
// to sign in on another device without asking an admin. Once by default, or
// reusable, like ReissueLogin -- it is ReissueLogin pointed at yourself, so it
// has the same effect: any link the account could still use stops working,
// and existing sessions stay signed in.
//
// An API key may ask too, but only one that carries the account's full role:
// the link becomes a session, and a session acts with the account's role, so
// a key scoped down to "user" on an admin's account would otherwise climb.
// Revoking the key voids the link while it can still be used.
func ( handlers *Handlers ) CreateMyLoginLink( c fiber.Ctx ) ( err error ) {
	var body loginLinkBody
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	payload , refused := handlers.createMyLoginLink( c , body.LoginLinkRequest )
	if refused != nil {
		err = refused.send( c )
		return
	}
	err = c.JSON( payload )
	return
}

// createMyLoginLink is CreateMyLoginLink after the request is read, for it
// and the MCP create_my_login_link tool.
func ( handlers *Handlers ) createMyLoginLink( c fiber.Ctx , request models.LoginLinkRequest ) ( payload fiber.Map , refused *refusal ) {
	actor := security.ActorFrom( c )
	if actor.ViaAPIKey() && actor.Role != actor.User.Role {
		refused = refuse( fiber.StatusForbidden , "this key acts with less than your account's role, so it cannot make a login link" )
		return
	}
	options , refused := handlers.loginLinkOptions( c , request )
	if refused != nil { return }
	credential , info , token_err := models.IssueLoginLink( handlers.Store , actor.User.ID , options )
	if token_err != nil {
		refused = internalFailure( token_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "own login link created" , fiber.Map{ "max_uses": info.MaxUses , "expires_at": info.ExpiresAt } )
	payload = loginLinkResponse( credential , info )
	return
}

// CancelMyLoginLink stops the caller's own live login link working.
func ( handlers *Handlers ) CancelMyLoginLink( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	payload , refused := handlers.cancelMyLoginLink( c )
	if refused != nil {
		err = refused.send( c )
		return
	}
	err = c.JSON( payload )
	return
}

// cancelMyLoginLink is CancelMyLoginLink after the request is read, for it
// and the MCP cancel_my_login_link tool.
func ( handlers *Handlers ) cancelMyLoginLink( c fiber.Ctx ) ( payload fiber.Map , refused *refusal ) {
	removed , cancel_err := models.CancelLoginLink( handlers.Store , security.UserFrom( c ).ID , security.UserFrom( c ).ID )
	if cancel_err != nil {
		refused = internalFailure( cancel_err )
		return
	}
	handlers.audit( c , logs.KindAuth , "own login link cancelled" , fiber.Map{ "removed": removed } )
	payload = fiber.Map{ "ok": true , "removed": removed }
	return
}

// Logout deletes the session server-side as well as clearing the cookie, so
// a copy of the cookie captured earlier is dead too.
//
// It is held to the CSRF token like every other state change. SameSite=Strict
// already stops another site from sending the cookie here, but not a page on
// a sibling subdomain, and being signed out by someone else's page is the
// first step of tricking a person into signing in to the wrong account.
//
// Called with an API key it does nothing and says so by succeeding: there is
// no session to destroy. A key is ended by revoking it, not by logging out.
func ( handlers *Handlers ) Logout( c fiber.Ctx ) ( err error ) {
	var body csrfOnlyRequest
	if c.Bind().JSON( &body ) != nil {
		err = badRequest( c , "malformed request body" )
		return
	}
	if handlers.Guard.CheckCSRF( c , body.CSRFToken ) == false {
		err = forbidden( c , "invalid csrf token" )
		return
	}
	handlers.audit( c , logs.KindAuth , "signed out" , nil )
	handlers.destroyCookieSession( c )
	handlers.Guard.ClearSessionCookie( c )
	err = c.JSON( fiber.Map{ "ok": true } )
	return
}

// openAPIURL is where the API reference is read: config/openapi.json in
// app.repo when that is set, so it opens as a page there, else this server's
// own copy, which needs the same sign-in.
func ( handlers *Handlers ) openAPIURL() ( result string ) {
	result = handlers.cfg().RepoFile( "config/openapi.json" )
	if result == "" {
		result = "/api/openapi.json"
	}
	return
}

