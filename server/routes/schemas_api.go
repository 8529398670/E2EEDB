package routes

import (
	time "time"

)

// The named shapes the API docs share: components/schemas in
// config/openapi.json. See server/apidoc for what the struct tags mean.

type apiKeySchema struct {
	ID string `json:"id"`
	UserID int `json:"user_id"`
	Name string `json:"name"`
	Role string `json:"role" enum:"admin|user"`
	CreatedAt time.Time `json:"created_at"`
	Revoked bool `json:"revoked"`
	Expired bool `json:"expired"`
	Live bool `json:"live"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	RevokedAt time.Time `json:"revoked_at,omitempty"`
	DisplayName string `json:"display_name,omitempty" doc:"The key's owner. On the admin list only."`
	CreatedBy int `json:"created_by,omitempty" doc:"The admin who made this key for its owner. Absent if the owner made it."`
	CreatedByName string `json:"created_by_name,omitempty"`
	Scope *apiKeyScopeDoc `json:"scope,omitempty" doc:"Present on a key limited to one collection and the ones under it."`
}

type apiKeyScopeDoc struct {
	Collection string `json:"collection" doc:"The collection's id."`
	Access string `json:"access" enum:"read|write"`
}

func ( apiKeySchema ) APIName() ( name string ) { name = "APIKey"; return }


type jobSchema struct {
	Name string `json:"name"`
	IntervalSeconds int `json:"interval_seconds"`
	Running bool `json:"running"`
	Interrupted bool `json:"interrupted"`
	Runs int `json:"runs"`
	NextDue time.Time `json:"next_due"`
	LastStarted time.Time `json:"last_started,omitempty"`
	LastFinished time.Time `json:"last_finished,omitempty"`
	LastOk bool `json:"last_ok,omitempty"`
	LastNote string `json:"last_note,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

func ( jobSchema ) APIName() ( name string ) { name = "Job"; return }





type logDaySchema struct {
	Date string `json:"date"`
	Entries []map[string]any `json:"entries"`
	Next *int `json:"next,omitempty"`
}

func ( logDaySchema ) APIName() ( name string ) { name = "LogDay"; return }

type logDaysSchema struct {
	Days []map[string]any `json:"days"`
	TotalBytes int `json:"total_bytes,omitempty"`
	Dropped int `json:"dropped,omitempty"`
	Settings map[string]any `json:"settings,omitempty"`
}

func ( logDaysSchema ) APIName() ( name string ) { name = "LogDays"; return }

type meSchema struct {
	Authenticated bool `json:"authenticated"`
	ID int `json:"id"`
	DisplayName string `json:"display_name"`
	Role string `json:"role" doc:"The effective role: never higher than an API key's own."`
	AccountRole string `json:"account_role"`
	IsOwner bool `json:"is_owner"`
	Maintenance string `json:"maintenance" enum:"none|read_only|full"`
	TwoFactor bool `json:"two_factor,omitempty"`
	TwoFactorEnabled bool `json:"two_factor_enabled,omitempty"`
	Auth string `json:"auth,omitempty"`
	APIKeysEnabled bool `json:"api_keys_enabled,omitempty"`
	LogsEnabled bool `json:"logs_enabled,omitempty"`
	LogsUIClicks bool `json:"logs_ui_clicks,omitempty"`
	CSRFToken string `json:"csrf_token,omitempty" doc:"Browser sessions only."`
	APIKeyID string `json:"api_key_id,omitempty" doc:"API keys only."`
	APIKeyName string `json:"api_key_name,omitempty" doc:"API keys only."`
	Version string `json:"version,omitempty" doc:"The running build. dev when none was stamped."`
	Announcement string `json:"announcement,omitempty" doc:"server.announcement. Empty when there is none."`
	Repo string `json:"repo,omitempty" doc:"app.repo without a trailing / or .git: where the source lives. Empty when it is not set."`
	Description string `json:"description,omitempty" doc:"app.description. Empty when there is none."`
	ShowAbout bool `json:"show_about,omitempty" doc:"app.show_about: whether the menu has About."`
	OpenapiURL string `json:"openapi_url,omitempty" doc:"Where to read this API's reference: config/openapi.json in app.repo, or /api/openapi.json when there is no repo."`
	Shortcuts map[string]string `json:"shortcuts,omitempty" doc:"The keyboard shortcuts you changed, by action. Mod is Cmd on a Mac and Ctrl elsewhere."`
	Themes *[]map[string]any `json:"themes,omitempty" doc:"Your themes (see the Theme schema): your own list, else the app's defaults, else null for the built-in ones."`
	ThemesCustom bool `json:"themes_custom,omitempty" doc:"Whether you have your own list rather than following the defaults."`
	ThemeID string `json:"theme_id,omitempty" doc:"The theme you use. Empty: the first."`
	LoginLink *loginLinkSchema `json:"login_link,omitempty" doc:"Your own live login link, or null."`
}

func ( meSchema ) APIName() ( name string ) { name = "Me"; return }

type memberSchema struct {
	ID int `json:"id"`
	DisplayName string `json:"display_name"`
}

func ( memberSchema ) APIName() ( name string ) { name = "Member"; return }

type newAPIKeySchema struct {
	apiKeySchema
	Credential string `json:"credential" doc:"Shown in this response only, and never recoverable."`
}

func ( newAPIKeySchema ) APIName() ( name string ) { name = "NewAPIKey"; return }

type pruneResultSchema struct {
	Compressed int `json:"compressed,omitempty"`
	Deleted int `json:"deleted,omitempty"`
	BytesBefore int `json:"bytes_before,omitempty"`
	BytesAfter int `json:"bytes_after,omitempty"`
}

func ( pruneResultSchema ) APIName() ( name string ) { name = "PruneResult"; return }

type revokedSchema struct {
	Sessions int `json:"sessions,omitempty"`
	LoginLinks int `json:"login_links,omitempty"`
	APIKeys int `json:"api_keys,omitempty"`
	Passwords int `json:"passwords,omitempty"`
}

func ( revokedSchema ) APIName() ( name string ) { name = "Revoked"; return }

type sessionSchema struct {
	ID string `json:"id"`
	Current bool `json:"current"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
	IP string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Label string `json:"label,omitempty" doc:"The name you gave this device."`
	IPName string `json:"ip_name,omitempty" doc:"What the owner calls this address on the Logs screen. The owner's own list only."`
}

func ( sessionSchema ) APIName() ( name string ) { name = "Session"; return }

type settingsResultSchema struct {
	Changes []map[string]any `json:"changes,omitempty" nullable:"true"`
	Applied []string `json:"applied,omitempty" nullable:"true"`
	Restart []string `json:"restart,omitempty" nullable:"true"`
	Scripts []string `json:"scripts,omitempty" nullable:"true"`
	Unchanged []string `json:"unchanged,omitempty" nullable:"true"`
	Version string `json:"version,omitempty"`
}

func ( settingsResultSchema ) APIName() ( name string ) { name = "SettingsResult"; return }

type settingsSnapshotSchema struct {
	File string `json:"file,omitempty"`
	SecretFile string `json:"secret_file,omitempty"`
	Version string `json:"version,omitempty" doc:"Send it back when saving: a changed file is refused with a 409."`
	Writable bool `json:"writable,omitempty"`
	Stale bool `json:"stale,omitempty"`
	InContainer bool `json:"in_container,omitempty"`
	Error *settingsSnapshotSchemaErrorDoc `json:"error,omitempty"`
	Sections []settingsSnapshotSchemaSectionsItemDoc `json:"sections,omitempty"`
}

func ( settingsSnapshotSchema ) APIName() ( name string ) { name = "SettingsSnapshot"; return }

type settingsSnapshotSchemaErrorDoc struct {
	Message string `json:"message,omitempty"`
	At time.Time `json:"at,omitempty"`
	Origin string `json:"origin,omitempty"`
}

type settingsSnapshotSchemaSectionsItemDoc struct {
	Name string `json:"name,omitempty"`
	Help string `json:"help,omitempty"`
	Keys []settingsSnapshotSchemaSectionsItemDocKeysItem `json:"keys,omitempty"`
}

type settingsSnapshotSchemaSectionsItemDocKeysItem struct {
	Key string `json:"key,omitempty"`
	Name string `json:"name,omitempty"`
	Type string `json:"type,omitempty"`
	Value any `json:"value,omitempty"`
	Default any `json:"default,omitempty"`
	InFile bool `json:"in_file,omitempty"`
	Help string `json:"help,omitempty"`
	Apply string `json:"apply,omitempty"`
	PendingRestart bool `json:"pending_restart,omitempty"`
	Running any `json:"running,omitempty"`
	Locked bool `json:"locked,omitempty"`
	FileOnly bool `json:"file_only,omitempty" doc:"A path: change it in config.yaml, never here."`
}

type signInSchemaShape1Doc struct {
	Ok bool `json:"ok"`
}

type signInSchemaShape2Doc struct {
	TwoFactor bool `json:"two_factor"`
	Challenge string `json:"challenge"`
}

type signInSchema struct{}

func ( signInSchema ) APIName() ( name string ) { name = "SignIn"; return }

func ( signInSchema ) APIOneOf() ( shapes []any ) {
	shapes = []any{ signInSchemaShape1Doc{} , signInSchemaShape2Doc{} }
	return
}

func ( signInSchema ) APIDoc() ( text string ) { text = "Either the sign-in finished, or a two-factor code is needed: send it with the challenge to /api/login/two-factor."; return }

type userSchema struct {
	ID int `json:"id"`
	DisplayName string `json:"display_name"`
	Role string `json:"role" enum:"admin|user"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	Disabled bool `json:"disabled"`
	Owner bool `json:"owner"`
	TwoFactor bool `json:"two_factor,omitempty"`
	LoginLink *loginLinkSchema `json:"login_link,omitempty" doc:"The account's live login link, or null."`
}

func ( userSchema ) APIName() ( name string ) { name = "User"; return }




type ipNamesSchema struct {
	Names []ipNamesSchemaNamesItemDoc `json:"names,omitempty"`
}

func ( ipNamesSchema ) APIName() ( name string ) { name = "IPNames"; return }

type ipNamesSchemaNamesItemDoc struct {
	Target string `json:"target,omitempty"`
	Name string `json:"name,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
}

type loginLinkSchema struct {
	MaxUses int `json:"max_uses" doc:"Sign-ins it allows. 0 when unlimited."`
	Unlimited bool `json:"unlimited"`
	Uses int `json:"uses" doc:"Sign-ins so far."`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at" doc:"null when it never expires."`
	LastUsedAt *time.Time `json:"last_used_at"`
}

func ( loginLinkSchema ) APIName() ( name string ) { name = "LoginLink"; return }

func ( loginLinkSchema ) APIDoc() ( text string ) { text = "A login link that can still be used. One per account at most."; return }

type themeSchema struct {
	ID string `json:"id" doc:"Lower-case letters, digits, - and _, up to 32."`
	Name string `json:"name" doc:"1 to 60 characters."`
	Mode string `json:"mode" enum:"light|dark"`
	Accent string `json:"accent" doc:"The main color: what you can press."`
	Second string `json:"second" doc:"Says where you are: active nav item, headings, info."`
	Background string `json:"background,omitempty" doc:"The page. Left out: the mode's own."`
	Surface string `json:"surface,omitempty" doc:"Cards. Left out: the mode's own."`
	Overrides map[string]string `json:"overrides,omitempty" doc:"Worked-out colors replaced by name: text, accent, accentFg, second, secondFg, secondText, link, navLink, background, surface, nested, chrome, info, infoBorder, border, and for each button variant V (Secondary, Success, Danger, Warning, Info, Light, Dark) btnV, btnVFg and btnVText. Leaving one out puts the readable color back."`
	Button themeSchemaButtonDoc `json:"button,omitempty" doc:"How the theme's buttons look. A choice left out is the default (rounded, normal, raised, normal)."`
	Light themeSchemaLightDoc `json:"light,omitempty" doc:"A dark theme's colors for light mode, kept while it is dark. Switching the theme to light swaps them in."`
	Dark themeSchemaDarkDoc `json:"dark,omitempty" doc:"A light theme's colors for dark mode, kept while it is light. Switching the theme to dark swaps them in. A light theme's light (or a dark theme's dark) is dropped."`
}

func ( themeSchema ) APIName() ( name string ) { name = "Theme"; return }

func ( themeSchema ) APIDoc() ( text string ) { text = "A color scheme on the Appearance screen. Colors are #rrggbb. Anything not given is worked out by static/js/theme.js at readable contrast."; return }

type themeSchemaButtonDoc struct {
	Shape string `json:"shape,omitempty" enum:"square|soft|rounded|pill"`
	Weight string `json:"weight,omitempty" enum:"normal|medium|bold"`
	Depth string `json:"depth,omitempty" enum:"flat|raised|glossy"`
	Case string `json:"case,omitempty" enum:"normal|upper"`
}

type themeSchemaLightDoc struct {
	Accent string `json:"accent" doc:"The main color: what you can press."`
	Second string `json:"second" doc:"Says where you are: active nav item, headings, info."`
	Background string `json:"background,omitempty" doc:"The page. Left out: the mode's own."`
	Surface string `json:"surface,omitempty" doc:"Cards. Left out: the mode's own."`
	Overrides map[string]string `json:"overrides,omitempty" doc:"Worked-out colors replaced by name: text, accent, accentFg, second, secondFg, secondText, link, navLink, background, surface, nested, chrome, info, infoBorder, border, and for each button variant V (Secondary, Success, Danger, Warning, Info, Light, Dark) btnV, btnVFg and btnVText. Leaving one out puts the readable color back."`
}

type themeSchemaDarkDoc struct {
	Accent string `json:"accent" doc:"The main color: what you can press."`
	Second string `json:"second" doc:"Says where you are: active nav item, headings, info."`
	Background string `json:"background,omitempty" doc:"The page. Left out: the mode's own."`
	Surface string `json:"surface,omitempty" doc:"Cards. Left out: the mode's own."`
	Overrides map[string]string `json:"overrides,omitempty" doc:"Worked-out colors replaced by name: text, accent, accentFg, second, secondFg, secondText, link, navLink, background, surface, nested, chrome, info, infoBorder, border, and for each button variant V (Secondary, Success, Danger, Warning, Info, Light, Dark) btnV, btnVFg and btnVText. Leaving one out puts the readable color back."`
}
