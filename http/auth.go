package fbhttp

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/golang-jwt/jwt/v5/request"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	fberrors "github.com/filebrowser/filebrowser/v2/errors"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

const (
	DefaultTokenExpirationTime = time.Hour * 2

	maxAuthBodySize = 1 << 20 // 1 MiB
)

type userInfo struct {
	ID                    uint              `json:"id"`
	Locale                string            `json:"locale"`
	ViewMode              users.ViewMode    `json:"viewMode"`
	SingleClick           bool              `json:"singleClick"`
	RedirectAfterCopyMove bool              `json:"redirectAfterCopyMove"`
	Perm                  users.Permissions `json:"perm"`
	Commands              []string          `json:"commands"`
	LockPassword          bool              `json:"lockPassword"`
	HideDotfiles          bool              `json:"hideDotfiles"`
	DateFormat            bool              `json:"dateFormat"`
	Username              string            `json:"username"`
	AceEditorTheme        string            `json:"aceEditorTheme"`
}

type authToken struct {
	User userInfo `json:"user"`
	jwt.RegisteredClaims
}

// authValue returns the JWT the request carries in its header, or "" when it
// carries none.
//
// The `auth` cookie deliberately is not consulted here: it holds a short-lived
// media credential, not a JWT, and that credential is only ever accepted for the
// endpoints the browser loads by itself. See session.go.
func authValue(r *http.Request) string {
	token, _ := request.HeaderExtractor{"X-Auth"}.ExtractToken(r)

	// A JWT is the only thing that may pass: anything else that could appear in
	// the header — a stray Basic credential, a session identifier — is not one,
	// and treating it as one would only produce confusing parse errors.
	if strings.Count(token, ".") != 2 {
		return ""
	}

	return token
}

func renewableErr(err error, r *http.Request, d *data, tk *authToken) bool {
	if d.settings.AuthMethod != fbAuth.MethodProxyAuth || err == nil {
		return false
	}

	if d.settings.LogoutPage == settings.DefaultLogoutPage {
		return false
	}

	if !errors.Is(err, jwt.ErrTokenExpired) {
		return false
	}

	// The expiration is only waived because the trusted proxy, not the token,
	// decides when the session ends. Require the proxy to still assert the same
	// identity on this request, otherwise a token that leaked before it expired
	// would authenticate on its own forever.
	return proxyAsserts(r, d, tk.User.ID)
}

// proxyAsserts reports whether the proxy-auth header on r identifies the user
// the token was issued for. The username is resolved through the user store, so
// that it is matched exactly as a regular proxy login would match it.
func proxyAsserts(r *http.Request, d *data, id uint) bool {
	auther, err := d.store.Auth.Get(fbAuth.MethodProxyAuth)
	if err != nil {
		return false
	}

	proxy, ok := auther.(*fbAuth.ProxyAuth)
	if !ok || proxy.Header == "" {
		return false
	}

	username := r.Header.Get(proxy.Header)
	if username == "" {
		return false
	}

	user, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, username)
	if err != nil {
		return false
	}

	return user.ID == id
}

func withUser(fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		keyFunc := func(_ *jwt.Token) (interface{}, error) {
			return d.settings.Key, nil
		}

		var tk authToken
		p := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())

		var (
			token *jwt.Token
			err   error
		)
		if raw := authValue(r); raw != "" {
			token, err = p.ParseWithClaims(raw, &tk, keyFunc)
		} else {
			err = request.ErrNoTokenInRequest
		}

		if err != nil || token == nil || !token.Valid {
			if !renewableErr(err, r, d, &tk) {
				return mediaOrUnauthorized(w, r, d, fn)
			}
		}

		expiresSoon := tk.ExpiresAt != nil && time.Until(tk.ExpiresAt.Time) < time.Hour
		updated := tk.IssuedAt != nil && tk.IssuedAt.Unix() < d.store.Users.LastUpdate(tk.User.ID)

		if expiresSoon || updated {
			w.Header().Add("X-Renew-Token", "true")
		}

		user, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, tk.User.ID)
		if err != nil {
			return http.StatusInternalServerError, err
		}
		d.user = user

		// Every authenticated reply reissues the media cookie, so its short
		// lifetime only ever expires after genuine idleness.
		setMediaCredential(w, d.settings.Key, user.ID)

		canonicalizeRequestPath(r)
		return fn(w, r, d)
	}
}

// mediaOrUnauthorized is the way in for the requests the browser issues itself.
//
// A thumbnail, a video stream or a download opened in a new tab cannot carry a
// header, so the only credential it can present is the media cookie — resolved
// by the middleware into a user on the request context. Anything else is turned
// away as before.
func mediaOrUnauthorized(w http.ResponseWriter, r *http.Request, d *data, fn handleFunc) (int, error) {
	userID, ok := mediaUserFromContext(r.Context())
	if !ok {
		return http.StatusUnauthorized, nil
	}

	user, err := d.store.Users.Get(d.server.Root, d.server.FollowExternalSymlinks, userID)
	if err != nil {
		return http.StatusUnauthorized, nil
	}
	d.user = user

	setMediaCredential(w, d.settings.Key, user.ID)

	canonicalizeRequestPath(r)
	return fn(w, r, d)
}

func withAdmin(fn handleFunc) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if !d.user.Perm.Admin {
			return http.StatusForbidden, nil
		}

		return fn(w, r, d)
	})
}

func loginHandler(tokenExpireTime time.Duration) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)
		}

		auther, err := d.store.Auth.Get(d.settings.AuthMethod)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		user, err := auther.Auth(r, d.store.Users, d.settings, d.server)
		switch {
		case errors.Is(err, os.ErrPermission):
			return http.StatusForbidden, nil
		case err != nil:
			return http.StatusInternalServerError, err
		}

		return printToken(w, r, d, user, tokenExpireTime)
	}
}

type signupBody struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

var signupHandler = func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
	if !d.settings.Signup {
		return http.StatusMethodNotAllowed, nil
	}

	if r.Body == nil {
		return http.StatusBadRequest, nil
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)

	info := &signupBody{}
	err := json.NewDecoder(r.Body).Decode(info)
	if err != nil {
		return http.StatusBadRequest, err
	}

	if info.Password == "" || info.Username == "" {
		return http.StatusBadRequest, nil
	}

	user := &users.User{
		Username: info.Username,
	}

	d.settings.Defaults.Apply(user)

	// Users signed up via the signup handler should never become admins, even
	// if that is the default permission.
	user.Perm.Admin = false

	// Self-registered users should not inherit execution capabilities from
	// default settings, regardless of what the administrator has configured
	// as the default. Execution rights must be explicitly granted by an admin.
	user.Perm.Execute = false
	user.Commands = []string{}

	pwd, err := users.ValidateAndHashPwd(info.Password, d.settings.MinimumPasswordLength)
	if err != nil {
		return http.StatusBadRequest, err
	}

	user.Password = pwd

	derivedScope, err := d.settings.CreateUserHome(user, d.server.Root, false)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	log.Printf("new user: %s, home dir: [%s].", user.Username, user.Scope)

	err = d.store.Users.SaveProvisioned(user, derivedScope)
	if errors.Is(err, fberrors.ErrExist) {
		return http.StatusConflict, err
	} else if err != nil {
		return http.StatusInternalServerError, err
	}

	return http.StatusOK, nil
}

func renewHandler(tokenExpireTime time.Duration) handleFunc {
	return withUser(func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		w.Header().Set("X-Renew-Token", "false")
		return printToken(w, r, d, d.user, tokenExpireTime)
	})
}

func printToken(w http.ResponseWriter, _ *http.Request, d *data, user *users.User, tokenExpirationTime time.Duration) (int, error) {
	claims := &authToken{
		User: userInfo{
			ID:                    user.ID,
			Locale:                user.Locale,
			ViewMode:              user.ViewMode,
			SingleClick:           user.SingleClick,
			RedirectAfterCopyMove: user.RedirectAfterCopyMove,
			Perm:                  user.Perm,
			LockPassword:          user.LockPassword,
			Commands:              user.Commands,
			HideDotfiles:          user.HideDotfiles,
			DateFormat:            user.DateFormat,
			Username:              user.Username,
			AceEditorTheme:        user.AceEditorTheme,
		},
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(tokenExpirationTime)),
			Issuer:    "File Browser",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(d.settings.Key)
	if err != nil {
		return http.StatusInternalServerError, err
	}

	w.Header().Set("Cache-Control", "no-store")

	// The cookie the browser will present on the requests it issues itself. It
	// is issued here because login is the first place a user is known.
	setMediaCredential(w, d.settings.Key, user.ID)

	// A client that sent a session key gets its token encrypted. That is what
	// keeps the JWT off the wire entirely: the login response would otherwise
	// hand an eavesdropper the very bearer token the credential scheme exists to
	// hide. Clients that sent no session key — the CLI, curl, third-party
	// clients — keep getting the plaintext token they have always had.
	if len(d.sessionKey) > 0 {
		body, err := sealSessionReply(d.settings.Key, d.sessionKey, signed)
		if err != nil {
			return http.StatusInternalServerError, err
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		if _, err := w.Write(body); err != nil {
			return http.StatusInternalServerError, err
		}
		return 0, nil
	}

	w.Header().Set("Content-Type", "text/plain")
	if _, err := w.Write([]byte(signed)); err != nil {
		return http.StatusInternalServerError, err
	}
	return 0, nil
}
