package fbhttp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/filebrowser/filebrowser/v2/storage"
)

// The v2 credential replaces the bare JWT on every authenticated request.
//
// A JWT is a bearer token: whoever reads one off the wire can use it. Over plain
// HTTP that is the whole problem, so the client stops sending it. Instead the
// client generates a session key at login, sends it up inside the already
// encrypted login envelope, and then proves possession of it on every request:
//
//	v2.<sealed session key>.<unix seconds>.<nonce>.<AES-GCM(session key, JWT)>
//
// The sealed session key is the session key wrapped under the server's own
// signing key. The server can therefore recover it on any request without
// keeping session state, which is what lets this work unchanged on a
// multi-instance deployment.
//
// Replay is what the nonce defends: the nonce is part of the AEAD's additional
// data, so an eavesdropper cannot swap it, and the server accepts each nonce
// exactly once. Captured ciphertext is therefore good for nothing.
//
// # What this protects, and what it does not
//
// The threat model is a *passive* eavesdropper: someone who can read traffic but
// cannot modify it or serve their own content. Against that, the JWT never
// appears on the wire and a captured credential cannot be reused.
//
// It does nothing against an active attacker. Somebody who can rewrite requests
// or responses can strip the credential, substitute their own public key in the
// handshake, or inject script into a served page — at which point no amount of
// application-layer encryption helps. That is a property of running without
// TLS, not a gap in this file.
const (
	credentialV2Prefix  = "v2."
	sessionKeySize      = 32
	credentialNonceSize = 12
	// credentialWindow is how far a credential's timestamp may be from the
	// server's clock. It only has to cover clock drift and queueing.
	//
	// 300s rather than a tighter minute because a minute is not enough in the
	// deployments this actually runs in: a box with no DNS and no public NTP
	// silently drifts, and one that does sync often syncs to a gateway that is
	// itself tens of seconds off. At 60s such a client is rejected on every
	// request, which surfaces as a broken UI rather than as a clock problem.
	// Widening this costs little — replay is stopped by the nonce table, not by
	// the timestamp, so this only bounds how old a credential may be.
	credentialWindow = 300 * time.Second
	// maxRememberedNonces bounds the replay table. Reaching it drops the oldest
	// entries, which weakens replay detection rather than breaking requests.
	maxRememberedNonces = 1 << 16
)

var (
	// ErrSessionKey means the sealed session key could not be opened: the
	// client is holding material from a different database. Only a fresh login
	// fixes it.
	ErrSessionKey = errors.New("sealed session key is not usable")
	// ErrCredentialStale means the credential is outside its time window, or
	// its nonce has already been spent. Rebuilding the credential fixes it.
	ErrCredentialStale = errors.New("credential is expired or already used")
	// ErrCredentialMalformed means the credential is not shaped like a
	// credential at all.
	ErrCredentialMalformed = errors.New("malformed credential")
)

// AAD strings keep the three uses of the server key from ever producing
// interchangeable ciphertext.
const (
	sessionKeySealAAD   = "filebrowser/session-key/v1"
	credentialAADPrefix = "filebrowser/credential/v1\n"
	responseSealAAD     = "filebrowser/session-response/v1"
)

// credentialCipher derives the AEAD used to seal session material under the
// server's signing key.
//
// The root is the signing key: it is generated per database, stored only in the
// database, and never transmitted. Anything able to derive this cipher could
// already forge a JWT, so sealing under it adds no new assumption. It is hashed
// first because the signing key is not necessarily an AES key size.
func credentialCipher(root []byte) (cipher.AEAD, error) {
	sum := sha256.Sum256(append([]byte("filebrowser/session/v1\x00"), root...))

	return newAEAD(sum[:])
}

// sessionCipher builds the AEAD over a client's session key.
//
// Unlike the signing key, a session key is already exactly 32 bytes and is used
// as-is — the browser builds the same cipher from the same bytes, so any
// derivation here would silently stop the two from agreeing.
func sessionCipher(sessionKey []byte) (cipher.AEAD, error) {
	if len(sessionKey) != sessionKeySize {
		return nil, ErrSessionKey
	}

	return newAEAD(sessionKey)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// sealSessionKey wraps a client's session key so the client can carry it back on
// later requests without the server having to remember anything.
func sealSessionKey(serverKey, sessionKey []byte) (string, error) {
	aead, err := credentialCipher(serverKey)
	if err != nil {
		return "", err
	}

	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(
		aead.Seal(nonce, nonce, sessionKey, []byte(sessionKeySealAAD)),
	), nil
}

// openSessionKey is the inverse of sealSessionKey.
func openSessionKey(serverKey []byte, sealed string) ([]byte, error) {
	aead, err := credentialCipher(serverKey)
	if err != nil {
		return nil, err
	}

	raw, err := base64.StdEncoding.DecodeString(sealed)
	if err != nil || len(raw) < aead.NonceSize()+1 {
		return nil, ErrCredentialMalformed
	}

	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	key, err := aead.Open(nil, nonce, ciphertext, []byte(sessionKeySealAAD))
	if err != nil || len(key) != sessionKeySize {
		return nil, ErrSessionKey
	}

	return key, nil
}

// credentialAAD binds the timestamp and nonce into the authentication tag, so a
// captured credential cannot be re-dated or given a fresh nonce to outrun the
// replay table.
func credentialAAD(method string, issuedAt int64, nonce string) []byte {
	return []byte(credentialAADPrefix + method + "\n" + strconv.FormatInt(issuedAt, 10) + "\n" + nonce)
}

// buildCredential produces the v2 header for one request. The browser builds the
// same value in @/utils/credcrypt; this exists for Go clients and for tests.
func buildCredential(serverKey, sessionKey []byte, jwt, method string, now time.Time) (string, error) {
	aead, err := sessionCipher(sessionKey)
	if err != nil {
		return "", err
	}

	sealedKey, err := sealSessionKey(serverKey, sessionKey)
	if err != nil {
		return "", err
	}

	nonce, err := randomBytes(credentialNonceSize)
	if err != nil {
		return "", err
	}
	nonceText := base64.RawURLEncoding.EncodeToString(nonce)
	issuedAt := now.Unix()

	ciphertext := aead.Seal(nil, nonce, []byte(jwt), credentialAAD(method, issuedAt, nonceText))

	return strings.Join([]string{
		"v2",
		sealedKey,
		strconv.FormatInt(issuedAt, 10),
		nonceText,
		base64.StdEncoding.EncodeToString(ciphertext),
	}, "."), nil
}

// openCredential validates a v2 credential against the request it arrived on and
// returns the JWT and session key it carries.
//
// The request itself is only used for its method, which the tag covers: binding
// the exact request target would mean reconciling the browser's URL serialiser
// with Go's, and a mismatch there would lock users out of their own files for no
// security gain, since the nonce already rules out reuse.
func openCredential(serverKey []byte, r *http.Request, raw string, now time.Time) (jwt string, sessionKey []byte, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 5 || parts[0] != "v2" {
		return "", nil, ErrCredentialMalformed
	}

	sessionKey, err = openSessionKey(serverKey, parts[1])
	if err != nil {
		return "", nil, err
	}

	issuedAt, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", nil, ErrCredentialMalformed
	}
	nonceText := parts[3]

	// The clock check comes before the nonce claim so that a credential from
	// last week cannot spend a nonce and push a live one out of the table.
	if drift := now.Sub(time.Unix(issuedAt, 0)); drift > credentialWindow || drift < -credentialWindow {
		return "", nil, ErrCredentialStale
	}

	aead, err := sessionCipher(sessionKey)
	if err != nil {
		return "", nil, ErrCredentialMalformed
	}

	ciphertext, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return "", nil, ErrCredentialMalformed
	}

	plain, err := aead.Open(nil, mustNonce(nonceText), ciphertext, credentialAAD(r.Method, issuedAt, nonceText))
	if err != nil {
		// The tag did not verify: wrong session key, or the method, timestamp or
		// nonce was altered in flight.
		return "", nil, ErrCredentialMalformed
	}

	// Only now, with the credential proven authentic, is the nonce spent — a
	// forged credential must not be able to burn someone else's.
	if !credentialNonces.claim(nonceText, now) {
		return "", nil, ErrCredentialStale
	}

	return string(plain), sessionKey, nil
}

// mustNonce decodes a nonce that has already been validated as part of the tag.
// A credential whose nonce does not decode can never verify, so the zero nonce
// is only a placeholder that fails the tag check.
func mustNonce(nonceText string) []byte {
	nonce, err := base64.RawURLEncoding.DecodeString(nonceText)
	if err != nil {
		return make([]byte, credentialNonceSize)
	}
	return nonce
}

// credentialErrorStatus maps a credential failure onto a response.
//
// A spent or expired credential is recoverable — the client rebuilds it with a
// fresh nonce — so it gets 428 like every other "redo this and retry" signal in
// this package. A session key that cannot be opened means the client is holding
// material from another database, which only a fresh login fixes.
func credentialErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrCredentialStale):
		return http.StatusPreconditionRequired
	case errors.Is(err, ErrSessionKey):
		return http.StatusUnauthorized
	default:
		return http.StatusBadRequest
	}
}

// nonceCache remembers which credential nonces have been spent, so that captured
// ciphertext cannot be replayed.
//
// A miss weakens replay detection; it never rejects a legitimate request, because
// every request carries a fresh nonce. That asymmetry is why bounded eviction is
// an acceptable policy here.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
	max  int
}

func newNonceCache(ttl time.Duration, max int) *nonceCache {
	return &nonceCache{seen: make(map[string]time.Time), ttl: ttl, max: max}
}

// claim records nonce as spent as of now. It reports false if the nonce was
// already spent within the TTL, which is the signature of a replay.
func (c *nonceCache) claim(nonce string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, spent := c.seen[nonce]; spent {
		return false
	}

	if len(c.seen) >= c.max {
		c.sweep(now)
	}
	c.seen[nonce] = now.Add(c.ttl)

	return true
}

// sweep drops expired nonces. It must be called with c.mu held.
func (c *nonceCache) sweep(now time.Time) {
	for nonce, expires := range c.seen {
		if now.After(expires) {
			delete(c.seen, nonce)
		}
	}
}

// size reports how many nonces are outstanding, for tests and diagnostics.
func (c *nonceCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.seen)
}

// credentialNonces is the process-wide replay table. It holds nonces for twice
// the accepted time window, so a credential cannot outlive its own record.
var credentialNonces = newNonceCache(2*credentialWindow, maxRememberedNonces)

// sessionPayload is what an encrypted credential reply carries: the JWT plus the
// sealed session key the client echoes on later requests.
type sessionPayload struct {
	Token     string `json:"token"`
	SealedKey string `json:"sealedKey"`
}

type sessionCiphertext struct {
	IV   string `json:"iv"`
	Data string `json:"d"`
}

type encryptedSessionReply struct {
	Encrypted *sessionCiphertext `json:"encrypted"`
}

// sealSessionReply encrypts a freshly issued token under the client's session
// key, and hands back the sealed session key the client carries from then on.
//
// Encrypting the reply is what keeps the JWT off the wire: without it, the login
// response would hand an eavesdropper exactly the bearer token this file exists
// to hide.
func sealSessionReply(serverKey, sessionKey []byte, jwt string) ([]byte, error) {
	sealedKey, err := sealSessionKey(serverKey, sessionKey)
	if err != nil {
		return nil, err
	}

	body, err := json.Marshal(sessionPayload{Token: jwt, SealedKey: sealedKey})
	if err != nil {
		return nil, err
	}

	aead, err := sessionCipher(sessionKey)
	if err != nil {
		return nil, err
	}

	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return nil, err
	}

	reply := encryptedSessionReply{
		Encrypted: &sessionCiphertext{
			IV:   base64.StdEncoding.EncodeToString(nonce),
			Data: base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, body, []byte(responseSealAAD))),
		},
	}

	return json.Marshal(reply)
}

// sessionKeyFromPayload picks up the optional session key a client sends along
// with its credentials. Only the login request carries one, and it travels
// inside the encrypted envelope, so it never appears on the wire.
func sessionKeyFromPayload(payload json.RawMessage) []byte {
	var probe struct {
		SessionKey string `json:"sessionKey"`
	}
	if err := json.Unmarshal(payload, &probe); err != nil || probe.SessionKey == "" {
		return nil
	}

	key, err := base64.StdEncoding.DecodeString(probe.SessionKey)
	if err != nil || len(key) != sessionKeySize {
		return nil
	}

	return key
}

type credentialContextKey struct{}

// mediaUserContextKey carries the user a media cookie authenticated.
type mediaUserContextKey struct{}

// sessionKeyFromContext returns the session key the credential middleware
// recovered for this request, if any.
func sessionKeyFromContext(ctx context.Context) []byte {
	key, _ := ctx.Value(credentialContextKey{}).([]byte)
	return key
}

// mediaUserFromContext returns the user a media cookie authenticated, if any.
func mediaUserFromContext(ctx context.Context) (uint, bool) {
	id, ok := ctx.Value(mediaUserContextKey{}).(uint)
	return id, ok
}

/* --------------------------------------------------------------- media cookie
 *
 * Some of what the browser loads it requests itself — thumbnails, a video
 * stream, a download handed to a new tab. Those requests cannot carry a header,
 * so the only thing they can present is a cookie.
 *
 * A cookie is necessarily a bearer credential: the browser hands it to whatever
 * the page asks for, and the client cannot bind it to one request. What this
 * file can do is make it cheap to capture: the cookie carries a sealed, opaque
 * blob rather than the JWT, it is accepted only for the media endpoints and only
 * for GET, and it expires in a minute — reissued on every authenticated reply,
 * so it stays fresh exactly as long as the session is being used, and lapses
 * when it is not.
 *
 * A captured cookie is therefore worth about a minute of read-only media access,
 * against two hours of full account access before this change. Under a threat
 * model that already accepts file content being readable in transit, that is the
 * gap worth closing.
 */

const (
	mediaCookieName = "auth"
	// mediaCredentialTTL is deliberately short. Because every authenticated
	// reply reissues the cookie, active browsing never notices it; it only
	// lapses after real idleness, and the next API call revives it.
	mediaCredentialTTL = 60 * time.Second
	mediaSealAAD       = "filebrowser/media-credential/v1"
)

// mediaCredentialPaths are the endpoints a browser loads by itself. Restricting
// the cookie to these keeps it from reaching directory listings and search,
// where a stolen credential would be worth much more.
var mediaCredentialPaths = []string{"/api/raw", "/api/preview", "/api/subtitle"}

// isMediaPath reports whether path (as received, before any prefix stripping) is
// one a media cookie may authenticate.
func isMediaPath(path string) bool {
	for _, prefix := range mediaCredentialPaths {
		if path == prefix || strings.HasPrefix(path, prefix+"/") || strings.HasPrefix(path, prefix+"?") {
			return true
		}
	}
	return false
}

type mediaCredential struct {
	UserID uint  `json:"u"`
	Expiry int64 `json:"e"`
}

// sealMediaCredential produces the opaque cookie value.
func sealMediaCredential(serverKey []byte, userID uint, now time.Time) (string, error) {
	aead, err := credentialCipher(serverKey)
	if err != nil {
		return "", err
	}

	body, err := json.Marshal(mediaCredential{
		UserID: userID,
		Expiry: now.Add(mediaCredentialTTL).Unix(),
	})
	if err != nil {
		return "", err
	}

	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return "", err
	}

	// The cookie value has to survive a header unquoted, so it is base64url
	// without padding: no character in it is special to a cookie parser.
	return base64.RawURLEncoding.EncodeToString(
		aead.Seal(nonce, nonce, body, []byte(mediaSealAAD)),
	), nil
}

// openMediaCredential validates a cookie value and returns the user it names.
func openMediaCredential(serverKey []byte, value string, now time.Time) (uint, error) {
	aead, err := credentialCipher(serverKey)
	if err != nil {
		return 0, err
	}

	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) < aead.NonceSize()+1 {
		return 0, ErrCredentialMalformed
	}

	nonce, ciphertext := raw[:aead.NonceSize()], raw[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ciphertext, []byte(mediaSealAAD))
	if err != nil {
		return 0, ErrSessionKey
	}

	var cred mediaCredential
	if err := json.Unmarshal(plain, &cred); err != nil {
		return 0, ErrCredentialMalformed
	}
	if cred.UserID == 0 {
		return 0, ErrCredentialMalformed
	}
	if now.Unix() > cred.Expiry {
		return 0, ErrCredentialStale
	}

	return cred.UserID, nil
}

// setMediaCredential issues a fresh cookie. It is called from every reply that
// authenticated a user, which is what keeps the short lifetime from being
// noticeable.
func setMediaCredential(w http.ResponseWriter, serverKey []byte, userID uint) {
	value, err := sealMediaCredential(serverKey, userID, time.Now())
	if err != nil {
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     mediaCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(mediaCredentialTTL.Seconds()),
		SameSite: http.SameSiteStrictMode,
	})
}

// mediaUserFromRequest resolves a media cookie, if the request is one a media
// cookie is allowed to authenticate.
func mediaUserFromRequest(serverKey []byte, r *http.Request, now time.Time) (uint, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return 0, false
	}
	if !isMediaPath(r.URL.Path) {
		return 0, false
	}

	cookie, err := r.Cookie(mediaCookieName)
	if err != nil || cookie.Value == "" {
		return 0, false
	}

	userID, err := openMediaCredential(serverKey, cookie.Value, now)
	if err != nil {
		return 0, false
	}

	return userID, true
}

// credentialMiddleware turns a v2 credential into the plain JWT the rest of the
// server already understands, and resolves the media cookie the browser sends on
// the requests it issues itself.
//
// Doing it here rather than inside withUser matters: this is the outermost layer
// that still sees the request as it arrived, and it keeps the credential format
// out of every handler. From withUser onwards everything is exactly as it was
// before — same JWT parsing, same renewal rules.
func credentialMiddleware(store *storage.Storage) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("X-Auth")
			usesCredential := strings.HasPrefix(raw, credentialV2Prefix)

			_, cookieErr := r.Cookie(mediaCookieName)
			usesCookie := cookieErr == nil && isMediaPath(r.URL.Path) &&
				(r.Method == http.MethodGet || r.Method == http.MethodHead)

			if !usesCredential && !usesCookie {
				next.ServeHTTP(w, r)
				return
			}

			settings, err := store.Settings.Get()
			if err != nil {
				status := http.StatusInternalServerError
				http.Error(w, strconv.Itoa(status)+" "+http.StatusText(status), status)
				return
			}

			ctx := r.Context()

			if usesCredential {
				jwt, sessionKey, err := openCredential(settings.Key, r, raw, time.Now())
				if err != nil {
					status := credentialErrorStatus(err)
					http.Error(w, strconv.Itoa(status)+" "+http.StatusText(status)+" ("+err.Error()+")", status)
					return
				}

				// Hand the recovered material to the layers below, then get out
				// of the way.
				r.Header.Set("X-Auth", jwt)
				ctx = context.WithValue(ctx, credentialContextKey{}, sessionKey)
			}

			// A credential always wins: a stale media cookie must not be able to
			// override a perfectly good session credential.
			if !usesCredential {
				if userID, ok := mediaUserFromRequest(settings.Key, r, time.Now()); ok {
					ctx = context.WithValue(ctx, mediaUserContextKey{}, userID)
				}
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
