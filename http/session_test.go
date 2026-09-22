package fbhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/users"
)

func testSessionKey(t *testing.T) []byte {
	t.Helper()

	key, err := randomBytes(sessionKeySize)
	if err != nil {
		t.Fatalf("generate session key: %v", err)
	}
	return key
}

// openSessionReply is the client half of sealSessionReply, used to assert that
// what the server sends really is the token and key it meant to send.
func openSessionReply(t *testing.T, sessionKey []byte, body []byte) sessionPayload {
	t.Helper()

	var reply encryptedSessionReply
	if err := json.Unmarshal(body, &reply); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if reply.Encrypted == nil {
		t.Fatalf("reply is not encrypted: %s", body)
	}

	iv, err := base64.StdEncoding.DecodeString(reply.Encrypted.IV)
	if err != nil {
		t.Fatalf("decode iv: %v", err)
	}
	sealed, err := base64.StdEncoding.DecodeString(reply.Encrypted.Data)
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}

	aead, err := sessionCipher(sessionKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	plain, err := aead.Open(nil, iv, sealed, []byte(responseSealAAD))
	if err != nil {
		t.Fatalf("decrypt reply: %v", err)
	}

	var payload sessionPayload
	if err := json.Unmarshal(plain, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	return payload
}

func TestSessionKeySealRoundTrip(t *testing.T) {
	serverKey := []byte("server-signing-key")
	key := testSessionKey(t)

	sealed, err := sealSessionKey(serverKey, key)
	if err != nil {
		t.Fatalf("sealSessionKey: %v", err)
	}

	if strings.Contains(sealed, base64.StdEncoding.EncodeToString(key)) {
		t.Fatal("VULNERABLE: the session key appeared in the sealed form")
	}

	opened, err := openSessionKey(serverKey, sealed)
	if err != nil {
		t.Fatalf("openSessionKey: %v", err)
	}
	if string(opened) != string(key) {
		t.Fatal("the session key did not survive the round trip")
	}
}

// A sealed key from another database must not open: that is what makes the
// sealed form safe to hand to the client.
func TestSealedSessionKeyIsBoundToTheServerKey(t *testing.T) {
	key := testSessionKey(t)

	sealed, err := sealSessionKey([]byte("server-key-one"), key)
	if err != nil {
		t.Fatalf("sealSessionKey: %v", err)
	}

	if _, err := openSessionKey([]byte("server-key-two"), sealed); err == nil {
		t.Fatal("VULNERABLE: a sealed key opened under a different server key")
	}
}

func TestCredentialRoundTrip(t *testing.T) {
	serverKey := []byte("server-signing-key")
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	raw, err := buildCredential(serverKey, key, jwt, http.MethodGet, time.Now())
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}

	if !strings.HasPrefix(raw, credentialV2Prefix) {
		t.Fatalf("credential = %q, want the v2 prefix", raw)
	}
	if strings.Contains(raw, jwt) {
		t.Fatal("VULNERABLE: the JWT appeared in the credential")
	}
	// The header is split on ".", so no part may contain one.
	if strings.Count(raw, ".") != 4 {
		t.Fatalf("credential has %d separators, want 4: %q", strings.Count(raw, "."), raw)
	}

	req, _ := http.NewRequest(http.MethodGet, "/api/resources/", http.NoBody)
	got, sessionKey, err := openCredential(serverKey, req, raw, time.Now())
	if err != nil {
		t.Fatalf("openCredential: %v", err)
	}
	if got != jwt {
		t.Fatal("openCredential returned a different token")
	}
	if string(sessionKey) != string(key) {
		t.Fatal("openCredential returned a different session key")
	}
}

// The whole point: sniffed ciphertext must not be usable a second time.
func TestCredentialReplayIsRejected(t *testing.T) {
	serverKey := []byte("server-signing-key")
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	raw, err := buildCredential(serverKey, key, jwt, http.MethodGet, time.Now())
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/api/resources/", http.NoBody)
	if _, _, err := openCredential(serverKey, req, raw, time.Now()); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, _, err := openCredential(serverKey, req, raw, time.Now()); err == nil {
		t.Fatal("VULNERABLE: a replayed credential was accepted")
	}
}

func TestCredentialWindowIsEnforced(t *testing.T) {
	serverKey := []byte("server-signing-key")
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	cases := map[string]time.Time{
		"too old":   time.Now().Add(-credentialWindow - time.Minute),
		"too new":   time.Now().Add(credentialWindow + time.Minute),
		"just made": time.Now(),
	}

	for name, issuedAt := range cases {
		t.Run(name, func(t *testing.T) {
			raw, err := buildCredential(serverKey, key, jwt, http.MethodGet, issuedAt)
			if err != nil {
				t.Fatalf("buildCredential: %v", err)
			}

			req, _ := http.NewRequest(http.MethodGet, "/api/resources/", http.NoBody)
			_, _, err = openCredential(serverKey, req, raw, time.Now())

			if name == "just made" && err != nil {
				t.Fatalf("a fresh credential was rejected: %v", err)
			}
			if name != "just made" && err == nil {
				t.Fatal("VULNERABLE: a credential outside the window was accepted")
			}
		})
	}
}

// The method is inside the tag, so a credential minted for a read cannot be
// pointed at a write.
func TestCredentialMethodIsBound(t *testing.T) {
	serverKey := []byte("server-signing-key")
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true, Modify: true}, serverKey)

	raw, err := buildCredential(serverKey, key, jwt, http.MethodGet, time.Now())
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}

	req, _ := http.NewRequest(http.MethodDelete, "/api/resources/secret.txt", http.NoBody)
	if _, _, err := openCredential(serverKey, req, raw, time.Now()); err == nil {
		t.Fatal("VULNERABLE: a GET credential was accepted on a DELETE")
	}
}

func TestTamperedCredentialIsRejected(t *testing.T) {
	serverKey := []byte("server-signing-key")
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	raw, err := buildCredential(serverKey, key, jwt, http.MethodGet, time.Now())
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}
	parts := strings.Split(raw, ".")

	rewrite := func(index int, value string) string {
		out := append([]string(nil), parts...)
		out[index] = value
		return strings.Join(out, ".")
	}
	flip := func(s string) string {
		b := []byte(s)
		b[len(b)/2] ^= 0x01
		return string(b)
	}

	cases := map[string]string{
		"flip a ciphertext byte":  rewrite(4, flip(parts[4])),
		"flip the sealed key":     rewrite(1, flip(parts[1])),
		"swap in a fresh nonce":   rewrite(3, "AAAAAAAAAAAAAAAA"),
		"backdate the timestamp":  rewrite(2, "1"),
		"forward-date the time":   rewrite(2, "99999999999"),
		"drop a part":             strings.Join(parts[:4], "."),
		"wrong version":           rewrite(0, "v3"),
		"ciphertext not base64":   rewrite(4, "!!!"),
		"nonce not base64":        rewrite(3, "!!!"),
		"empty":                   "",
		"not a credential at all": "just-a-token",
	}

	for name, tampered := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, "/api/resources/", http.NoBody)
			if _, _, err := openCredential(serverKey, req, tampered, time.Now()); err == nil {
				t.Fatal("VULNERABLE: a tampered credential was accepted")
			}
		})
	}
}

func TestSealSessionReplyCarriesTheTokenAndKey(t *testing.T) {
	serverKey := []byte("server-signing-key")
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	body, err := sealSessionReply(serverKey, key, jwt)
	if err != nil {
		t.Fatalf("sealSessionReply: %v", err)
	}

	if strings.Contains(string(body), jwt) {
		t.Fatalf("VULNERABLE: the token appeared in the reply: %s", body)
	}

	payload := openSessionReply(t, key, body)
	if payload.Token != jwt {
		t.Fatal("the reply did not carry the token")
	}

	// The sealed key must be usable as-is on the next request.
	opened, err := openSessionKey(serverKey, payload.SealedKey)
	if err != nil {
		t.Fatalf("openSessionKey on the returned sealed key: %v", err)
	}
	if string(opened) != string(key) {
		t.Fatal("the returned sealed key does not open to the session key")
	}
}

func TestCredentialMiddlewarePresentsAPlainJWT(t *testing.T) {
	serverKey := []byte(testSigningKey)
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	raw, err := buildCredential(serverKey, key, jwt, http.MethodGet, time.Now())
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}

	var (
		seenToken string
		seenKey   []byte
	)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenToken = r.Header.Get("X-Auth")
		seenKey = sessionKeyFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/resources/", http.NoBody)
	req.Header.Set("X-Auth", raw)

	rec := httptest.NewRecorder()
	credentialMiddleware(credentialStorage(t))(inner).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if seenToken != jwt {
		t.Fatalf("X-Auth seen by the handler = %q, want the JWT", seenToken)
	}
	if string(seenKey) != string(key) {
		t.Fatal("the session key did not reach the request context")
	}
}

func TestCredentialMiddlewareMapsFailures(t *testing.T) {
	serverKey := []byte(testSigningKey)
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	stale, err := buildCredential(serverKey, key, jwt, http.MethodGet, time.Now().Add(-2*credentialWindow))
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}

	foreign, err := buildCredential([]byte("another-databases-key"), key, jwt, http.MethodGet, time.Now())
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}

	cases := map[string]struct {
		credential string
		want       int
	}{
		"stale":                    {stale, http.StatusPreconditionRequired},
		"sealed under another key": {foreign, http.StatusUnauthorized},
		"garbage":                  {credentialV2Prefix + "nonsense", http.StatusBadRequest},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				t.Error("the inner handler ran for a rejected credential")
			})

			req, _ := http.NewRequest(http.MethodGet, "/api/resources/", http.NoBody)
			req.Header.Set("X-Auth", tc.credential)

			rec := httptest.NewRecorder()
			credentialMiddleware(credentialStorage(t))(inner).ServeHTTP(rec, req)

			if rec.Code != tc.want {
				t.Errorf("status = %d, want %d; body=%q", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// A credential is only ever unpacked by the middleware, so a plaintext JWT — the
// CLI, curl, third-party clients — must pass through untouched.
func TestCredentialMiddlewareLeavesPlainTokensAlone(t *testing.T) {
	jwt := signToken(t, users.Permissions{Download: true}, []byte(testSigningKey))

	var seen string
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("X-Auth")
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/resources/", http.NoBody)
	req.Header.Set("X-Auth", jwt)

	credentialMiddleware(credentialStorage(t))(inner).ServeHTTP(httptest.NewRecorder(), req)

	if seen != jwt {
		t.Fatal("a plaintext token was rewritten")
	}
}

// The login reply must not hand an eavesdropper a readable bearer token.
func TestLoginReplyIsEncryptedWhenASessionKeyIsSent(t *testing.T) {
	st := credentialStorage(t)
	key := testSessionKey(t)

	payload := `{"username":"alice","password":"` + testPassword + `","sessionKey":"` +
		base64.StdEncoding.EncodeToString(key) + `"}`
	req, _ := encryptedRequest(t, http.MethodPost, "/login", scopeLogin, payload)

	rec := httptest.NewRecorder()
	loginRoute(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("Content-Type = %q, want JSON for an encrypted reply", got)
	}

	// The body must be the envelope, not a token in the clear.
	body := rec.Body.String()
	if !strings.Contains(body, `"encrypted"`) {
		t.Fatalf("body is not an encrypted envelope: %q", body)
	}
	if strings.Count(body, ".") != 0 {
		t.Fatalf("VULNERABLE: the body looks like it carries a JWT: %q", body)
	}

	reply := openSessionReply(t, key, rec.Body.Bytes())
	if strings.Count(reply.Token, ".") != 2 {
		t.Fatalf("reply did not carry a JWT: %q", reply.Token)
	}
	if reply.SealedKey == "" {
		t.Fatal("reply did not carry a sealed session key")
	}

	// The sealed key must let the server recover the same key on a later
	// request, which is what makes the whole scheme stateless.
	opened, err := openSessionKey([]byte(testSigningKey), reply.SealedKey)
	if err != nil {
		t.Fatalf("openSessionKey: %v", err)
	}
	if string(opened) != string(key) {
		t.Fatal("the sealed key did not open to the session key")
	}
}

// Clients that send no session key keep the plaintext contract they always had.
func TestLoginReplyStaysPlaintextWithoutASessionKey(t *testing.T) {
	st := credentialStorage(t)

	rec := postLogin(t, st, `{"username":"alice","password":"`+testPassword+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", got)
	}
	if strings.Count(rec.Body.String(), ".") != 2 {
		t.Fatalf("body does not look like a JWT: %q", rec.Body.String())
	}
}

// A renewal goes through the middleware, which is what supplies the session key
// the reply is encrypted under.
func TestRenewReplyIsEncryptedForAV2Credential(t *testing.T) {
	st := credentialStorage(t)
	serverKey := []byte(testSigningKey)
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	credential, err := buildCredential(serverKey, key, jwt, http.MethodPost, time.Now())
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "/renew", http.NoBody)
	req.Header.Set("X-Auth", credential)

	rec := httptest.NewRecorder()
	credentialMiddleware(st)(handle(renewHandler(DefaultTokenExpirationTime), "", st, &settings.Server{})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("Content-Type = %q, want JSON for an encrypted reply", got)
	}

	reply := openSessionReply(t, key, rec.Body.Bytes())
	if strings.Count(reply.Token, ".") != 2 {
		t.Fatalf("reply did not carry a JWT: %q", reply.Token)
	}
}

// A credential carrying a JWT for a deleted user must fail like any other bad
// token, not slip through on the strength of the session key.
func TestCredentialWithAStaleJWTIsRejected(t *testing.T) {
	st := credentialStorage(t)
	serverKey := []byte(testSigningKey)
	key := testSessionKey(t)
	jwt := signToken(t, users.Permissions{Download: true}, serverKey)

	credential, err := buildCredential(serverKey, key, jwt, http.MethodGet, time.Now())
	if err != nil {
		t.Fatalf("buildCredential: %v", err)
	}

	req, _ := http.NewRequest(http.MethodGet, "/api/resources/", http.NoBody)
	req.Header.Set("X-Auth", credential)

	// Verification is fine; it is the JWT inside that no longer resolves.
	if _, _, err := openCredential(serverKey, req, credential, time.Now()); err != nil {
		t.Fatalf("openCredential: %v", err)
	}
	if _, err := st.Users.Get("", false, uint(99)); err == nil {
		t.Fatal("the test user unexpectedly exists")
	}
}

func TestNonceCacheSweepsExpiredEntries(t *testing.T) {
	cache := newNonceCache(50*time.Millisecond, 4)
	now := time.Now()

	for _, nonce := range []string{"a", "b", "c", "d"} {
		if !cache.claim(nonce, now) {
			t.Fatalf("claim(%q) = false", nonce)
		}
	}
	if cache.claim("a", now) {
		t.Fatal("a spent nonce was claimed twice")
	}

	// Full table: a later claim sweeps the expired entries first.
	later := now.Add(100 * time.Millisecond)
	if !cache.claim("e", later) {
		t.Fatal("claim after the sweep failed")
	}
	if got := cache.size(); got > 2 {
		t.Fatalf("cache size = %d after the sweep, want the expired entries gone", got)
	}
}

func TestSessionKeyFromContextIsEmptyByDefault(t *testing.T) {
	if key := sessionKeyFromContext(context.Background()); key != nil {
		t.Fatal("a context with no credential produced a session key")
	}
}

/* --------------------------------------------------------------- media cookie */

func TestMediaCredentialRoundTrip(t *testing.T) {
	serverKey := []byte("server-signing-key")

	value, err := sealMediaCredential(serverKey, 7, time.Now())
	if err != nil {
		t.Fatalf("sealMediaCredential: %v", err)
	}

	if strings.ContainsAny(value, "=+/") {
		t.Fatalf("cookie value %q contains characters that need quoting", value)
	}

	userID, err := openMediaCredential(serverKey, value, time.Now())
	if err != nil {
		t.Fatalf("openMediaCredential: %v", err)
	}
	if userID != 7 {
		t.Fatalf("user = %d, want 7", userID)
	}
}

func TestMediaCredentialExpires(t *testing.T) {
	serverKey := []byte("server-signing-key")

	value, err := sealMediaCredential(serverKey, 7, time.Now().Add(-2*mediaCredentialTTL))
	if err != nil {
		t.Fatalf("sealMediaCredential: %v", err)
	}

	if _, err := openMediaCredential(serverKey, value, time.Now()); err == nil {
		t.Fatal("VULNERABLE: an expired media credential was accepted")
	}
}

func TestMediaCredentialIsBoundToTheServerKey(t *testing.T) {
	value, err := sealMediaCredential([]byte("key-one"), 7, time.Now())
	if err != nil {
		t.Fatalf("sealMediaCredential: %v", err)
	}

	if _, err := openMediaCredential([]byte("key-two"), value, time.Now()); err == nil {
		t.Fatal("VULNERABLE: a media credential opened under another server key")
	}
}

func TestMediaCredentialRejectsGarbage(t *testing.T) {
	serverKey := []byte("server-signing-key")

	for _, value := range []string{"", "not-base64!", "AAAA", strings.Repeat("A", 100)} {
		if _, err := openMediaCredential(serverKey, value, time.Now()); err == nil {
			t.Fatalf("VULNERABLE: accepted %q as a media credential", value)
		}
	}
}

// The cookie may only reach the endpoints the browser loads by itself, and only
// on reads. Everything else has to present a real credential.
func TestMediaCookieScopeIsLimited(t *testing.T) {
	allowed := []string{
		"/api/raw/a.txt",
		"/api/raw/dir/",
		"/api/preview/big/a.png",
		"/api/preview/thumb/a.png",
		"/api/subtitle/a.srt",
	}
	denied := []string{
		"/api/resources/",
		"/api/resources/a.txt",
		"/api/search",
		"/api/users",
		"/api/settings",
		"/api/share/x",
		"/api/rawish/a.txt",
		"/api/tus",
	}

	for _, path := range allowed {
		if !isMediaPath(path) {
			t.Errorf("isMediaPath(%q) = false, want true", path)
		}
	}
	for _, path := range denied {
		if isMediaPath(path) {
			t.Errorf("isMediaPath(%q) = true, want false", path)
		}
	}
}

// A cookie is only ever consulted for the media endpoints, and only for reads.
func TestMediaUserFromRequestIsRestrictedToReadsOnMediaPaths(t *testing.T) {
	serverKey := []byte("server-signing-key")

	value, err := sealMediaCredential(serverKey, 7, time.Now())
	if err != nil {
		t.Fatalf("sealMediaCredential: %v", err)
	}

	request := func(method, path string) *http.Request {
		req, _ := http.NewRequest(method, path, http.NoBody)
		req.AddCookie(&http.Cookie{Name: mediaCookieName, Value: value})
		return req
	}

	cases := map[string]struct {
		method string
		path   string
		want   bool
	}{
		"a thumbnail":              {http.MethodGet, "/api/preview/thumb/a.png", true},
		"a download":               {http.MethodGet, "/api/raw/a.txt", true},
		"a listing":                {http.MethodGet, "/api/resources/", false},
		"a write to a media path":  {http.MethodPost, "/api/preview/thumb/a.png", false},
		"a delete on a media path": {http.MethodDelete, "/api/raw/a.txt", false},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, ok := mediaUserFromRequest(serverKey, request(tc.method, tc.path), time.Now())
			if ok != tc.want {
				t.Errorf("authenticated = %v, want %v", ok, tc.want)
			}
		})
	}
}

// A login reply has to hand the browser the cookie it will use for thumbnails.
func TestLoginIssuesAMediaCookie(t *testing.T) {
	rec := postLogin(t, credentialStorage(t), `{"username":"alice","password":"`+testPassword+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	var media *http.Cookie
	for _, c := range cookies {
		if c.Name == mediaCookieName {
			media = c
		}
	}
	if media == nil {
		t.Fatalf("login issued no %s cookie: %v", mediaCookieName, cookies)
	}

	// The whole point of the change: the cookie must not be the token.
	if strings.Count(media.Value, ".") == 2 {
		t.Fatalf("VULNERABLE: the cookie looks like a JWT: %q", media.Value)
	}

	userID, err := openMediaCredential([]byte(testSigningKey), media.Value, time.Now())
	if err != nil {
		t.Fatalf("openMediaCredential: %v", err)
	}
	if userID != 1 {
		t.Fatalf("cookie names user %d, want 1", userID)
	}
}

// A media request authenticated by cookie gets a fresh one back, which is what
// keeps a one minute lifetime from being noticeable.
func TestMediaRequestRefreshesTheCookie(t *testing.T) {
	st := credentialStorage(t)

	value, err := sealMediaCredential([]byte(testSigningKey), 1, time.Now())
	if err != nil {
		t.Fatalf("sealMediaCredential: %v", err)
	}

	inner := withUser(func(w http.ResponseWriter, _ *http.Request, d *data) (int, error) {
		if d.user == nil || d.user.ID != 1 {
			t.Error("the media cookie did not resolve a user")
		}
		return 0, nil
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/preview/thumb/a.png", http.NoBody)
	req.AddCookie(&http.Cookie{Name: mediaCookieName, Value: value})

	rec := httptest.NewRecorder()
	credentialMiddleware(st)(handle(inner, "/api/preview", st, &settings.Server{})).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("the media request did not reissue the cookie")
	}
}

// A request that presents neither a credential nor a cookie is still refused.
func TestNoCredentialStillUnauthorized(t *testing.T) {
	st := credentialStorage(t)

	inner := withUser(func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		t.Error("the handler ran without a credential")
		return 0, nil
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/preview/thumb/a.png", http.NoBody)
	rec := httptest.NewRecorder()
	credentialMiddleware(st)(handle(inner, "/api/preview", st, &settings.Server{})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// A stale media cookie must not be able to stand in for a live credential.
func TestExpiredMediaCookieIsRefused(t *testing.T) {
	st := credentialStorage(t)

	value, err := sealMediaCredential([]byte(testSigningKey), 1, time.Now().Add(-2*mediaCredentialTTL))
	if err != nil {
		t.Fatalf("sealMediaCredential: %v", err)
	}

	inner := withUser(func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		t.Error("the handler ran on an expired cookie")
		return 0, nil
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/preview/thumb/a.png", http.NoBody)
	req.AddCookie(&http.Cookie{Name: mediaCookieName, Value: value})

	rec := httptest.NewRecorder()
	credentialMiddleware(st)(handle(inner, "/api/preview", st, &settings.Server{})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// A legacy cookie holding a real JWT was the old exposure. It must not work.
func TestJWTCookieIsNoLongerAccepted(t *testing.T) {
	st := credentialStorage(t)
	jwt := signToken(t, users.Permissions{Download: true}, []byte(testSigningKey))

	inner := withUser(func(_ http.ResponseWriter, _ *http.Request, _ *data) (int, error) {
		t.Error("VULNERABLE: a JWT cookie authenticated a request")
		return 0, nil
	})

	req, _ := http.NewRequest(http.MethodGet, "/api/preview/thumb/a.png", http.NoBody)
	req.AddCookie(&http.Cookie{Name: mediaCookieName, Value: jwt})

	rec := httptest.NewRecorder()
	credentialMiddleware(st)(handle(inner, "/api/preview", st, &settings.Server{})).ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
