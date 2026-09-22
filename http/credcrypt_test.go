package fbhttp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/asdine/storm/v3"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"

	fbAuth "github.com/filebrowser/filebrowser/v2/auth"
	"github.com/filebrowser/filebrowser/v2/credcrypt"
	"github.com/filebrowser/filebrowser/v2/settings"
	"github.com/filebrowser/filebrowser/v2/share"
	"github.com/filebrowser/filebrowser/v2/storage"
	"github.com/filebrowser/filebrowser/v2/storage/bolt"
	"github.com/filebrowser/filebrowser/v2/users"
)

const (
	testSigningKey = "test-signing-key"
	testPassword   = "correct-horse-battery-staple"
)

// secretMarker stands in for a password in the leak assertions. It is spelled
// with base64 alphabet characters only, so it *could* show up inside an encoded
// ciphertext — which is what makes "the body does not contain it" a real check
// rather than one that base64 is guaranteed to pass.
const secretMarker = "zqxjwsecretmarker7777"

// sealEnvelope does what the browser does: it seals payload under the service's
// public key and returns the envelope that replaces the request body.
func sealEnvelope(t *testing.T, svc *credcrypt.Service, challenge, payload string) credcrypt.Envelope {
	t.Helper()

	der, err := base64.StdEncoding.DecodeString(svc.PublicKey())
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("public key is %T, want *rsa.PublicKey", parsed)
	}

	key := make([]byte, 32)
	iv := make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("generate iv: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("new gcm: %v", err)
	}

	plain := []byte(`{"challenge":` + quote(challenge) + `,"payload":` + payload + `}`)

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}

	return credcrypt.Envelope{
		KeyID: svc.KeyID(),
		Key:   base64.StdEncoding.EncodeToString(wrapped),
		IV:    base64.StdEncoding.EncodeToString(iv),
		Data:  base64.StdEncoding.EncodeToString(gcm.Seal(nil, iv, plain, nil)),
	}
}

func quote(s string) string {
	quoted, _ := json.Marshal(s)
	return string(quoted)
}

// encryptedRequest builds a request whose body is an envelope for scope, sealing
// payload. It also returns the sealed body, so tests can assert on what actually
// goes on the wire.
func encryptedRequest(t *testing.T, method, target, scope, payload string) (*http.Request, string) {
	t.Helper()

	svc := credentialCrypto()
	challenge, err := svc.Challenge(scope)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	env := sealEnvelope(t, svc, challenge, payload)
	raw, err := json.Marshal(map[string]credcrypt.Envelope{"encrypted": env})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	req, err := http.NewRequest(method, target, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req, string(raw)
}

// rewriteEnvelope decodes a sealed body, applies mutate, and re-encodes it, so a
// test can corrupt exactly one field.
func rewriteEnvelope(t *testing.T, wire string, mutate func(*credcrypt.Envelope)) string {
	t.Helper()

	var parsed map[string]credcrypt.Envelope
	if err := json.Unmarshal([]byte(wire), &parsed); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}

	env := parsed["encrypted"]
	mutate(&env)

	raw, err := json.Marshal(map[string]credcrypt.Envelope{"encrypted": env})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(raw)
}

// credentialStorage returns a storage holding a single, non-admin user "alice",
// whose password is a real bcrypt hash, plus the settings JSON auth needs.
func credentialStorage(t *testing.T) *storage.Storage {
	t.Helper()
	return credentialStorageWithPassword(t, testPassword)
}

func credentialStorageWithPassword(t *testing.T, password string) *storage.Storage {
	t.Helper()

	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatalf("failed to get storage: %v", err)
	}

	hash, err := users.HashPwd(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if err := st.Users.Save(&users.User{
		Username: "alice",
		Password: hash,
		Perm:     users.Permissions{Create: true, Modify: true, Download: true, Share: true},
	}); err != nil {
		t.Fatalf("failed to save user: %v", err)
	}

	if err := st.Settings.Save(&settings.Settings{
		Key:                   []byte(testSigningKey),
		AuthMethod:            fbAuth.MethodJSONAuth,
		MinimumPasswordLength: 1,
	}); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	// loginHandler resolves the auther through the store, so the JSON auther has
	// to exist there just as `fb config init` leaves it.
	if err := st.Auth.Save(&fbAuth.JSONAuth{}); err != nil {
		t.Fatalf("failed to save auther: %v", err)
	}

	return st
}

// loginRoute and userRoute mirror how NewHandler wires the password-bearing
// routes, so these tests exercise the decorator and not the bare handler.
func loginRoute(st *storage.Storage) http.Handler {
	return handle(withEncryptedCredentials(scopeLogin, loginHandler(DefaultTokenExpirationTime)), "", st, &settings.Server{})
}

func userRoute(fn handleFunc, st *storage.Storage) http.Handler {
	return handle(withEncryptedCredentials(scopeUsers, fn), "", st, &settings.Server{})
}

func postLogin(t *testing.T, st *storage.Storage, body string) *httptest.ResponseRecorder {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	rec := httptest.NewRecorder()
	loginRoute(st).ServeHTTP(rec, req)
	return rec
}

func TestHandshakeIssuesKeyAndChallenge(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "/crypto/handshake", strings.NewReader(`{"scope":"login"}`))
	rec := httptest.NewRecorder()

	handle(cryptoHandshakeHandler(), "", credentialStorage(t), &settings.Server{}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("handshake status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	var resp handshakeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode handshake: %v", err)
	}

	if resp.Algorithm != credcrypt.Algorithm {
		t.Errorf("algorithm = %q, want %q", resp.Algorithm, credcrypt.Algorithm)
	}
	if resp.Challenge == "" || resp.Key == "" || resp.KeyID == "" {
		t.Fatalf("handshake returned an incomplete response: %s", rec.Body.String())
	}
	if resp.KeyID != credentialCrypto().KeyID() {
		t.Errorf("keyID = %q, want %q", resp.KeyID, credentialCrypto().KeyID())
	}
	if resp.ExpiresIn <= 0 {
		t.Errorf("expiresIn = %d, want > 0", resp.ExpiresIn)
	}

	// The advertised key must be the one the server can actually decrypt with.
	if _, err := credentialCrypto().Open(scopeLogin, sealEnvelope(t, credentialCrypto(), resp.Challenge, `{}`)); err != nil {
		t.Errorf("the challenge from the handshake was not redeemable: %v", err)
	}
}

func TestHandshakeRejectsUnknownScope(t *testing.T) {
	cases := map[string]string{
		"unknown scope": `{"scope":"not-a-scope"}`,
		"missing scope": `{}`,
		"not json":      `nonsense`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "/crypto/handshake", strings.NewReader(body))
			rec := httptest.NewRecorder()

			handle(cryptoHandshakeHandler(), "", credentialStorage(t), &settings.Server{}).ServeHTTP(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
			}
		})
	}
}

// The point of the whole change: a login whose credentials travel in an envelope
// must succeed, and must not put the password on the wire.
func TestLoginAcceptsEncryptedCredentials(t *testing.T) {
	st := credentialStorageWithPassword(t, secretMarker)

	req, wire := encryptedRequest(t, http.MethodPost, "/login", scopeLogin,
		`{"username":"alice","password":"`+secretMarker+`"}`)

	if strings.Contains(wire, secretMarker) {
		t.Fatalf("VULNERABLE: the password appeared in the request body: %s", wire)
	}
	if strings.Contains(wire, "password") {
		t.Fatalf("VULNERABLE: the credential field name appeared in the request body: %s", wire)
	}
	if !strings.Contains(wire, "encrypted") {
		t.Fatalf("the request body is not an envelope: %s", wire)
	}

	rec := httptest.NewRecorder()
	loginRoute(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("encrypted login status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if strings.Count(rec.Body.String(), ".") != 2 {
		t.Fatalf("login did not return a JWT: %q", rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// Legacy clients — the documented HTTP API, curl, mobile apps — still post in
// the clear, and must keep working.
func TestLoginStillAcceptsPlaintextCredentials(t *testing.T) {
	rec := postLogin(t, credentialStorage(t), `{"username":"alice","password":"`+testPassword+`"}`)

	if rec.Code != http.StatusOK {
		t.Fatalf("plaintext login status = %d, body=%q", rec.Code, rec.Body.String())
	}
}

// Ciphertext captured off the wire must not be usable a second time. The replay
// is built as a fresh request carrying the same bytes, which is what an attacker
// who captured them would actually send.
func TestLoginRejectsReplayedEnvelope(t *testing.T) {
	st := credentialStorage(t)

	_, wire := encryptedRequest(t, http.MethodPost, "/login", scopeLogin,
		`{"username":"alice","password":"`+testPassword+`"}`)

	// A replay is a fresh request carrying the same captured bytes.
	send := func() *httptest.ResponseRecorder {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(wire))
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		rec := httptest.NewRecorder()
		loginRoute(st).ServeHTTP(rec, req)
		return rec
	}

	if first := send(); first.Code != http.StatusOK {
		t.Fatalf("first login status = %d, body=%q", first.Code, first.Body.String())
	}

	if again := send(); again.Code != http.StatusPreconditionRequired {
		t.Fatalf("VULNERABLE: replayed envelope status = %d, want 428; body=%q", again.Code, again.Body.String())
	}
}

func TestLoginRejectsWrongPasswordInEnvelope(t *testing.T) {
	req, _ := encryptedRequest(t, http.MethodPost, "/login", scopeLogin,
		`{"username":"alice","password":"not-the-password"}`)

	rec := httptest.NewRecorder()
	loginRoute(credentialStorage(t)).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
}

func TestLoginRejectsUnknownUserInEnvelope(t *testing.T) {
	req, _ := encryptedRequest(t, http.MethodPost, "/login", scopeLogin,
		`{"username":"nobody","password":"`+testPassword+`"}`)

	rec := httptest.NewRecorder()
	loginRoute(credentialStorage(t)).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%q", rec.Code, rec.Body.String())
	}
}

// A challenge is only good for the operation it was issued for.
func TestEnvelopeIsBoundToItsScope(t *testing.T) {
	// Issued for signup, replayed at login.
	req, _ := encryptedRequest(t, http.MethodPost, "/login", scopeSignup,
		`{"username":"alice","password":"`+testPassword+`"}`)

	rec := httptest.NewRecorder()
	loginRoute(credentialStorage(t)).ServeHTTP(rec, req)

	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("VULNERABLE: cross-scope envelope status = %d, want 428; body=%q", rec.Code, rec.Body.String())
	}
}

// The key pair lives only as long as the process, so a client holding one from
// before a restart must be told to redo the handshake rather than be rejected
// outright.
func TestStaleKeyIsAnsweredWithPreconditionRequired(t *testing.T) {
	st := credentialStorage(t)

	_, wire := encryptedRequest(t, http.MethodPost, "/login", scopeLogin,
		`{"username":"alice","password":"`+testPassword+`"}`)

	stale, err := http.NewRequest(http.MethodPost, "/login",
		strings.NewReader(rewriteEnvelope(t, wire, func(e *credcrypt.Envelope) {
			e.KeyID = "stale-key-id"
		})))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	rec := httptest.NewRecorder()
	loginRoute(st).ServeHTTP(rec, stale)

	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("stale-key status = %d, want 428; body=%q", rec.Code, rec.Body.String())
	}
}

func TestTamperedEnvelopeIsRejected(t *testing.T) {
	st := credentialStorage(t)

	_, wire := encryptedRequest(t, http.MethodPost, "/login", scopeLogin,
		`{"username":"alice","password":"`+testPassword+`"}`)

	corrupted := rewriteEnvelope(t, wire, func(e *credcrypt.Envelope) {
		sealed, err := base64.StdEncoding.DecodeString(e.Data)
		if err != nil {
			t.Fatalf("decode ciphertext: %v", err)
		}
		sealed[len(sealed)/2] ^= 0x01
		e.Data = base64.StdEncoding.EncodeToString(sealed)
	})

	req, err := http.NewRequest(http.MethodPost, "/login", strings.NewReader(corrupted))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	rec := httptest.NewRecorder()
	loginRoute(st).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tampered status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
}

func TestSignupAcceptsEncryptedCredentials(t *testing.T) {
	root := t.TempDir()

	db, err := storm.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	st, err := bolt.NewStorage(db)
	if err != nil {
		t.Fatalf("failed to get storage: %v", err)
	}
	if err := st.Settings.Save(&settings.Settings{
		Key:                   []byte(testSigningKey),
		Signup:                true,
		CreateUserDir:         true,
		UserHomeBasePath:      "/users",
		MinimumPasswordLength: 1,
	}); err != nil {
		t.Fatalf("failed to save settings: %v", err)
	}

	req, wire := encryptedRequest(t, http.MethodPost, "/signup", scopeSignup,
		`{"username":"bob","password":"`+secretMarker+`"}`)

	if strings.Contains(wire, secretMarker) {
		t.Fatalf("VULNERABLE: the password appeared in the request body: %s", wire)
	}

	rec := httptest.NewRecorder()
	handle(withEncryptedCredentials(scopeSignup, signupHandler), "", st, &settings.Server{Root: root}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("encrypted signup status = %d, body=%q", rec.Code, rec.Body.String())
	}

	saved, err := st.Users.Get(root, false, "bob")
	if err != nil {
		t.Fatalf("signup did not create the user: %v", err)
	}
	if !users.CheckPwd(secretMarker, saved.Password) {
		t.Fatal("signup stored an unexpected password")
	}
}

// Changing a password sends both the new one and the current one, so the whole
// modify request travels in an envelope.
func TestUserUpdateAcceptsEncryptedCredentials(t *testing.T) {
	st := credentialStorage(t)
	const newPassword = "brandnewpassphrase9182"

	payload := `{"what":"user","which":["password"],"current_password":"` + testPassword +
		`","data":{"id":1,"username":"alice","password":"` + newPassword + `"}}`
	req, wire := encryptedRequest(t, http.MethodPut, "/users/1", scopeUsers, payload)

	if strings.Contains(wire, newPassword) || strings.Contains(wire, testPassword) {
		t.Fatalf("VULNERABLE: a password appeared in the request body: %s", wire)
	}

	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("X-Auth", signToken(t, users.Permissions{}, []byte(testSigningKey)))

	rec := httptest.NewRecorder()
	userRoute(userPutHandler, st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("encrypted user update status = %d, body=%q", rec.Code, rec.Body.String())
	}

	updated, err := st.Users.Get("", false, uint(1))
	if err != nil {
		t.Fatalf("failed to reload user: %v", err)
	}
	if !users.CheckPwd(newPassword, updated.Password) {
		t.Fatal("the new password was not applied")
	}
}

// If the envelope were not being decrypted, a wrong current_password would fail
// with a decode error; it must fail with the documented password error instead.
func TestUserUpdateChecksTheDecryptedCurrentPassword(t *testing.T) {
	st := credentialStorage(t)

	payload := `{"what":"user","which":["password"],"current_password":"wrong-password",` +
		`"data":{"id":1,"username":"alice","password":"whatever123456"}}`
	req, _ := encryptedRequest(t, http.MethodPut, "/users/1", scopeUsers, payload)

	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("X-Auth", signToken(t, users.Permissions{}, []byte(testSigningKey)))

	rec := httptest.NewRecorder()
	userRoute(userPutHandler, st).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "current password is incorrect") {
		t.Fatalf("body = %q, want the incorrect-current-password error", rec.Body.String())
	}
}

// Deleting an account re-authenticates with the current password.
func TestUserDeleteAcceptsEncryptedCredentials(t *testing.T) {
	st := credentialStorage(t)

	req, wire := encryptedRequest(t, http.MethodDelete, "/users/1", scopeUsers,
		`{"current_password":"`+testPassword+`"}`)

	if strings.Contains(wire, testPassword) {
		t.Fatalf("VULNERABLE: the password appeared in the request body: %s", wire)
	}

	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("X-Auth", signToken(t, users.Permissions{}, []byte(testSigningKey)))

	rec := httptest.NewRecorder()
	userRoute(userDeleteHandler, st).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("encrypted user delete status = %d, body=%q", rec.Code, rec.Body.String())
	}
	if _, err := st.Users.Get("", false, uint(1)); err == nil {
		t.Fatal("the user was not deleted")
	}
}

// The share password is a credential on its way to a public page that has no
// other protection at all, so it is encrypted too.
func TestSharePasswordHeaderIsAcceptedEncryptedAndPlain(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secretMarker), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash share password: %v", err)
	}
	link := &share.Link{PasswordHash: string(hash), Token: "share-token"}

	// Each envelope is single-use, so every call needs a fresh one.
	freshHeader := func(t *testing.T) string {
		t.Helper()
		header, err := sealedHeader(t, scopeShareUnlock, secretMarker)
		if err != nil {
			t.Fatalf("seal share password: %v", err)
		}
		return header
	}

	if leaked := freshHeader(t); strings.Contains(leaked, secretMarker) {
		t.Fatalf("VULNERABLE: the share password appeared in the header: %s", leaked)
	}

	shareRequest := func(password string) *http.Request {
		req, _ := http.NewRequest(http.MethodGet, "/api/public/share/hash", http.NoBody)
		if password != "" {
			req.Header.Set(sharePasswordHeader, password)
		}
		return req
	}

	t.Run("encrypted value is accepted", func(t *testing.T) {
		status, err := authenticateShareRequest(shareRequest(freshHeader(t)), link)
		if err != nil || status != 0 {
			t.Fatalf("status = %d, err = %v; want 0, nil", status, err)
		}
	})

	t.Run("literal value is still accepted", func(t *testing.T) {
		status, err := authenticateShareRequest(shareRequest(secretMarker), link)
		if err != nil || status != 0 {
			t.Fatalf("status = %d, err = %v; want 0, nil", status, err)
		}
	})

	t.Run("wrong encrypted value is rejected", func(t *testing.T) {
		wrong, err := sealedHeader(t, scopeShareUnlock, "not-the-share-password")
		if err != nil {
			t.Fatalf("seal share password: %v", err)
		}

		status, err := authenticateShareRequest(shareRequest(wrong), link)
		if err != nil || status != http.StatusUnauthorized {
			t.Fatalf("status = %d, err = %v; want 401, nil", status, err)
		}
	})

	t.Run("replayed encrypted value is rejected", func(t *testing.T) {
		header := freshHeader(t)

		if status, err := authenticateShareRequest(shareRequest(header), link); err != nil || status != 0 {
			t.Fatalf("first use: status = %d, err = %v", status, err)
		}

		status, _ := authenticateShareRequest(shareRequest(header), link)
		if status != http.StatusPreconditionRequired {
			t.Fatalf("VULNERABLE: replayed share password status = %d, want 428", status)
		}
	})

	t.Run("no password at all is unauthorised", func(t *testing.T) {
		status, err := authenticateShareRequest(shareRequest(""), link)
		if err != nil || status != http.StatusUnauthorized {
			t.Fatalf("status = %d, err = %v; want 401, nil", status, err)
		}
	})
}

// A client that sends a header it cannot have produced must be told so rather
// than be handed a 500.
func TestMalformedEncryptedHeaderIsRejected(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secretMarker), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("hash share password: %v", err)
	}
	link := &share.Link{PasswordHash: string(hash), Token: "share-token"}

	req, _ := http.NewRequest(http.MethodGet, "/api/public/share/hash", http.NoBody)
	req.Header.Set(sharePasswordHeader, encryptedValuePrefix+"not-json")

	status, err := authenticateShareRequest(req, link)
	if err == nil {
		t.Fatal("a malformed envelope was accepted")
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
}

// sealedHeader is the client half of the header form: it seals a scalar secret
// and prefixes it, mirroring encryptHeaderValue in @/utils/credcrypt.
func sealedHeader(t *testing.T, scope, value string) (string, error) {
	t.Helper()

	svc := credentialCrypto()
	challenge, err := svc.Challenge(scope)
	if err != nil {
		return "", err
	}

	env := sealEnvelope(t, svc, challenge, `{"value":`+quote(value)+`}`)
	raw, err := json.Marshal(env)
	if err != nil {
		return "", err
	}

	return encryptedValuePrefix + string(raw), nil
}
