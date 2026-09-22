package fbhttp

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/filebrowser/filebrowser/v2/credcrypt"
)

// Scopes name the operations that accept an encrypted body. A challenge is
// issued for exactly one of them and is refused anywhere else, so an envelope
// captured from one endpoint cannot be replayed against another.
const (
	scopeLogin       = "login"
	scopeSignup      = "signup"
	scopeUsers       = "users"
	scopeShare       = "share"
	scopeShareUnlock = "share-unlock"
)

var credentialScopes = []string{
	scopeLogin,
	scopeSignup,
	scopeUsers,
	scopeShare,
	scopeShareUnlock,
}

// credentialCrypto is the process-wide credential service. It is built on first
// use rather than at init time, so binaries that never serve HTTP — the CLI, for
// instance — do not pay for a key generation they will never need.
//
// The key pair is deliberately ephemeral: it exists only in memory and is
// replaced on every restart, so the private key never reaches the disk. The cost
// is that a client holding a cached public key must redo the handshake after a
// restart, which the KeyID check in the envelope makes explicit and cheap.
var credentialCrypto = sync.OnceValue(func() *credcrypt.Service {
	svc, err := credcrypt.New(credcrypt.DefaultChallengeTTL)
	if err != nil {
		// RSA key generation only fails when the system CSPRNG is broken, in
		// which case no part of this process can protect anything anyway.
		panic(fmt.Sprintf("fbhttp: cannot initialise credential encryption: %v", err))
	}
	return svc
})

// encryptedBody is the outer shape a client uses in place of a plaintext body:
//
//	{"encrypted": {"kid": "...", "k": "...", "iv": "...", "d": "..."}}
type encryptedBody struct {
	Encrypted *credcrypt.Envelope `json:"encrypted"`
}

type handshakeRequest struct {
	Scope string `json:"scope"`
}

type handshakeResponse struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"keyID"`
	Key       string `json:"key"`
	Challenge string `json:"challenge"`
	ExpiresIn int    `json:"expiresIn"`
}

// cryptoHandshakeHandler issues the material a client needs to encrypt one
// request: the server's public key and a single-use challenge for the scope the
// client is about to exercise.
//
// This route is unauthenticated by necessity — it is what a client calls before
// it can log in. It leaks nothing: the public key is public, and a challenge is
// worthless without a password to put inside it.
func cryptoHandshakeHandler() handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		var req handshakeRequest

		if r.Body != nil {
			raw, err := io.ReadAll(io.LimitReader(r.Body, 4<<10))
			if err != nil {
				return http.StatusBadRequest, err
			}
			_ = r.Body.Close()

			if err := json.Unmarshal(raw, &req); err != nil {
				return http.StatusBadRequest, err
			}
		}

		if !slices.Contains(credentialScopes, req.Scope) {
			return http.StatusBadRequest, fmt.Errorf("unknown credential scope %q", req.Scope)
		}

		svc := credentialCrypto()

		challenge, err := svc.Challenge(req.Scope)
		if err != nil {
			return errToStatus(err), err
		}

		// A handshake is single-use and must never be served from a cache.
		w.Header().Set("Cache-Control", "no-store")

		return renderJSON(w, r, handshakeResponse{
			Algorithm: credcrypt.Algorithm,
			KeyID:     svc.KeyID(),
			Key:       svc.PublicKey(),
			Challenge: challenge,
			ExpiresIn: int(svc.TTL().Seconds()),
		})
	}
}

// withEncryptedCredentials lets a client replace a password-bearing request body
// with an encrypted envelope, and unwraps it before the handler runs.
//
// Bodies that arrive in the clear are handed through untouched. That is not a
// downgrade an attacker can exploit: the choice is made by the client, and a
// passive eavesdropper cannot rewrite the request. It is what keeps the CLI, the
// documented HTTP API and third-party clients working.
//
// Endpoints that take no password are unaffected either way, since an unwrapped
// body is passed through unchanged.
func withEncryptedCredentials(scope string, fn handleFunc) handleFunc {
	return func(w http.ResponseWriter, r *http.Request, d *data) (int, error) {
		if r.Body == nil || r.Body == http.NoBody {
			return fn(w, r, d)
		}

		// The envelope is larger than the plaintext it carries, so the limit has
		// to be applied to what arrives rather than to what comes out.
		r.Body = http.MaxBytesReader(w, r.Body, maxAuthBodySize)

		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return http.StatusBadRequest, err
		}
		_ = r.Body.Close()

		// Always hand the handler a readable body, whichever branch is taken.
		r.Body = io.NopCloser(bytes.NewReader(raw))
		r.ContentLength = int64(len(raw))

		var probe encryptedBody
		if err := json.Unmarshal(raw, &probe); err != nil || probe.Encrypted == nil {
			return fn(w, r, d)
		}

		payload, err := credentialCrypto().Open(scope, *probe.Encrypted)
		if err != nil {
			return credentialStatus(err), err
		}

		// A login carries the session key it wants its token encrypted under.
		// Every other operation simply does not, and gets nothing.
		if key := sessionKeyFromPayload(payload); key != nil {
			d.sessionKey = key
		}

		r.Body = io.NopCloser(bytes.NewReader(payload))
		r.ContentLength = int64(len(payload))

		return fn(w, r, d)
	}
}

// credentialStatus maps an envelope failure onto a response code.
//
// A stale key or a spent challenge is recoverable — the client simply has to ask
// for a fresh handshake — so it gets 428 rather than a 4xx that a client would
// treat as "your password is wrong" and give up on.
func credentialStatus(err error) int {
	switch {
	case errors.Is(err, credcrypt.ErrStaleKey), errors.Is(err, credcrypt.ErrChallenge):
		return http.StatusPreconditionRequired
	case errors.Is(err, credcrypt.ErrExhausted):
		return http.StatusServiceUnavailable
	default:
		return http.StatusBadRequest
	}
}

// encryptedValuePrefix marks a header value that carries an encrypted envelope
// instead of a literal secret. Base64 cannot contain ':', so the two forms
// cannot be confused.
const encryptedValuePrefix = "enc:"

// encryptableValue wraps a scalar secret, so that it can travel inside an
// envelope whose payload is always a JSON object.
type encryptableValue struct {
	Value string `json:"value"`
}

// openValue decrypts a prefixed header value and returns the secret it carries.
// ok is false when the value is not an envelope, in which case the caller is
// holding a literal secret.
func openValue(scope, raw string) (value string, ok bool, err error) {
	encoded, isEnvelope := strings.CutPrefix(raw, encryptedValuePrefix)
	if !isEnvelope {
		return "", false, nil
	}

	var env credcrypt.Envelope
	if err := json.Unmarshal([]byte(encoded), &env); err != nil {
		return "", true, err
	}

	payload, err := credentialCrypto().Open(scope, env)
	if err != nil {
		return "", true, err
	}

	var wrapped encryptableValue
	if err := json.Unmarshal(payload, &wrapped); err != nil {
		return "", true, err
	}

	return wrapped.Value, true, nil
}
