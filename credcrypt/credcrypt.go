// Package credcrypt protects credentials that would otherwise travel in
// cleartext over a plain HTTP connection.
//
// # Threat model
//
// A passive network attacker who can read request bodies — a shared Wi-Fi
// segment, a mirroring switch port, a logging reverse proxy a few hops away —
// can otherwise lift a username and password straight out of a login POST.
//
// # Scheme
//
// The client asks for a handshake, generates a random AES-256-GCM key,
// encrypts the request payload with it, and wraps that key with RSA-OAEP
// (SHA-256) under the server's ephemeral public key. Only the holder of the
// matching private key — the server itself — can recover the payload, so the
// password is never observable on the wire.
//
// Ciphertext alone would however be replayable verbatim by that same passive
// attacker, so a handshake also yields a single-use challenge, and the client
// puts it inside the encrypted payload. The server accepts a challenge exactly
// once, only for the scope it was issued for, and only until it expires. A
// captured envelope is therefore worthless afterwards.
//
// # Scope
//
// A "scope" is the operation a challenge was issued for (login, signup, users,
// share, share-unlock). It stops an envelope captured from one endpoint from
// being replayed against another, and is checked after decryption so that a
// mismatch is not distinguishable from any other failure by a passive
// observer.
//
// # Limitations
//
// This protects the credentials in a request body. It is NOT a substitute for
// TLS: the session token the server returns afterwards, and every other byte
// of the response, still travel in the clear. Deploy behind HTTPS where
// possible; this is a mitigation for the cases where that is not an option.
package credcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Algorithm is the identifier reported to the client. It names the key-wrapping
// algorithm; the payload cipher (AES-256-GCM) is implied by the envelope shape.
const Algorithm = "RSA-OAEP-256"

// DefaultChallengeTTL is how long a handshake challenge stays usable. It only
// has to cover the round trip between the handshake and the request it belongs
// to, so it is deliberately short.
const DefaultChallengeTTL = 2 * time.Minute

const (
	// rsaKeyBits is the modulus size of the ephemeral key pair.
	rsaKeyBits = 2048
	// aesKeyBytes is the size of the generated payload key: AES-256.
	aesKeyBytes = 32
	// challengeBytes is the entropy of a challenge token. It only needs to be
	// unguessable within the TTL, but guessing it is not even the main defence
	// — a challenge is consumed on first use.
	challengeBytes = 24
	// maxChallenges caps the challenge table. Reaching it means either a flood
	// of handshakes or a client that never finishes logging in; both are
	// handled by pruning expired entries and then refusing new ones, so the
	// table cannot be used to exhaust memory.
	maxChallenges = 1 << 14
)

// Errors returned by Open. Callers map them onto responses; the distinction
// that matters is whether retrying with a fresh handshake could succeed.
var (
	// ErrStaleKey means the envelope was encrypted to a public key this server
	// no longer holds — typically a cached key from before a restart. A fresh
	// handshake fixes it.
	ErrStaleKey = errors.New("credcrypt: envelope was encrypted to a stale public key")

	// ErrChallenge means the challenge was unknown, already used, expired, or
	// issued for a different scope. A fresh handshake is required.
	ErrChallenge = errors.New("credcrypt: challenge is missing, expired or already used")

	// ErrMalformed means the envelope is not well formed, its authentication
	// tag does not verify, or its payload cannot be parsed. No amount of
	// retrying helps.
	ErrMalformed = errors.New("credcrypt: malformed envelope")

	// ErrExhausted is returned when the challenge table is full of live
	// challenges and no new one can be issued.
	ErrExhausted = errors.New("credcrypt: too many pending handshakes")
)

// Envelope is the encrypted replacement for a request body, as it appears on
// the wire:
//
//	{"encrypted": {"kid": "...", "k": "...", "iv": "...", "d": "..."}}
//
// All four fields are standard base64. KeyID lets the server reject a stale key
// before doing any asymmetric work; Key and IV are the RSA-wrapped AES key and
// the GCM nonce; Data is the sealed payload.
type Envelope struct {
	KeyID string `json:"kid"`
	Key   string `json:"k"`
	IV    string `json:"iv"`
	Data  string `json:"d"`
}

// encryptedPayload is the plaintext of an envelope, before it is encrypted. The
// application body is kept as raw JSON so that the server can hand it to the
// existing handlers unmodified, without knowing its schema.
type encryptedPayload struct {
	Challenge string          `json:"challenge"`
	Payload   json.RawMessage `json:"payload"`
}

type challenge struct {
	scope   string
	expires time.Time
}

// Service holds the ephemeral key pair and the outstanding challenges.
type Service struct {
	priv   *rsa.PrivateKey
	pubDER string // standard base64 of the SPKI encoding
	keyID  string // short fingerprint of pubDER

	ttl time.Duration

	mu         sync.Mutex
	challenges map[string]challenge
}

// New generates a key pair and returns a ready Service.
//
// The key pair lives only in memory: it is created at startup and replaced on
// every restart. That keeps the private key off disk entirely, and the cost is
// only that a client holding a cached public key has to redo the handshake
// after a restart — which the KeyID check makes cheap and explicit.
func New(ttl time.Duration) (*Service, error) {
	if ttl <= 0 {
		ttl = DefaultChallengeTTL
	}

	priv, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return nil, fmt.Errorf("credcrypt: generate key: %w", err)
	}

	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("credcrypt: marshal public key: %w", err)
	}

	sum := sha256.Sum256(der)

	return &Service{
		priv:       priv,
		pubDER:     base64.StdEncoding.EncodeToString(der),
		keyID:      base64.RawURLEncoding.EncodeToString(sum[:9]),
		ttl:        ttl,
		challenges: make(map[string]challenge),
	}, nil
}

// TTL reports how long a freshly issued challenge remains valid.
func (s *Service) TTL() time.Duration { return s.ttl }

// KeyID is the short, non-secret identifier of the current public key. Clients
// echo it back in an envelope so the server can detect a stale key without
// attempting a decryption that is bound to fail.
func (s *Service) KeyID() string { return s.keyID }

// PublicKey returns the base64 SPKI encoding of the public key, as accepted by
// WebCrypto's importKey("spki", ...) and by node-forge's
// pki.publicKeyFromAsn1 after a DER decode.
func (s *Service) PublicKey() string { return s.pubDER }

// Challenge issues a single-use token for the given scope.
func (s *Service) Challenge(scope string) (string, error) {
	buf := make([]byte, challengeBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("credcrypt: generate challenge: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(buf)

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.challenges) >= maxChallenges {
		s.sweepLocked(now)
	}
	if len(s.challenges) >= maxChallenges {
		return "", ErrExhausted
	}

	s.challenges[token] = challenge{scope: scope, expires: now.Add(s.ttl)}
	return token, nil
}

// Open validates an envelope and returns the application body it carries.
//
// The returned bytes are the value of the envelope's "payload" property, ready
// to be used as a request body. Order matters here: the challenge is only
// consumed once the payload is known to be authentic, so a forged envelope
// cannot burn someone else's challenge.
func (s *Service) Open(scope string, env Envelope) (json.RawMessage, error) {
	if env.KeyID != s.keyID {
		return nil, ErrStaleKey
	}

	wrapped, err := base64.StdEncoding.DecodeString(env.Key)
	if err != nil {
		return nil, ErrMalformed
	}
	iv, err := base64.StdEncoding.DecodeString(env.IV)
	if err != nil {
		return nil, ErrMalformed
	}
	sealed, err := base64.StdEncoding.DecodeString(env.Data)
	if err != nil {
		return nil, ErrMalformed
	}

	key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.priv, wrapped, nil)
	if err != nil {
		// The envelope named the current key but was not wrapped with it:
		// either it was tampered with or the client and server disagree about
		// the key. Both are answered by redoing the handshake.
		return nil, ErrStaleKey
	}
	if len(key) != aesKeyBytes {
		return nil, ErrMalformed
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrMalformed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrMalformed
	}
	if len(iv) != gcm.NonceSize() {
		return nil, ErrMalformed
	}

	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		// Authentication failed: wrong key, truncated, or modified ciphertext.
		return nil, ErrMalformed
	}

	var inner encryptedPayload
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, ErrMalformed
	}
	if len(inner.Payload) == 0 || !json.Valid(inner.Payload) {
		return nil, ErrMalformed
	}

	if !s.consume(inner.Challenge, scope) {
		return nil, ErrChallenge
	}

	return inner.Payload, nil
}

// consume redeems a challenge: it succeeds only if the token is outstanding,
// unexpired, and was issued for this scope, and it never succeeds twice.
func (s *Service) consume(token, scope string) bool {
	if token == "" {
		return false
	}

	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	ch, ok := s.challenges[token]
	if !ok {
		return false
	}
	// Delete unconditionally, so a wrong scope or an expired token still burns
	// it and cannot be probed repeatedly.
	delete(s.challenges, token)

	if ch.scope != scope || now.After(ch.expires) {
		return false
	}

	return true
}

// sweepLocked drops expired challenges. It must be called with s.mu held.
func (s *Service) sweepLocked(now time.Time) {
	for token, ch := range s.challenges {
		if now.After(ch.expires) {
			delete(s.challenges, token)
		}
	}
}

// Pending reports how many challenges are outstanding. It exists for tests and
// diagnostics.
func (s *Service) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.challenges)
}
