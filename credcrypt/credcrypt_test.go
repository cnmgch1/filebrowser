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
	"strconv"
	"strings"
	"testing"
	"time"
)

// seal performs, in the test process, exactly what the browser does: it wraps a
// fresh AES-256-GCM key under the service's public key and seals the payload.
// Keeping it here rather than calling Service internals means the tests
// exercise the real wire format.
func seal(t *testing.T, svc *Service, challenge, payload string) Envelope {
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

	key := make([]byte, aesKeyBytes)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate payload key: %v", err)
	}
	iv := make([]byte, 12)
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

	// Built by hand rather than with json.Marshal, because some tests need to
	// seal a payload that is not valid JSON — Marshal would refuse it.
	plain := []byte(`{"challenge":` + strconv.Quote(challenge) + `,"payload":` + payload + `}`)

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, key, nil)
	if err != nil {
		t.Fatalf("wrap key: %v", err)
	}

	return Envelope{
		KeyID: svc.KeyID(),
		Key:   base64.StdEncoding.EncodeToString(wrapped),
		IV:    base64.StdEncoding.EncodeToString(iv),
		Data:  base64.StdEncoding.EncodeToString(gcm.Seal(nil, iv, plain, nil)),
	}
}

func newTestService(t *testing.T, ttl time.Duration) *Service {
	t.Helper()
	svc, err := New(ttl)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

func TestOpenRoundTrip(t *testing.T) {
	svc := newTestService(t, time.Minute)

	challenge, err := svc.Challenge("login")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	body := `{"username":"alice","password":"correct horse battery staple"}`
	got, err := svc.Open("login", seal(t, svc, challenge, body))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != body {
		t.Fatalf("payload = %s, want %s", got, body)
	}
}

// A passive attacker who captures an envelope must not be able to send it
// again: the challenge inside it is already spent.
func TestReplayIsRejected(t *testing.T) {
	svc := newTestService(t, time.Minute)

	challenge, err := svc.Challenge("login")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	env := seal(t, svc, challenge, `{"username":"alice","password":"hunter2"}`)

	if _, err := svc.Open("login", env); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	if _, err := svc.Open("login", env); !errors.Is(err, ErrChallenge) {
		t.Fatalf("replayed Open error = %v, want ErrChallenge", err)
	}
}

func TestScopeIsEnforced(t *testing.T) {
	svc := newTestService(t, time.Minute)

	challenge, err := svc.Challenge("login")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	env := seal(t, svc, challenge, `{"username":"alice","password":"hunter2"}`)

	if _, err := svc.Open("users", env); !errors.Is(err, ErrChallenge) {
		t.Fatalf("cross-scope Open error = %v, want ErrChallenge", err)
	}

	// The wrong-scope attempt must also have burned the challenge, so it cannot
	// be probed against every scope until one matches.
	if _, err := svc.Open("login", env); !errors.Is(err, ErrChallenge) {
		t.Fatalf("Open after cross-scope attempt error = %v, want ErrChallenge", err)
	}
}

func TestExpiredChallengeIsRejected(t *testing.T) {
	svc := newTestService(t, 30*time.Millisecond)

	challenge, err := svc.Challenge("login")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	env := seal(t, svc, challenge, `{"username":"alice","password":"hunter2"}`)

	time.Sleep(60 * time.Millisecond)

	if _, err := svc.Open("login", env); !errors.Is(err, ErrChallenge) {
		t.Fatalf("expired Open error = %v, want ErrChallenge", err)
	}
}

// A client that cached the public key across a restart holds a key the server
// no longer has. The KeyID check must catch it without attempting a decryption.
func TestStaleKeyIsReported(t *testing.T) {
	old := newTestService(t, time.Minute)
	current := newTestService(t, time.Minute)

	challenge, err := old.Challenge("login")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	env := seal(t, old, challenge, `{"username":"alice","password":"hunter2"}`)

	if _, err := current.Open("login", env); !errors.Is(err, ErrStaleKey) {
		t.Fatalf("stale-key Open error = %v, want ErrStaleKey", err)
	}
}

// Pasting the current KeyID onto an envelope wrapped with another key must not
// be accepted either.
func TestMismatchedWrappingKeyIsRejected(t *testing.T) {
	old := newTestService(t, time.Minute)
	current := newTestService(t, time.Minute)

	challenge, err := current.Challenge("login")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	env := seal(t, old, challenge, `{"username":"alice","password":"hunter2"}`)
	env.KeyID = current.KeyID()

	if _, err := current.Open("login", env); !errors.Is(err, ErrStaleKey) {
		t.Fatalf("mismatched-wrap Open error = %v, want ErrStaleKey", err)
	}
}

func TestTamperedCiphertextIsRejected(t *testing.T) {
	svc := newTestService(t, time.Minute)

	cases := map[string]func(*Envelope){
		"flip a ciphertext byte": func(e *Envelope) {
			raw, _ := base64.StdEncoding.DecodeString(e.Data)
			raw[len(raw)/2] ^= 0x01
			e.Data = base64.StdEncoding.EncodeToString(raw)
		},
		"replace the iv": func(e *Envelope) {
			iv := make([]byte, 12)
			if _, err := rand.Read(iv); err != nil {
				t.Fatalf("rand: %v", err)
			}
			e.IV = base64.StdEncoding.EncodeToString(iv)
		},
		"truncate the ciphertext": func(e *Envelope) {
			raw, _ := base64.StdEncoding.DecodeString(e.Data)
			e.Data = base64.StdEncoding.EncodeToString(raw[:len(raw)-1])
		},
		"not base64": func(e *Envelope) { e.Data = "!!!not base64!!!" },
		"empty":      func(e *Envelope) { e.Data = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			challenge, err := svc.Challenge("login")
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			env := seal(t, svc, challenge, `{"username":"alice","password":"hunter2"}`)
			mutate(&env)

			if _, err := svc.Open("login", env); err == nil {
				t.Fatal("Open accepted a tampered envelope")
			}
		})
	}
}

func TestMissingChallengeIsRejected(t *testing.T) {
	svc := newTestService(t, time.Minute)

	if _, err := svc.Open("login", seal(t, svc, "", `{"username":"alice","password":"hunter2"}`)); !errors.Is(err, ErrChallenge) {
		t.Fatalf("Open error = %v, want ErrChallenge", err)
	}
}

func TestUnknownChallengeIsRejected(t *testing.T) {
	svc := newTestService(t, time.Minute)

	env := seal(t, svc, base64.RawURLEncoding.EncodeToString([]byte("never issued by this server")), `{}`)
	if _, err := svc.Open("login", env); !errors.Is(err, ErrChallenge) {
		t.Fatalf("Open error = %v, want ErrChallenge", err)
	}
}

func TestPayloadMustBeValidJSON(t *testing.T) {
	svc := newTestService(t, time.Minute)

	cases := map[string]string{
		"empty":        ``,
		"not json":     `hello`,
		"broken brace": `{"a":`,
	}

	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			challenge, err := svc.Challenge("login")
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			if _, err := svc.Open("login", seal(t, svc, challenge, payload)); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Open error = %v, want ErrMalformed", err)
			}
		})
	}
}

// Empty objects and arrays are legitimate bodies (POST /api/share sends "{}"),
// so they must not be mistaken for a malformed payload.
func TestEmptyObjectPayloadIsAccepted(t *testing.T) {
	svc := newTestService(t, time.Minute)

	challenge, err := svc.Challenge("share")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	got, err := svc.Open("share", seal(t, svc, challenge, `{}`))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != "{}" {
		t.Fatalf("payload = %s, want {}", got)
	}
}

// The whole point: the password must not be recoverable from what is sent.
func TestEnvelopeDoesNotContainTheSecret(t *testing.T) {
	svc := newTestService(t, time.Minute)

	const secret = "hunter2-the-unique-marker"

	challenge, err := svc.Challenge("login")
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	env := seal(t, svc, challenge, `{"username":"alice","password":"`+secret+`"}`)

	wire, err := json.Marshal(map[string]Envelope{"encrypted": env})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	if strings.Contains(string(wire), secret) {
		t.Fatalf("secret leaked onto the wire: %s", wire)
	}
	if strings.Contains(string(wire), "password") {
		t.Fatalf("field name leaked onto the wire: %s", wire)
	}
}

func TestChallengesAreUnique(t *testing.T) {
	svc := newTestService(t, time.Minute)

	seen := make(map[string]bool)
	for range 512 {
		token, err := svc.Challenge("login")
		if err != nil {
			t.Fatalf("Challenge: %v", err)
		}
		if seen[token] {
			t.Fatalf("duplicate challenge token %q", token)
		}
		seen[token] = true
	}
}

func TestExpiredChallengesAreSwept(t *testing.T) {
	svc := newTestService(t, time.Minute)

	svc.mu.Lock()
	svc.challenges["stale"] = challenge{scope: "login", expires: time.Now().Add(-time.Hour)}
	svc.challenges["fresh"] = challenge{scope: "login", expires: time.Now().Add(time.Hour)}
	svc.sweepLocked(time.Now())
	_, staleStillThere := svc.challenges["stale"]
	_, freshStillThere := svc.challenges["fresh"]
	svc.mu.Unlock()

	if staleStillThere {
		t.Error("expired challenge was not swept")
	}
	if !freshStillThere {
		t.Error("live challenge was swept")
	}
}

func TestTTLDefaultsWhenNonPositive(t *testing.T) {
	svc := newTestService(t, 0)
	if svc.TTL() != DefaultChallengeTTL {
		t.Fatalf("TTL = %v, want %v", svc.TTL(), DefaultChallengeTTL)
	}
}
