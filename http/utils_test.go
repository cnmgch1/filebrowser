package fbhttp

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// cleanSeparators takes the host separator explicitly so the Windows behaviour
// can be asserted from any platform. See GHSA-fgm5-pw99-w2p7: on Windows a
// backslash is a path separator the filesystem resolves but the rule checker
// used to treat as an ordinary character, so "/allow\..\Secret.txt" evaded a
// rule for "/Secret.txt" and still opened it.
func TestCleanSeparators(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		sep  string
		want string
	}{
		// Windows: a backslash is a separator and must be resolved before the
		// path is matched against a rule.
		{"windows traversal", `/allow\..\Secret.txt`, `\`, "/Secret.txt"},
		{"windows leading backslash", `\Secret.txt`, `\`, "/Secret.txt"},
		{"windows mixed separators", `/a/b\..\..\c`, `\`, "/c"},
		{"windows already canonical", "/Secret.txt", `\`, "/Secret.txt"},
		{"windows relative", `allow\..\Secret.txt`, `\`, "/Secret.txt"},
		{"windows empty", "", `\`, "/"},

		// POSIX: a backslash is a legal filename character and must survive, or
		// files named with one become unreachable.
		{"posix backslash is a filename character", `/a\b.txt`, "/", `/a\b.txt`},
		{"posix traversal", "/allow/../Secret.txt", "/", "/Secret.txt"},
		{"posix relative", "Secret.txt", "/", "/Secret.txt"},
		{"posix multiple slashes", "//a///b", "/", "/a/b"},
		{"posix empty", "", "/", "/"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := cleanSeparators(tc.in, tc.sep); got != tc.want {
				t.Errorf("cleanSeparators(%q, %q) = %q; want %q", tc.in, tc.sep, got, tc.want)
			}
		})
	}
}

// A redirect issued by stripPrefix has to name the whole path the client asked
// for, not just the prefix the handler was stripped of.
//
// The two prefixes are nested exactly as they are in the router — the base URL
// first, then the route — which is where a Location built from the route prefix
// alone loses the base URL. That is invisible until the server sits behind a
// reverse proxy mounted under a path: the redirect then names a path the proxy
// does not route here, and the client never comes back.
func TestStripPrefixRedirectKeepsBaseURL(t *testing.T) {
	t.Parallel()

	reached := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	cases := []struct {
		name     string
		baseURL  string
		route    string
		path     string
		wantCode int
		wantLoc  string
	}{
		{"no base url", "", "/api/usage", "/api/usage", http.StatusMovedPermanently, "/api/usage/"},
		{"on the base url itself", "/213filebrowser", "/api/usage", "/213filebrowser", http.StatusMovedPermanently, "/213filebrowser/"},
		{"base url and route", "/213filebrowser", "/api/usage", "/213filebrowser/api/usage", http.StatusMovedPermanently, "/213filebrowser/api/usage/"},
		{"already has the slash", "/213filebrowser", "/api/usage", "/213filebrowser/api/usage/", http.StatusOK, ""},
		{"unrelated path", "/213filebrowser", "/api/usage", "/213filebrowser/api/usage/dir", http.StatusOK, ""},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := stripPrefix(tc.baseURL, stripPrefix(tc.route, reached))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, http.NoBody))

			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d; want %d", rec.Code, tc.wantCode)
			}
			if got := rec.Header().Get("Location"); got != tc.wantLoc {
				t.Errorf("Location = %q; want %q", got, tc.wantLoc)
			}
		})
	}
}
