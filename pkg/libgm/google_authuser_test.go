package libgm

import (
	"net/http"
	"testing"
)

// A browser signed into several Google accounts serves Messages at /u/N; Google
// rejects cookie-authenticated requests for account N unless X-Goog-AuthUser names it.
func TestAddCookiesToRequestSetsGoogleAuthUserOnlyForNonDefaultAccount(t *testing.T) {
	for _, test := range []struct {
		index int
		want  string
	}{{index: 0, want: ""}, {index: 1, want: "1"}, {index: 9, want: "9"}} {
		auth := NewAuthData()
		auth.SetCookies(map[string]string{"SAPISID": "sapisid-value", "SID": "sid-value"})
		auth.SetGoogleAuthUser(test.index)
		request, err := http.NewRequest(http.MethodPost, "https://instantmessaging-pa.googleapis.com/", nil)
		if err != nil {
			t.Fatal(err)
		}
		auth.AddCookiesToRequest(request)
		if got := request.Header.Get("X-Goog-AuthUser"); got != test.want {
			t.Fatalf("index %d: X-Goog-AuthUser = %q, want %q", test.index, got, test.want)
		}
		if request.Header.Get("Authorization") == "" || len(request.Cookies()) != 2 {
			t.Fatalf("index %d: cookie authentication was not applied", test.index)
		}
		snapshot := auth.Snapshot()
		if snapshot.GoogleAuthUser != test.index {
			t.Fatalf("index %d: snapshot GoogleAuthUser = %d", test.index, snapshot.GoogleAuthUser)
		}
		snapshot.ClearSecrets()
		if snapshot.GoogleAuthUser != 0 {
			t.Fatalf("index %d: ClearSecrets left GoogleAuthUser = %d", test.index, snapshot.GoogleAuthUser)
		}
	}
}

func TestAddCookiesToRequestOmitsGoogleAuthUserWithoutCookies(t *testing.T) {
	auth := NewAuthData()
	auth.SetGoogleAuthUser(1)
	request, err := http.NewRequest(http.MethodGet, "https://instantmessaging-pa.googleapis.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.AddCookiesToRequest(request)
	if got := request.Header.Get("X-Goog-AuthUser"); got != "" {
		t.Fatalf("X-Goog-AuthUser without cookies = %q", got)
	}
}
