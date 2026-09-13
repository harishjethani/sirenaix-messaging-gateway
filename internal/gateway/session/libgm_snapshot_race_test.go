package session_test

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"go.mau.fi/mautrix-gmessages/internal/gateway/provider/gmessages"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

// This test intentionally lives under the session package so the documented
// session race command exercises libgm's cookie lock and the gateway codec
// together.
func TestConcurrentLibGMCookieRotationAndSessionSnapshot(t *testing.T) {
	auth := libgm.NewAuthData()
	auth.SetCookies(raceTestCookies("initial"))
	auth.SetDevices(&gmproto.Device{SourceID: "browser"}, &gmproto.Device{SourceID: "mobile"})
	auth.SetTachyonAuth([]byte("token"), time.Now().Add(time.Hour), int64(time.Hour))
	auth.SetSessionIdentifiers(uuid.New(), uuid.New(), uuid.New())
	var wait sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wait.Add(2)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 250; iteration++ {
				auth.SetCookies(raceTestCookies(string(rune('a' + worker))))
			}
		}(worker)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 250; iteration++ {
				if _, err := gmessages.EncodeSession(auth, nil); err != nil {
					t.Errorf("EncodeSession: %v", err)
					return
				}
			}
		}()
	}
	wait.Wait()
}

func raceTestCookies(sid string) map[string]string {
	return map[string]string{"SID": sid, "HSID": "2", "OSID": "3", "SSID": "4", "APISID": "5", "SAPISID": "6", "__Secure-1PSIDTS": "7"}
}
