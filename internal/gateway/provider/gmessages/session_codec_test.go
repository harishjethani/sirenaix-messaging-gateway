package gmessages

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	gatewaysession "go.mau.fi/mautrix-gmessages/internal/gateway/session"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	libgmcrypto "go.mau.fi/mautrix-gmessages/pkg/libgm/crypto"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

func TestSessionCodecRoundTripRestoresIndependentSessionMaterial(t *testing.T) {
	auth := libgm.NewAuthData()
	auth.SetCookies(validCookieSet())
	auth.Browser = &gmproto.Device{SourceID: "browser-id"}
	auth.Mobile = &gmproto.Device{SourceID: "phone-id"}
	auth.TachyonAuthToken = []byte("tachyon-token")
	auth.TachyonExpiry = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	auth.TachyonTTL = int64(time.Hour)
	auth.WebEncryptionKey = []byte("web-key")
	auth.SessionID = uuid.MustParse("11111111-1111-1111-1111-111111111111")
	auth.DestRegID = uuid.MustParse("22222222-2222-2222-2222-222222222222")
	auth.PairingID = uuid.MustParse("33333333-3333-3333-3333-333333333333")
	push := &libgm.PushKeys{URL: "https://push.invalid/id", P256DH: make([]byte, 65), Auth: make([]byte, 16)}

	encoded, err := EncodeSession(auth, push)
	if err != nil {
		t.Fatalf("EncodeSession: %v", err)
	}
	restoredAuth, restoredPush, err := DecodeSession(encoded)
	if err != nil {
		t.Fatalf("DecodeSession: %v", err)
	}
	if restoredAuth.Browser.GetSourceID() != "browser-id" || restoredAuth.Mobile.GetSourceID() != "phone-id" ||
		!bytes.Equal(restoredAuth.TachyonAuthToken, auth.TachyonAuthToken) || restoredAuth.SessionID != auth.SessionID ||
		restoredAuth.DestRegID != auth.DestRegID || restoredAuth.PairingID != auth.PairingID || restoredPush.URL != push.URL {
		t.Fatalf("restored session lost material: auth=%#v push=%#v", restoredAuth, restoredPush)
	}

	auth.SetCookies(map[string]string{"SID": "mutated"})
	auth.RequestCrypto.AESKey[0] ^= 1
	push.Auth[0] ^= 1
	if got := restoredAuth.CookieSnapshot()["SID"]; got != "one" {
		t.Fatalf("restored cookie aliased original: %q", got)
	}
	if bytes.Equal(restoredAuth.RequestCrypto.AESKey, auth.RequestCrypto.AESKey) || bytes.Equal(restoredPush.Auth, push.Auth) {
		t.Fatal("restored key material aliases original")
	}
}

func TestRotatedExtraCookieSurvivesEncryptedVaultRestart(t *testing.T) {
	auth := validSessionAuth()
	auth.UpdateCookiesFromResponse(&http.Response{Header: http.Header{
		"Set-Cookie": {"__Secure-provider-rotation=bounded-extra; Path=/; Secure; HttpOnly"},
	}})
	encoded, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatalf("EncodeSession after Set-Cookie rotation: %v", err)
	}
	manager, err := gatewaysession.NewManager(codecTestWrapper{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	store := &codecEnvelopeStore{}
	vault, err := gatewaysession.NewVault(manager, store)
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	scope := gatewaysession.Scope{TenantID: "tenant-a", ConnectionID: "connection-1", Provider: "gmessages"}
	if err = vault.Save(context.Background(), scope, encoded); err != nil {
		t.Fatalf("encrypted Save: %v", err)
	}
	restarted, _ := gatewaysession.NewVault(manager, store)
	restoredJSON, err := restarted.Load(context.Background(), scope)
	if err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	restored, _, err := DecodeSession(restoredJSON)
	if err != nil {
		t.Fatalf("DecodeSession after restart: %v", err)
	}
	if got := restored.CookieSnapshot()["__Secure-provider-rotation"]; got != "bounded-extra" {
		t.Fatalf("rotated extra cookie = %q", got)
	}
}

func TestFinishedSessionRejectsMalformedOrOversizedExtraCookiesSafely(t *testing.T) {
	const sentinel = "extra-cookie-secret-sentinel"
	tests := []struct {
		name    string
		cookies func() map[string]string
	}{
		{name: "too many", cookies: func() map[string]string {
			cookies := validCookieSet()
			for i := 0; i < 59; i++ {
				cookies["extra-"+strconv.Itoa(i)] = "value"
			}
			return cookies
		}},
		{name: "oversized name", cookies: func() map[string]string {
			cookies := validCookieSet()
			cookies[strings.Repeat("n", 257)] = sentinel
			return cookies
		}},
		{name: "control in name", cookies: func() map[string]string {
			cookies := validCookieSet()
			cookies["bad\nname"] = sentinel
			return cookies
		}},
		{name: "oversized value", cookies: func() map[string]string {
			cookies := validCookieSet()
			cookies["EXTRA"] = strings.Repeat("v", maxSessionFieldSize+1)
			return cookies
		}},
		{name: "control in value", cookies: func() map[string]string {
			cookies := validCookieSet()
			cookies["EXTRA"] = sentinel + "\x00"
			return cookies
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := validSessionAuth()
			auth.SetCookies(test.cookies())
			_, err := EncodeSession(auth, nil)
			if !errors.Is(err, ErrInvalidSessionData) {
				t.Fatalf("EncodeSession = %v", err)
			}
			if strings.Contains(err.Error(), sentinel) {
				t.Fatalf("error exposed cookie material: %v", err)
			}
		})
	}
}

func TestFinishedSessionCookieValuesUseRFC6265CookieOctets(t *testing.T) {
	forbidden := []struct {
		name  string
		value string
	}{
		{name: "space", value: "secret value"},
		{name: "tab", value: "secret\tvalue"},
		{name: "nul", value: "secret\x00value"},
		{name: "delete", value: "secret\x7fvalue"},
		{name: "dquote", value: `secret"value`},
		{name: "comma", value: "secret,value"},
		{name: "semicolon", value: "secret;value"},
		{name: "backslash", value: `secret\value`},
	}
	for _, test := range forbidden {
		t.Run("reject_"+test.name, func(t *testing.T) {
			auth := validSessionAuth()
			cookies := auth.CookieSnapshot()
			cookies["ROTATED"] = test.value
			auth.SetCookies(cookies)
			_, err := EncodeSession(auth, nil)
			if !errors.Is(err, ErrInvalidSessionData) {
				t.Fatalf("EncodeSession accepted forbidden cookie value %q", test.name)
			}
			if strings.Contains(err.Error(), test.value) {
				t.Fatalf("error exposed rejected cookie value: %v", err)
			}
		})
	}

	accepted := []string{
		"!#$%&'()*+-./0123456789:<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{|}~",
		"AbC012+/=_-",
	}
	for index, value := range accepted {
		t.Run("accept_"+strconv.Itoa(index), func(t *testing.T) {
			auth := validSessionAuth()
			cookies := auth.CookieSnapshot()
			cookies["ROTATED"] = value
			auth.SetCookies(cookies)
			if _, err := EncodeSession(auth, nil); err != nil {
				t.Fatalf("EncodeSession rejected RFC 6265 cookie-octets: %v", err)
			}
		})
	}
}

func TestSessionCodecRejectsStructurallyUnusableMaterial(t *testing.T) {
	valid := libgm.NewAuthData()
	valid.SetCookies(validCookieSet())
	valid.SetDevices(&gmproto.Device{SourceID: "browser-id"}, &gmproto.Device{SourceID: "mobile-id"})
	valid.SetTachyonAuth([]byte("token"), time.Now().Add(time.Hour), int64(time.Hour))
	valid.SetSessionIdentifiers(uuid.New(), uuid.New(), uuid.New())
	validPush := &libgm.PushKeys{URL: "https://push.invalid/id", P256DH: make([]byte, 65), Auth: make([]byte, 16)}
	tests := []struct {
		name   string
		mutate func(*libgm.AuthData, *libgm.PushKeys)
	}{
		{name: "short AES key", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.RequestCrypto.AESKey = make([]byte, 31) }},
		{name: "short HMAC key", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.RequestCrypto.HMACKey = make([]byte, 31) }},
		{name: "invalid EC public key", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) {
			auth.RefreshKey.X = []byte{1}
			auth.RefreshKey.Y = []byte{1}
		}},
		{name: "missing browser ID", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.Browser.SourceID = "" }},
		{name: "missing mobile ID", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.Mobile.SourceID = "" }},
		{name: "missing token", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.TachyonAuthToken = nil }},
		{name: "missing registration ID", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.DestRegID = uuid.Nil }},
		{name: "missing cookies", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.Cookies = nil }},
		{name: "negative google account index", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.GoogleAuthUser = -1 }},
		{name: "google account index out of range", mutate: func(auth *libgm.AuthData, _ *libgm.PushKeys) { auth.GoogleAuthUser = 10 }},
		{name: "short push public key", mutate: func(_ *libgm.AuthData, push *libgm.PushKeys) { push.P256DH = make([]byte, 64) }},
		{name: "short push auth", mutate: func(_ *libgm.AuthData, push *libgm.PushKeys) { push.Auth = make([]byte, 15) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			auth := valid.Snapshot()
			push := clonePushKeys(validPush)
			test.mutate(auth, push)
			encoded, err := json.Marshal(sessionWire{Version: sessionCodecVersion, Auth: auth, Push: push})
			auth.ClearSecrets()
			clearPushKeys(push)
			if err != nil {
				t.Fatalf("Marshal fixture: %v", err)
			}
			if _, _, err := DecodeSession(encoded); !errors.Is(err, ErrInvalidSessionData) {
				t.Fatalf("DecodeSession = %v", err)
			}
		})
	}
	if _, _, err := DecodeSession(make([]byte, 4*1024*1024+1)); !errors.Is(err, ErrInvalidSessionData) {
		t.Fatalf("oversized DecodeSession = %v", err)
	}
}

func TestSessionSnapshotIsRaceSafeDuringCookieRotation(t *testing.T) {
	auth := validSessionAuth()
	var wait sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			for iteration := 0; iteration < 250; iteration++ {
				cookies := validCookieSet()
				cookies["SID"] = string(rune('a' + worker))
				auth.SetCookies(cookies)
			}
		}(worker)
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 250; iteration++ {
				if _, err := EncodeSession(auth, nil); err != nil {
					t.Errorf("EncodeSession: %v", err)
					return
				}
			}
		}()
	}
	wait.Wait()
}

func TestSessionSnapshotSynchronizesEveryMutableMaterialClass(t *testing.T) {
	auth := libgm.NewAuthData()
	client := libgm.NewClient(auth, &libgm.PushKeys{URL: "https://push.invalid/a", P256DH: make([]byte, 65), Auth: make([]byte, 16)}, zerolog.Nop())
	refreshKeys := []*libgmcrypto.JWK{libgmcrypto.GenerateECDSAKey(), libgmcrypto.GenerateECDSAKey()}
	var wait sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		worker := worker
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 200; iteration++ {
				auth.SetCookies(validCookieSet())
				auth.SetDevices(&gmproto.Device{SourceID: "browser"}, &gmproto.Device{SourceID: "mobile"})
				auth.SetTachyonAuth([]byte{byte(worker + 1)}, time.Now().Add(time.Hour), int64(time.Hour))
				auth.SetRequestCryptoKeys(bytes.Repeat([]byte{byte(worker + 1)}, 32), bytes.Repeat([]byte{byte(worker + 2)}, 32))
				auth.SetRefreshKey(refreshKeys[worker%len(refreshKeys)])
				auth.SetSessionIdentifiers(uuid.New(), uuid.New(), uuid.New())
				auth.SetWebEncryptionKey([]byte{byte(worker + 3)})
				client.SetPushKeys(&libgm.PushKeys{URL: "https://push.invalid/b", P256DH: make([]byte, 65), Auth: make([]byte, 16)})
			}
		}()
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 200; iteration++ {
				snapshot, push := client.SnapshotSession()
				if snapshot == nil {
					t.Error("nil snapshot")
					return
				}
				snapshot.ClearSecrets()
				clearPushKeys(push)
			}
		}()
	}
	wait.Wait()
}

func validCookieSet() map[string]string {
	return map[string]string{"SID": "one", "HSID": "two", "OSID": "three", "SSID": "four", "APISID": "five", "SAPISID": "six", "__Secure-1PSIDTS": "seven"}
}

func TestSessionCodecPersistsGoogleAuthUserAndDefaultsLegacySessions(t *testing.T) {
	auth := validSessionAuth()
	auth.SetGoogleAuthUser(1)
	encoded, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatalf("EncodeSession: %v", err)
	}
	restored, _, err := DecodeSession(encoded)
	if err != nil || restored.GoogleAuthUser != 1 {
		t.Fatalf("DecodeSession GoogleAuthUser = %v, err = %v", restored, err)
	}
	legacy := validSessionAuth()
	legacyEncoded, err := EncodeSession(legacy, nil)
	if err != nil {
		t.Fatalf("EncodeSession legacy: %v", err)
	}
	if bytes.Contains(legacyEncoded, []byte("google_authuser")) {
		t.Fatal("default account index changed the persisted session encoding")
	}
	restoredLegacy, _, err := DecodeSession(legacyEncoded)
	if err != nil || restoredLegacy.GoogleAuthUser != 0 {
		t.Fatalf("legacy DecodeSession GoogleAuthUser = %v, err = %v", restoredLegacy, err)
	}
}

func validSessionAuth() *libgm.AuthData {
	auth := libgm.NewAuthData()
	auth.SetCookies(validCookieSet())
	auth.SetDevices(&gmproto.Device{SourceID: "browser-id"}, &gmproto.Device{SourceID: "mobile-id"})
	auth.SetTachyonAuth([]byte("token"), time.Now().Add(time.Hour), int64(time.Hour))
	auth.SetSessionIdentifiers(uuid.New(), uuid.New(), uuid.New())
	return auth
}

func TestDecodeSessionRejectsMalformedDataWithoutEchoingIt(t *testing.T) {
	secret := []byte("not-json-private-cookie-value")
	_, _, err := DecodeSession(secret)
	if err == nil || bytes.Contains([]byte(err.Error()), secret) {
		t.Fatalf("DecodeSession error = %v", err)
	}
}

func TestCookieValidationRequiresExactNonEmptySet(t *testing.T) {
	valid := map[string]string{
		"SID": "one", "HSID": "two", "OSID": "three", "SSID": "four", "APISID": "five", "SAPISID": "six", "__Secure-1PSIDTS": "seven",
	}
	if err := ValidateCookies(valid); err != nil {
		t.Fatalf("ValidateCookies(valid): %v", err)
	}
	tests := []map[string]string{
		{"SID": "one"},
		{"SID": "one", "HSID": "two", "OSID": "three", "SSID": "four", "APISID": "five", "SAPISID": "", "__Secure-1PSIDTS": "seven"},
		// Google rejects SignInGaia without the rotating __Secure-1PSIDTS cookie.
		{"SID": "one", "HSID": "two", "OSID": "three", "SSID": "four", "APISID": "five", "SAPISID": "six"},
		{"SID": "one", "HSID": "two", "OSID": "three", "SSID": "four", "APISID": "five", "SAPISID": "six", "__Secure-1PSIDTS": "seven", "ACCOUNT": "ambiguous-secret"},
	}
	for _, cookies := range tests {
		err := ValidateCookies(cookies)
		if err == nil {
			t.Fatal("invalid cookie bundle was accepted")
		}
		for _, value := range cookies {
			if value != "" && bytes.Contains([]byte(err.Error()), []byte(value)) {
				t.Fatalf("error exposed cookie value: %v", err)
			}
		}
	}
}

func TestCookieSnapshotDoesNotAliasInput(t *testing.T) {
	auth := &libgm.AuthData{RequestCrypto: libgmcrypto.NewAESCTRHelper()}
	input := map[string]string{"SID": "original"}
	auth.SetCookies(input)
	input["SID"] = "mutated"
	if got := auth.CookieSnapshot()["SID"]; got != "original" {
		t.Fatalf("cookie snapshot = %q", got)
	}
	copy := auth.CookieSnapshot()
	copy["SID"] = "copy-mutated"
	if got := auth.CookieSnapshot()["SID"]; got != "original" {
		t.Fatalf("cookie map was mutable through snapshot: %q", got)
	}
	_ = context.Background()
}

type codecTestWrapper struct{}

func (codecTestWrapper) WrapKey(_ context.Context, key []byte) (gatewaysession.WrappedKey, error) {
	return gatewaysession.WrappedKey{KeyID: "test", KeyVersion: 1, Ciphertext: append([]byte{1}, key...)}, nil
}

func (codecTestWrapper) UnwrapKey(_ context.Context, wrapped gatewaysession.WrappedKey) ([]byte, error) {
	if len(wrapped.Ciphertext) != 33 || wrapped.Ciphertext[0] != 1 {
		return nil, errors.New("invalid wrapped test key")
	}
	return append([]byte(nil), wrapped.Ciphertext[1:]...), nil
}

type codecEnvelopeStore struct {
	envelope gatewaysession.Envelope
}

func (store *codecEnvelopeStore) SaveEncryptedSession(_ context.Context, _ domain.TenantID, _ domain.ConnectionID, envelope gatewaysession.Envelope) error {
	envelope.Revision = store.envelope.Revision + 1
	store.envelope = envelope.Clone()
	return nil
}

func (store *codecEnvelopeStore) LoadEncryptedSession(context.Context, domain.TenantID, domain.ConnectionID) (gatewaysession.Envelope, error) {
	return store.envelope.Clone(), nil
}

func (store *codecEnvelopeStore) CompareAndSwapEncryptedSession(_ context.Context, _ domain.TenantID, _ domain.ConnectionID, expected uint64, envelope gatewaysession.Envelope) (bool, error) {
	if store.envelope.Revision != expected {
		return false, nil
	}
	envelope.Revision = expected + 1
	store.envelope = envelope.Clone()
	return true, nil
}
