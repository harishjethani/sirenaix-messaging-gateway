package gmessages

import (
	"bytes"
	"crypto/ecdh"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"

	"go.mau.fi/mautrix-gmessages/internal/gateway/pairing"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
)

const (
	sessionCodecVersion   = 1
	maxEncodedSessionSize = 4 * 1024 * 1024
	maxSessionFieldSize   = 64 * 1024
	maxDeviceIDSize       = 256
	maxPushURLSize        = 2048
	maxSessionCookieCount = 64
	maxCookieNameSize     = 256
)

var (
	ErrInvalidSessionData = errors.New("invalid Google Messages session data")
	ErrInvalidCookies     = pairing.ErrInvalidCookieBundle
)

// requiredGoogleCookies is the minimal web session Google accepts for SignInGaia;
// without the rotating __Secure-1PSIDTS cookie the request is rejected with 401.
var requiredGoogleCookies = [...]string{"SID", "HSID", "OSID", "SSID", "APISID", "SAPISID", "__Secure-1PSIDTS"}

type sessionWire struct {
	Version int             `json:"version"`
	Auth    *libgm.AuthData `json:"auth"`
	Push    *libgm.PushKeys `json:"push,omitempty"`
}

func ValidateCookies(cookies map[string]string) error {
	if len(cookies) != len(requiredGoogleCookies) {
		return ErrInvalidCookies
	}
	for _, name := range requiredGoogleCookies {
		if strings.TrimSpace(cookies[name]) == "" || !validCookieValue(cookies[name]) {
			return ErrInvalidCookies
		}
	}
	return nil
}

func EncodeSession(auth *libgm.AuthData, push *libgm.PushKeys) ([]byte, error) {
	if auth == nil {
		return nil, ErrInvalidSessionData
	}
	snapshot := auth.Snapshot()
	defer snapshot.ClearSecrets()
	pushSnapshot := clonePushKeys(push)
	defer clearPushKeys(pushSnapshot)
	if !validSession(snapshot, pushSnapshot) {
		return nil, ErrInvalidSessionData
	}
	encoded, err := json.Marshal(sessionWire{Version: sessionCodecVersion, Auth: snapshot, Push: pushSnapshot})
	if err != nil {
		return nil, ErrInvalidSessionData
	}
	if len(encoded) > maxEncodedSessionSize {
		zero(encoded)
		return nil, ErrInvalidSessionData
	}
	return encoded, nil
}

func DecodeSession(encoded []byte) (*libgm.AuthData, *libgm.PushKeys, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedSessionSize {
		return nil, nil, ErrInvalidSessionData
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire sessionWire
	if err := decoder.Decode(&wire); err != nil {
		return nil, nil, ErrInvalidSessionData
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, ErrInvalidSessionData
	}
	if wire.Version != sessionCodecVersion || !validSession(wire.Auth, wire.Push) {
		if wire.Auth != nil {
			wire.Auth.ClearSecrets()
		}
		return nil, nil, ErrInvalidSessionData
	}
	restored := wire.Auth.Snapshot()
	wire.Auth.ClearSecrets()
	return restored, clonePushKeys(wire.Push), nil
}

func validSession(auth *libgm.AuthData, push *libgm.PushKeys) bool {
	if auth == nil || auth.RequestCrypto == nil || len(auth.RequestCrypto.AESKey) != 32 || len(auth.RequestCrypto.HMACKey) != 32 ||
		auth.RefreshKey == nil || auth.RefreshKey.KeyType != "EC" || auth.RefreshKey.Curve != "P-256" ||
		!validP256PrivateKey(auth.RefreshKey.D, auth.RefreshKey.X, auth.RefreshKey.Y) ||
		auth.Browser == nil || len(strings.TrimSpace(auth.Browser.GetSourceID())) == 0 || len(auth.Browser.GetSourceID()) > maxDeviceIDSize ||
		auth.Mobile == nil || len(strings.TrimSpace(auth.Mobile.GetSourceID())) == 0 || len(auth.Mobile.GetSourceID()) > maxDeviceIDSize ||
		len(auth.TachyonAuthToken) == 0 || len(auth.TachyonAuthToken) > maxSessionFieldSize || auth.TachyonExpiry.IsZero() || auth.TachyonTTL <= 0 ||
		auth.SessionID.String() == "00000000-0000-0000-0000-000000000000" || auth.DestRegID.String() == "00000000-0000-0000-0000-000000000000" ||
		auth.PairingID.String() == "00000000-0000-0000-0000-000000000000" || !validFinishedSessionCookies(auth.Cookies) ||
		len(auth.WebEncryptionKey) > maxSessionFieldSize || !pairing.ValidGoogleAuthUser(auth.GoogleAuthUser) {
		return false
	}
	if push == nil {
		return true
	}
	parsed, err := url.Parse(push.URL)
	return err == nil && len(push.URL) > 0 && len(push.URL) <= maxPushURLSize && parsed.Scheme == "https" && parsed.Host != "" &&
		len(push.P256DH) == 65 && len(push.Auth) == 16
}

func validFinishedSessionCookies(cookies map[string]string) bool {
	if len(cookies) < len(requiredGoogleCookies) || len(cookies) > maxSessionCookieCount {
		return false
	}
	for name, value := range cookies {
		if !validCookieName(name) || !validCookieValue(value) {
			return false
		}
	}
	for _, name := range requiredGoogleCookies {
		if strings.TrimSpace(cookies[name]) == "" {
			return false
		}
	}
	return true
}

func validCookieName(name string) bool {
	if len(name) == 0 || len(name) > maxCookieNameSize {
		return false
	}
	for index := 0; index < len(name); index++ {
		char := name[index]
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			continue
		}
		switch char {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func validCookieValue(value string) bool {
	if len(value) > maxSessionFieldSize {
		return false
	}
	for index := 0; index < len(value); index++ {
		char := value[index]
		if char != 0x21 && !(char >= 0x23 && char <= 0x2b) && !(char >= 0x2d && char <= 0x3a) &&
			!(char >= 0x3c && char <= 0x5b) && !(char >= 0x5d && char <= 0x7e) {
			return false
		}
	}
	return true
}

func validP256PrivateKey(dBytes, xBytes, yBytes []byte) bool {
	if len(dBytes) == 0 || len(dBytes) > 32 || len(xBytes) == 0 || len(xBytes) > 32 || len(yBytes) == 0 || len(yBytes) > 32 {
		return false
	}
	privateBytes := make([]byte, 32)
	copy(privateBytes[len(privateBytes)-len(dBytes):], dBytes)
	privateKey, err := ecdh.P256().NewPrivateKey(privateBytes)
	if err != nil {
		return false
	}
	publicBytes := make([]byte, 65)
	publicBytes[0] = 4
	copy(publicBytes[1+32-len(xBytes):33], xBytes)
	copy(publicBytes[33+32-len(yBytes):], yBytes)
	publicKey, err := ecdh.P256().NewPublicKey(publicBytes)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(privateKey.PublicKey().Bytes(), publicKey.Bytes()) == 1
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func clonePushKeys(push *libgm.PushKeys) *libgm.PushKeys {
	if push == nil {
		return nil
	}
	return &libgm.PushKeys{URL: push.URL, P256DH: append([]byte(nil), push.P256DH...), Auth: append([]byte(nil), push.Auth...)}
}
