package gmessages

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-gmessages/internal/gateway/pairing"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
)

var ErrInvalidPairingAttempt = errors.New("invalid Google Messages pairing attempt")

type gaiaClient interface {
	FetchConfig(context.Context) error
	DiscoverGaiaPairingDevices(context.Context) (*libgm.GaiaDeviceDiscovery, []libgm.GaiaPairingDevice, error)
	StartGaiaPairingWithDeviceAttempt(context.Context, context.Context, *libgm.GaiaDeviceDiscovery, string) (string, *libgm.PairingSession, error)
	FinishGaiaPairing(context.Context, *libgm.PairingSession) (string, error)
	CancelGaiaPairing(context.Context, *libgm.PairingSession) error
	Disconnect()
	SnapshotSession() (*libgm.AuthData, *libgm.PushKeys)
	ClearSessionSecrets()
}

type gaiaClientFactory func(*libgm.AuthData, zerolog.Logger) gaiaClient

type PairingProvider struct {
	newClient gaiaClientFactory
}

type gaiaAttempt struct {
	client    gaiaClient
	discovery *libgm.GaiaDeviceDiscovery
	session   *libgm.PairingSession
	ctx       context.Context
	cancel    context.CancelFunc
}

func NewPairingProvider() *PairingProvider {
	return newPairingProvider(func(auth *libgm.AuthData, logger zerolog.Logger) gaiaClient {
		return libgm.NewClient(auth, nil, logger)
	})
}

func newPairingProvider(factory gaiaClientFactory) *PairingProvider {
	return &PairingProvider{newClient: factory}
}

func (*PairingProvider) Name() string { return "gmessages" }

func (provider *PairingProvider) Discover(ctx context.Context, credentials pairing.Credentials) (any, []pairing.Device, error) {
	if err := ValidateCookies(credentials.Cookies); err != nil {
		return nil, nil, err
	}
	if !pairing.ValidGoogleAuthUser(credentials.GoogleAuthUser) {
		return nil, nil, ErrInvalidCookies
	}
	auth := libgm.NewAuthData()
	auth.SetCookies(credentials.Cookies)
	// Must be set before the client's first cookie-authenticated request (FetchConfig).
	auth.SetGoogleAuthUser(credentials.GoogleAuthUser)
	client := provider.newClient(auth, zerolog.Nop())
	if client == nil {
		auth.ClearSecrets()
		return nil, nil, ErrInvalidPairingAttempt
	}
	attemptCtx, cancelAttempt := context.WithCancel(context.Background())
	attempt := &gaiaAttempt{client: client, ctx: attemptCtx, cancel: cancelAttempt}
	if err := client.FetchConfig(ctx); err != nil {
		provider.Dispose(ctx, attempt, false)
		return nil, nil, ErrInvalidPairingAttempt
	}
	discovery, choices, err := client.DiscoverGaiaPairingDevices(ctx)
	if err != nil {
		provider.Dispose(ctx, attempt, false)
		return nil, nil, ErrInvalidPairingAttempt
	}
	attempt.discovery = discovery
	devices := make([]pairing.Device, 0, len(choices))
	for _, choice := range choices {
		devices = append(devices, pairing.Device{ID: choice.ID, Label: choice.Label})
	}
	return attempt, devices, nil
}

func (provider *PairingProvider) StartApproval(ctx context.Context, handle any, deviceID string) (string, error) {
	attempt, ok := handle.(*gaiaAttempt)
	if !ok || attempt == nil || attempt.client == nil || attempt.discovery == nil || attempt.session != nil {
		return "", ErrInvalidPairingAttempt
	}
	emoji, session, err := attempt.client.StartGaiaPairingWithDeviceAttempt(ctx, attempt.ctx, attempt.discovery, deviceID)
	if err != nil {
		return "", ErrInvalidPairingAttempt
	}
	attempt.session = session
	return emoji, nil
}

func (provider *PairingProvider) Complete(ctx context.Context, handle any) (pairing.CompletedSession, error) {
	attempt, ok := handle.(*gaiaAttempt)
	if !ok || attempt == nil || attempt.client == nil || attempt.session == nil {
		return pairing.CompletedSession{}, ErrInvalidPairingAttempt
	}
	phoneID, err := attempt.client.FinishGaiaPairing(ctx, attempt.session)
	if err != nil || phoneID == "" {
		return pairing.CompletedSession{}, ErrInvalidPairingAttempt
	}
	auth, push := attempt.client.SnapshotSession()
	if auth == nil {
		return pairing.CompletedSession{}, ErrInvalidPairingAttempt
	}
	defer auth.ClearSecrets()
	defer clearPushKeys(push)
	plaintext, err := EncodeSession(auth, push)
	if err != nil {
		return pairing.CompletedSession{}, ErrInvalidPairingAttempt
	}
	fingerprint := sha256.Sum256([]byte("gmessages/" + phoneID))
	return pairing.CompletedSession{Plaintext: plaintext, DeviceFingerprint: fingerprint[:]}, nil
}

func (provider *PairingProvider) Dispose(ctx context.Context, handle any, cancel bool) {
	attempt, ok := handle.(*gaiaAttempt)
	if !ok || attempt == nil || attempt.client == nil {
		return
	}
	if attempt.cancel != nil {
		attempt.cancel()
	}
	if cancel && attempt.session != nil {
		_ = attempt.client.CancelGaiaPairing(ctx, attempt.session)
	}
	attempt.client.Disconnect()
	attempt.client.ClearSessionSecrets()
	attempt.client, attempt.discovery, attempt.session, attempt.ctx, attempt.cancel = nil, nil, nil, nil, nil
}

func clearPushKeys(push *libgm.PushKeys) {
	if push == nil {
		return
	}
	for index := range push.P256DH {
		push.P256DH[index] = 0
	}
	for index := range push.Auth {
		push.Auth[index] = 0
	}
}

var _ pairing.Provider = (*PairingProvider)(nil)
