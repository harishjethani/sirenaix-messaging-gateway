package gmessages

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-gmessages/internal/gateway/pairing"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
)

func TestPairingProviderValidatesCookiesBeforeClientCreation(t *testing.T) {
	created := 0
	provider := newPairingProvider(func(*libgm.AuthData, zerolog.Logger) gaiaClient {
		created++
		return &fakeGaiaClient{}
	})
	_, _, err := provider.Discover(context.Background(), pairing.Credentials{Cookies: map[string]string{"SID": "private-cookie"}})
	if !errors.Is(err, ErrInvalidCookies) || created != 0 || strings.Contains(err.Error(), "private-cookie") {
		t.Fatalf("Discover error=%v created=%d", err, created)
	}
}

// The account index must reach AuthData before the client is created, because
// FetchConfig and SignInGaia are the first cookie-authenticated requests.
func TestPairingProviderAppliesGoogleAuthUserBeforeClientCreation(t *testing.T) {
	observed := -1
	client := &fakeGaiaClient{auth: validSessionAuth()}
	provider := newPairingProvider(func(auth *libgm.AuthData, _ zerolog.Logger) gaiaClient {
		snapshot := auth.Snapshot()
		observed = snapshot.GoogleAuthUser
		snapshot.ClearSecrets()
		return client
	})
	handle, _, err := provider.Discover(context.Background(), pairing.Credentials{Cookies: validCookieBundle(), GoogleAuthUser: 1})
	if err != nil || observed != 1 {
		t.Fatalf("Discover error=%v observed GoogleAuthUser=%d", err, observed)
	}
	provider.Dispose(context.Background(), handle, false)

	created := 0
	rejecting := newPairingProvider(func(*libgm.AuthData, zerolog.Logger) gaiaClient {
		created++
		return client
	})
	for _, index := range []int{-1, 10} {
		if _, _, err := rejecting.Discover(context.Background(), pairing.Credentials{Cookies: validCookieBundle(), GoogleAuthUser: index}); !errors.Is(err, ErrInvalidCookies) {
			t.Fatalf("Discover GoogleAuthUser=%d error=%v", index, err)
		}
	}
	if created != 0 {
		t.Fatalf("out-of-range account index created %d clients", created)
	}
}

func TestPairingProviderForwardsExplicitDiscoveryChoiceAndEncodesCompletion(t *testing.T) {
	client := &fakeGaiaClient{
		devices: []libgm.GaiaPairingDevice{{ID: "phone-a", Label: "Phone A"}, {ID: "phone-b", Label: "Phone B"}},
		auth:    validSessionAuth(),
	}
	provider := newPairingProvider(func(*libgm.AuthData, zerolog.Logger) gaiaClient { return client })
	handle, devices, err := provider.Discover(context.Background(), pairing.Credentials{Cookies: validCookieBundle()})
	if err != nil || len(devices) != 2 {
		t.Fatalf("Discover = %#v, %v", devices, err)
	}
	if _, err := provider.StartApproval(context.Background(), handle, "phone-b"); err != nil || client.selected != "phone-b" {
		t.Fatalf("StartApproval selected=%q error=%v", client.selected, err)
	}
	completed, err := provider.Complete(context.Background(), handle)
	if err != nil || len(completed.Plaintext) == 0 || len(completed.DeviceFingerprint) != 32 {
		t.Fatalf("Complete = %#v, %v", completed, err)
	}
	auth, _, err := DecodeSession(completed.Plaintext)
	if err != nil || auth == nil {
		t.Fatalf("completed session decode = %#v, %v", auth, err)
	}
	provider.Dispose(context.Background(), handle, false)
	if !client.disconnected || !client.cleared {
		t.Fatal("Dispose did not disconnect and clear secrets")
	}
	_ = pairing.StateComplete
}

func TestPairingApprovalPollOutlivesRequestAndDisposeCancelsAttempt(t *testing.T) {
	client := &fakeGaiaClient{
		devices: []libgm.GaiaPairingDevice{{ID: "phone-a", Label: "Phone A"}},
		auth:    validSessionAuth(),
	}
	provider := newPairingProvider(func(*libgm.AuthData, zerolog.Logger) gaiaClient { return client })
	handle, _, err := provider.Discover(context.Background(), pairing.Credentials{Cookies: validCookieBundle()})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	if _, err = provider.StartApproval(requestCtx, handle, "phone-a"); err != nil {
		t.Fatalf("StartApproval() error = %v", err)
	}
	cancelRequest()
	if client.attemptCtx == nil || client.attemptCtx.Err() != nil {
		t.Fatal("approval poll was canceled with the SelectDevice request")
	}
	completed, err := provider.Complete(context.Background(), handle)
	if err != nil || len(completed.Plaintext) == 0 {
		t.Fatalf("Complete() after request cancellation = %#v, %v", completed, err)
	}
	provider.Dispose(context.Background(), handle, false)
	if client.attemptCtx.Err() == nil {
		t.Fatal("Dispose left the attempt-owned approval poll running")
	}
	if !client.disconnectSawAttemptCancellation {
		t.Fatal("Dispose joined the client before canceling the attempt-owned poll")
	}
}

func TestPairingCancellationStopsAttemptPollBeforeRemoteCancel(t *testing.T) {
	client := &fakeGaiaClient{
		devices: []libgm.GaiaPairingDevice{{ID: "phone-a", Label: "Phone A"}},
		auth:    validSessionAuth(),
	}
	provider := newPairingProvider(func(*libgm.AuthData, zerolog.Logger) gaiaClient { return client })
	handle, _, err := provider.Discover(context.Background(), pairing.Credentials{Cookies: validCookieBundle()})
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if _, err = provider.StartApproval(context.Background(), handle, "phone-a"); err != nil {
		t.Fatalf("StartApproval() error = %v", err)
	}
	provider.Dispose(context.Background(), handle, true)
	if !client.cancelSawAttemptCancellation {
		t.Fatal("remote pairing cancel started before the attempt-owned poll was canceled")
	}
}

type fakeGaiaClient struct {
	devices                          []libgm.GaiaPairingDevice
	auth                             *libgm.AuthData
	push                             *libgm.PushKeys
	selected                         string
	disconnected, cleared            bool
	session                          *libgm.PairingSession
	attemptCtx                       context.Context
	disconnectSawAttemptCancellation bool
	cancelSawAttemptCancellation     bool
}

func (client *fakeGaiaClient) FetchConfig(context.Context) error { return nil }
func (client *fakeGaiaClient) DiscoverGaiaPairingDevices(context.Context) (*libgm.GaiaDeviceDiscovery, []libgm.GaiaPairingDevice, error) {
	return &libgm.GaiaDeviceDiscovery{}, append([]libgm.GaiaPairingDevice(nil), client.devices...), nil
}
func (client *fakeGaiaClient) StartGaiaPairingWithDevice(requestCtx context.Context, _ *libgm.GaiaDeviceDiscovery, deviceID string) (string, *libgm.PairingSession, error) {
	return client.StartGaiaPairingWithDeviceAttempt(requestCtx, requestCtx, nil, deviceID)
}
func (client *fakeGaiaClient) StartGaiaPairingWithDeviceAttempt(_ context.Context, attemptCtx context.Context, _ *libgm.GaiaDeviceDiscovery, deviceID string) (string, *libgm.PairingSession, error) {
	client.selected = deviceID
	client.attemptCtx = attemptCtx
	client.session = &libgm.PairingSession{}
	return "🦊", client.session, nil
}
func (client *fakeGaiaClient) FinishGaiaPairing(context.Context, *libgm.PairingSession) (string, error) {
	return "phone-identity", nil
}
func (client *fakeGaiaClient) CancelGaiaPairing(context.Context, *libgm.PairingSession) error {
	client.cancelSawAttemptCancellation = client.attemptCtx != nil && client.attemptCtx.Err() != nil
	return nil
}
func (client *fakeGaiaClient) Disconnect() {
	client.disconnected = true
	client.disconnectSawAttemptCancellation = client.attemptCtx != nil && client.attemptCtx.Err() != nil
}
func (client *fakeGaiaClient) SnapshotSession() (*libgm.AuthData, *libgm.PushKeys) {
	return client.auth.Snapshot(), client.push
}
func (client *fakeGaiaClient) ClearSessionSecrets() {
	client.cleared = true
	client.auth.ClearSecrets()
}

func validCookieBundle() map[string]string {
	return map[string]string{"SID": "1", "HSID": "2", "OSID": "3", "SSID": "4", "APISID": "5", "SAPISID": "6", "__Secure-1PSIDTS": "7"}
}
