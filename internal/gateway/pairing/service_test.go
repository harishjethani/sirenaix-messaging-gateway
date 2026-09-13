package pairing

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/session"
)

func TestServiceAllowsOneActiveAttemptPerTenantConnection(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.devices = []Device{{ID: "only", Label: "Primary phone"}}
	repository.put(connection("tenant-a", "shared", domain.ConnectionStateUnpaired))
	repository.put(connection("tenant-b", "shared", domain.ConnectionStateUnpaired))

	first, err := service.Start(context.Background(), "tenant-a", "shared", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start first: %v", err)
	}
	if first.ID != "pairing-1" || first.State != StateAwaitingPhoneApproval || first.Emoji != "🦊" {
		t.Fatalf("first attempt = %#v", first)
	}
	if _, err := service.Start(context.Background(), "tenant-a", "shared", Credentials{Cookies: validCookies()}); !errors.Is(err, ErrAttemptActive) {
		t.Fatalf("duplicate Start error = %v", err)
	}
	secondTenant, err := service.Start(context.Background(), "tenant-b", "shared", Credentials{Cookies: validCookies()})
	if err != nil || secondTenant.ID == first.ID {
		t.Fatalf("tenant B Start = %#v, %v", secondTenant, err)
	}
}

func TestServicePreservesSafeInvalidCookieClassification(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.discoverErr = ErrInvalidCookieBundle
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	if _, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: map[string]string{"SID": "private-cookie"}}); !errors.Is(err, ErrInvalidCookieBundle) {
		t.Fatalf("Start error = %v", err)
	}
	if repository.state("tenant-a", "connection-1") != domain.ConnectionStateUnpaired {
		t.Fatal("invalid cookies changed connection state")
	}
}

func TestServiceRequiresExplicitDeviceSelectionBoundToAttempt(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.devices = []Device{{ID: "phone-a", Label: "Phone A"}, {ID: "phone-b", Label: "Phone B"}}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	repository.put(connection("tenant-a", "connection-2", domain.ConnectionStateUnpaired))

	first, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if first.State != StateAwaitingDeviceSelection || first.Emoji != "" || !reflect.DeepEqual(first.Devices, provider.devices) {
		t.Fatalf("device choice response = %#v", first)
	}
	if provider.startCalls != 0 {
		t.Fatal("provider silently selected a device")
	}
	if _, err := service.SelectDevice(context.Background(), "tenant-a", "connection-1", first.ID, "unknown"); !errors.Is(err, ErrUnknownDevice) {
		t.Fatalf("unknown selection error = %v", err)
	}
	if _, err := service.SelectDevice(context.Background(), "tenant-b", "connection-1", first.ID, "phone-a"); !errors.Is(err, ErrAttemptNotFound) {
		t.Fatalf("cross-tenant pairing ID error = %v", err)
	}

	second, err := service.Start(context.Background(), "tenant-a", "connection-2", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start second: %v", err)
	}
	if _, err := service.SelectDevice(context.Background(), "tenant-a", "connection-1", second.ID, "phone-a"); !errors.Is(err, ErrAttemptNotFound) {
		t.Fatalf("cross-connection pairing ID error = %v", err)
	}
	selected, err := service.SelectDevice(context.Background(), "tenant-a", "connection-1", first.ID, "phone-b")
	if err != nil || selected.State != StateAwaitingPhoneApproval || provider.selected != "phone-b" {
		t.Fatalf("SelectDevice = %#v, %v; provider selected %q", selected, err, provider.selected)
	}
}

func TestServiceExpiryAndCancelDisposeSecretAttempts(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.devices = []Device{{ID: "phone-a", Label: "Phone A"}, {ID: "phone-b", Label: "Phone B"}}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := service.Cancel(context.Background(), "tenant-a", "connection-1", attempt.ID); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if provider.cancelCalls != 1 || repository.state("tenant-a", "connection-1") != domain.ConnectionStateUnpaired {
		t.Fatalf("cancel cleanup calls=%d state=%s", provider.cancelCalls, repository.state("tenant-a", "connection-1"))
	}
	if err := service.Cancel(context.Background(), "tenant-a", "connection-1", attempt.ID); !errors.Is(err, ErrAttemptNotFound) {
		t.Fatalf("cancel replay error = %v", err)
	}

	attempt, err = service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	service.now = func() time.Time { return attempt.ExpiresAt.Add(time.Nanosecond) }
	if _, err := service.SelectDevice(context.Background(), "tenant-a", "connection-1", attempt.ID, "phone-a"); !errors.Is(err, ErrAttemptExpired) {
		t.Fatalf("expired selection error = %v", err)
	}
	if provider.cancelCalls != 2 || repository.state("tenant-a", "connection-1") != domain.ConnectionStateUnpaired {
		t.Fatalf("expiry cleanup calls=%d state=%s", provider.cancelCalls, repository.state("tenant-a", "connection-1"))
	}
}

func TestServiceSavesEncryptedSessionBeforeConnectedAndRetriesPersistence(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.devices = []Device{{ID: "phone-a", Label: "Phone A"}}
	provider.completed = CompletedSession{Plaintext: []byte("finished-private-session"), DeviceFingerprint: make([]byte, 32)}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	repository.commitErr = errors.New("database unavailable around finished-private-session")
	if _, err := service.Complete(context.Background(), "tenant-a", "connection-1", attempt.ID); !errors.Is(err, ErrSessionPersistence) {
		t.Fatalf("Complete persistence error = %v", err)
	}
	if repository.state("tenant-a", "connection-1") == domain.ConnectionStateConnected {
		t.Fatal("persistence failure claimed connected")
	}
	if provider.completeCalls != 1 {
		t.Fatalf("provider completion calls = %d", provider.completeCalls)
	}

	repository.commitErr = nil
	completed, err := service.Complete(context.Background(), "tenant-a", "connection-1", attempt.ID)
	if err != nil || completed.State != StateComplete || repository.state("tenant-a", "connection-1") != domain.ConnectionStateConnected {
		t.Fatalf("Complete retry = %#v, %v state=%s", completed, err, repository.state("tenant-a", "connection-1"))
	}
	if provider.completeCalls != 1 {
		t.Fatal("persistence retry repeated provider completion")
	}
	if len(repository.saved.Ciphertext) == 0 || string(repository.saved.Ciphertext) == "finished-private-session" || provider.releaseCalls != 1 {
		t.Fatalf("saved envelope/release = %#v/%d", repository.saved, provider.releaseCalls)
	}
}

func TestReauthorizationReplacementCommitsAtomically(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.devices = []Device{{ID: "phone-a", Label: "Phone A"}}
	provider.completed = CompletedSession{Plaintext: []byte("replacement-session"), DeviceFingerprint: make([]byte, 32)}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateReauthorizationRequired))
	repository.saved = session.Envelope{Version: 1, Provider: "gmessages", Ciphertext: []byte("old-ciphertext"), WrappedDEK: []byte{1}, Nonce: []byte{2}, KeyID: "old", KeyVersion: 1}

	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start reauthorization: %v", err)
	}
	old := repository.saved.Clone()
	repository.commitErr = errors.New("write failed")
	if _, err := service.Complete(context.Background(), "tenant-a", "connection-1", attempt.ID); !errors.Is(err, ErrSessionPersistence) {
		t.Fatalf("Complete error = %v", err)
	}
	if !reflect.DeepEqual(repository.saved, old) {
		t.Fatal("failed reauthorization replaced old session")
	}
	repository.commitErr = nil
	if _, err := service.Complete(context.Background(), "tenant-a", "connection-1", attempt.ID); err != nil {
		t.Fatalf("Complete retry: %v", err)
	}
	if reflect.DeepEqual(repository.saved, old) {
		t.Fatal("successful reauthorization did not replace session")
	}
}

func TestAuthorizationFailureTransitionIsIdempotentWithStableEventID(t *testing.T) {
	service, _, repository := newServiceFixture(t)
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateConnected))
	first, err := service.MarkAuthorizationFailure(context.Background(), "tenant-a", "connection-1")
	if err != nil || !first.Transitioned || first.EventID == "" {
		t.Fatalf("first transition = %#v, %v", first, err)
	}
	second, err := service.MarkAuthorizationFailure(context.Background(), "tenant-a", "connection-1")
	if err != nil || second.Transitioned || second.EventID != first.EventID {
		t.Fatalf("repeat transition = %#v, %v", second, err)
	}
	if repository.state("tenant-a", "connection-1") != domain.ConnectionStateReauthorizationRequired {
		t.Fatal("authorization failure did not update health state")
	}
}

func newServiceFixture(t *testing.T) (*Service, *fakeProvider, *fakeRepository) {
	t.Helper()
	provider := &fakeProvider{name: "gmessages", emoji: "🦊"}
	repository := &fakeRepository{
		connections: make(map[string]domain.Connection), eventIDs: make(map[string]string),
		databaseNow: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC),
	}
	wrapper := &testWrapper{}
	manager, err := session.NewManager(wrapper)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	sequence := 0
	service, err := NewService(Dependencies{
		Provider: provider, Repository: repository, Sessions: manager,
		Now:   func() time.Time { return time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC) },
		TTL:   5 * time.Minute,
		NewID: func() string { sequence++; return "pairing-" + string(rune('0'+sequence)) },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service, provider, repository
}

func validCookies() map[string]string {
	return map[string]string{"SID": "1", "HSID": "2", "OSID": "3", "SSID": "4", "APISID": "5", "SAPISID": "6", "__Secure-1PSIDTS": "7"}
}

func connection(tenant, id string, state domain.ConnectionState) domain.Connection {
	return domain.Connection{TenantID: domain.TenantID(tenant), ID: domain.ConnectionID(id), Name: "Phone", State: state}
}

type fakeProvider struct {
	name                      string
	devices                   []Device
	emoji, selected           string
	completed                 CompletedSession
	discoverErr               error
	discoverCalls             int
	lastCredentials           Credentials
	startCalls, completeCalls int
	cancelCalls, releaseCalls int
}

func (provider *fakeProvider) Name() string { return provider.name }
func (provider *fakeProvider) Discover(_ context.Context, credentials Credentials) (any, []Device, error) {
	provider.discoverCalls++
	provider.lastCredentials = credentials
	return &struct{}{}, append([]Device(nil), provider.devices...), provider.discoverErr
}
func (provider *fakeProvider) StartApproval(_ context.Context, _ any, deviceID string) (string, error) {
	provider.startCalls++
	provider.selected = deviceID
	return provider.emoji, nil
}
func (provider *fakeProvider) Complete(_ context.Context, _ any) (CompletedSession, error) {
	provider.completeCalls++
	return CompletedSession{Plaintext: append([]byte(nil), provider.completed.Plaintext...), DeviceFingerprint: append([]byte(nil), provider.completed.DeviceFingerprint...)}, nil
}
func (provider *fakeProvider) Dispose(_ context.Context, _ any, cancel bool) {
	if cancel {
		provider.cancelCalls++
	} else {
		provider.releaseCalls++
	}
}

type fakeRepository struct {
	mu             sync.Mutex
	connections    map[string]domain.Connection
	eventIDs       map[string]string
	saved          session.Envelope
	commitErr      error
	pairingPrior   map[string]domain.ConnectionState
	pairingStarted map[string]time.Time
	pairingAttempt map[string]string
	restoreErr     error
	restoreCalls   int
	databaseNow    time.Time
}

func repoKey(tenant domain.TenantID, connection domain.ConnectionID) string {
	return string(tenant) + "/" + string(connection)
}
func (repository *fakeRepository) put(value domain.Connection) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.connections[repoKey(value.TenantID, value.ID)] = value
}
func (repository *fakeRepository) state(tenant, connection string) domain.ConnectionState {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.connections[tenant+"/"+connection].State
}
func (repository *fakeRepository) GetConnection(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID) (domain.Connection, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	value, ok := repository.connections[repoKey(tenant, connection)]
	if !ok {
		return domain.Connection{}, errors.New("not found")
	}
	return value, nil
}
func (repository *fakeRepository) TransitionConnection(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID, from []domain.ConnectionState, to domain.ConnectionState) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	value, ok := repository.connections[repoKey(tenant, connection)]
	if !ok {
		return errors.New("not found")
	}
	allowed := false
	for _, state := range from {
		allowed = allowed || state == value.State
	}
	if !allowed {
		return ErrInvalidConnectionState
	}
	value.State = to
	repository.connections[repoKey(tenant, connection)] = value
	return nil
}
func (repository *fakeRepository) CommitPairedSession(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID, attemptID string, envelope session.Envelope, fingerprint []byte) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.commitErr != nil {
		return repository.commitErr
	}
	key := repoKey(tenant, connection)
	value := repository.connections[key]
	if value.State != domain.ConnectionStatePairing || repository.pairingAttempt[key] != attemptID {
		return ErrAttemptSuperseded
	}
	repository.saved = envelope.Clone()
	value.State = domain.ConnectionStateConnected
	repository.connections[key] = value
	delete(repository.pairingPrior, key)
	delete(repository.pairingStarted, key)
	delete(repository.pairingAttempt, key)
	return nil
}
func (repository *fakeRepository) MarkReauthorizationRequired(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID) (AuthorizationTransition, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := repoKey(tenant, connection)
	value := repository.connections[key]
	if value.State == domain.ConnectionStateReauthorizationRequired {
		return AuthorizationTransition{EventID: repository.eventIDs[key]}, nil
	}
	value.State = domain.ConnectionStateReauthorizationRequired
	repository.connections[key] = value
	repository.eventIDs[key] = "event-1"
	return AuthorizationTransition{Transitioned: true, EventID: "event-1"}, nil
}

func (repository *fakeRepository) BeginPairing(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID, attemptID string, ttl time.Duration) (domain.ConnectionState, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := repoKey(tenant, connection)
	value, ok := repository.connections[key]
	if !ok {
		return "", ErrInvalidConnectionState
	}
	prior := value.State
	if value.State == domain.ConnectionStatePairing {
		if !repository.pairingStarted[key].Before(repository.databaseNow.Add(-ttl)) {
			return "", ErrAttemptActive
		}
		prior = repository.pairingPrior[key]
	}
	if prior != domain.ConnectionStateUnpaired && prior != domain.ConnectionStateReauthorizationRequired {
		return "", ErrInvalidConnectionState
	}
	if repository.pairingPrior == nil {
		repository.pairingPrior = make(map[string]domain.ConnectionState)
		repository.pairingStarted = make(map[string]time.Time)
		repository.pairingAttempt = make(map[string]string)
	}
	repository.pairingPrior[key] = prior
	repository.pairingStarted[key] = repository.databaseNow
	repository.pairingAttempt[key] = attemptID
	value.State = domain.ConnectionStatePairing
	repository.connections[key] = value
	return prior, nil
}

func (repository *fakeRepository) RestorePairing(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID, attemptID string) (domain.ConnectionState, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.restoreCalls++
	if repository.restoreErr != nil {
		return "", repository.restoreErr
	}
	key := repoKey(tenant, connection)
	value, ok := repository.connections[key]
	prior, hasPrior := repository.pairingPrior[key]
	if !ok || value.State != domain.ConnectionStatePairing || !hasPrior || repository.pairingAttempt[key] != attemptID {
		return "", ErrAttemptSuperseded
	}
	value.State = prior
	repository.connections[key] = value
	delete(repository.pairingPrior, key)
	delete(repository.pairingStarted, key)
	delete(repository.pairingAttempt, key)
	return prior, nil
}

func (repository *fakeRepository) ReconcileStalePairings(_ context.Context, tenant domain.TenantID, ttl time.Duration) (int, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	cutoff := repository.databaseNow.Add(-ttl)
	restored := 0
	for key, started := range repository.pairingStarted {
		if !strings.HasPrefix(key, string(tenant)+"/") {
			continue
		}
		if !started.Before(cutoff) {
			continue
		}
		value := repository.connections[key]
		value.State = repository.pairingPrior[key]
		repository.connections[key] = value
		delete(repository.pairingPrior, key)
		delete(repository.pairingStarted, key)
		delete(repository.pairingAttempt, key)
		restored++
	}
	return restored, nil
}

type testWrapper struct{}

func (*testWrapper) WrapKey(_ context.Context, key []byte) (session.WrappedKey, error) {
	return session.WrappedKey{KeyID: "test", KeyVersion: 1, Ciphertext: append([]byte{1}, key...)}, nil
}
func (*testWrapper) UnwrapKey(_ context.Context, wrapped session.WrappedKey) ([]byte, error) {
	if len(wrapped.Ciphertext) != 33 {
		return nil, errors.New("invalid")
	}
	return append([]byte(nil), wrapped.Ciphertext[1:]...), nil
}

func TestServiceForwardsGoogleAccountIndexToProvider(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.devices = []Device{{ID: "phone-a", Label: "Phone A"}}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	if _, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies(), GoogleAuthUser: 1}); err != nil {
		t.Fatalf("Start error = %v", err)
	}
	if provider.lastCredentials.GoogleAuthUser != 1 || provider.lastCredentials.Cookies["SAPISID"] != "6" {
		t.Fatalf("provider credentials = %+v", provider.lastCredentials)
	}
}
