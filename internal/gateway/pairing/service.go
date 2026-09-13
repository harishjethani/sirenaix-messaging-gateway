// Package pairing owns bounded, tenant-scoped pairing attempts. It does not
// own connection polling, retries, leases, or other actor lifecycle concerns.
package pairing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"sync"
	"time"

	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/session"
)

var (
	ErrInvalidDependencies    = errors.New("invalid pairing service dependencies")
	ErrInvalidConnectionState = errors.New("connection state does not allow pairing")
	ErrAttemptActive          = errors.New("a pairing attempt is already active")
	ErrAttemptBusy            = errors.New("pairing attempt operation already in progress")
	ErrAttemptSuperseded      = errors.New("pairing attempt no longer owns the connection")
	ErrAttemptNotFound        = errors.New("pairing attempt not found")
	ErrAttemptExpired         = errors.New("pairing attempt expired")
	ErrUnknownDevice          = errors.New("selected device is not eligible for this pairing attempt")
	ErrInvalidProviderData    = errors.New("pairing provider returned invalid data")
	ErrProviderOperation      = errors.New("pairing provider operation failed")
	ErrSessionPersistence     = errors.New("encrypted session could not be persisted")
	ErrInvalidCookieBundle    = errors.New("invalid Google cookie bundle")
)

type State string

const (
	StateAwaitingDeviceSelection State = "awaiting_device_selection"
	StateAwaitingPhoneApproval   State = "awaiting_phone_approval"
	StateComplete                State = "complete"
	StateExpired                 State = "expired"
	StateCancelled               State = "cancelled"
	StateFailed                  State = "failed"
)

const (
	PairingIDMinLength = 8
	PairingIDMaxLength = 128
	DeviceIDMaxLength  = 256
	defaultAttemptTTL  = 5 * time.Minute
	maxAttemptTTL      = 24 * time.Hour
)

func ValidAttemptTTL(ttl time.Duration) bool { return ttl > 0 && ttl <= maxAttemptTTL }

func ValidPairingID(value string) bool {
	if len(value) < PairingIDMinLength || len(value) > PairingIDMaxLength {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

func ValidDeviceID(value string) bool {
	if len(value) == 0 || len(value) > DeviceIDMaxLength {
		return false
	}
	for _, char := range value {
		if char < '!' || char > '~' {
			return false
		}
	}
	return true
}

type Device struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type CompletedSession struct {
	Plaintext         []byte
	DeviceFingerprint []byte
}

// MaxGoogleAuthUser bounds the browser account index (/u/N) accepted for pairing.
const MaxGoogleAuthUser = 9

// Credentials carries the operator-supplied Google web session used to start pairing.
type Credentials struct {
	Cookies map[string]string
	// GoogleAuthUser is the account index of the Messages account in a browser
	// signed into several Google accounts (the N in /u/N); 0 is the default account.
	GoogleAuthUser int
}

// ValidGoogleAuthUser reports whether index is an accepted browser account index.
func ValidGoogleAuthUser(index int) bool {
	return index >= 0 && index <= MaxGoogleAuthUser
}

type Provider interface {
	Name() string
	Discover(ctx context.Context, credentials Credentials) (handle any, devices []Device, err error)
	StartApproval(ctx context.Context, handle any, deviceID string) (emoji string, err error)
	Complete(ctx context.Context, handle any) (CompletedSession, error)
	Dispose(ctx context.Context, handle any, cancel bool)
}

type AuthorizationTransition struct {
	Transitioned bool
	EventID      string
}

type Repository interface {
	GetConnection(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID) (domain.Connection, error)
	TransitionConnection(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, from []domain.ConnectionState, to domain.ConnectionState) error
	BeginPairing(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, attemptID string, ttl time.Duration) (domain.ConnectionState, error)
	RestorePairing(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, attemptID string) (domain.ConnectionState, error)
	ReconcileStalePairings(ctx context.Context, tenantID domain.TenantID, ttl time.Duration) (int, error)
	CommitPairedSession(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, attemptID string, envelope session.Envelope, fingerprint []byte) error
	MarkReauthorizationRequired(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID) (AuthorizationTransition, error)
}

type Dependencies struct {
	Provider   Provider
	Repository Repository
	Sessions   *session.Manager
	Now        func() time.Time
	TTL        time.Duration
	NewID      func() string
}

type Attempt struct {
	ID        string    `json:"pairing_id"`
	State     State     `json:"state"`
	ExpiresAt time.Time `json:"expires_at"`
	Devices   []Device  `json:"devices,omitempty"`
	Emoji     string    `json:"emoji,omitempty"`
}

type attemptKey struct {
	tenantID     domain.TenantID
	connectionID domain.ConnectionID
}

type activeAttempt struct {
	mu sync.Mutex
	Attempt
	key              attemptKey
	original         domain.ConnectionState
	handle           any
	deviceIDs        map[string]struct{}
	pending          *session.Envelope
	fingerprint      []byte
	operation        attemptOperation
	generation       uint64
	pairingPersisted bool
	cleanupPending   bool
	cleanupCancel    bool
	timer            *time.Timer
}

type attemptOperation uint8

const (
	operationIdle attemptOperation = iota
	operationStart
	operationSelect
	operationComplete
	operationCleanup
)

type Service struct {
	provider   Provider
	repository Repository
	sessions   *session.Manager
	now        func() time.Time
	ttl        time.Duration
	newID      func() string

	mu    sync.Mutex
	byKey map[attemptKey]*activeAttempt
	byID  map[string]*activeAttempt
}

func NewService(dependencies Dependencies) (*Service, error) {
	if isNil(dependencies.Provider) || isNil(dependencies.Repository) || dependencies.Sessions == nil ||
		dependencies.Provider.Name() == "" {
		return nil, ErrInvalidDependencies
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	if dependencies.TTL == 0 {
		dependencies.TTL = defaultAttemptTTL
	} else if !ValidAttemptTTL(dependencies.TTL) {
		return nil, ErrInvalidDependencies
	}
	if dependencies.NewID == nil {
		dependencies.NewID = randomID
	}
	return &Service{
		provider: dependencies.Provider, repository: dependencies.Repository, sessions: dependencies.Sessions,
		now: dependencies.Now, ttl: dependencies.TTL, newID: dependencies.NewID,
		byKey: make(map[attemptKey]*activeAttempt), byID: make(map[string]*activeAttempt),
	}, nil
}

func (service *Service) Start(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, credentials Credentials) (Attempt, error) {
	if tenantID == "" || connectionID == "" {
		return Attempt{}, ErrAttemptNotFound
	}
	key := attemptKey{tenantID: tenantID, connectionID: connectionID}
	service.mu.Lock()
	current := service.byKey[key]
	service.mu.Unlock()
	if current != nil {
		cleaned, err := service.retryCleanup(ctx, current)
		if err != nil {
			return Attempt{}, err
		}
		if cleaned {
			current = nil
		}
	}
	if current != nil {
		if _, err := service.lookup(ctx, tenantID, connectionID, current.ID); err == nil {
			return Attempt{}, ErrAttemptActive
		} else if !errors.Is(err, ErrAttemptExpired) {
			return Attempt{}, err
		}
	}
	connection, err := service.repository.GetConnection(ctx, tenantID, connectionID)
	if err != nil || connection.TenantID != tenantID || connection.ID != connectionID {
		return Attempt{}, ErrAttemptNotFound
	}
	if connection.State != domain.ConnectionStateUnpaired && connection.State != domain.ConnectionStateReauthorizationRequired &&
		connection.State != domain.ConnectionStatePairing {
		return Attempt{}, ErrInvalidConnectionState
	}
	id := service.newID()
	if !ValidPairingID(id) {
		return Attempt{}, ErrProviderOperation
	}
	startedAt := service.now()
	active := &activeAttempt{
		Attempt: Attempt{ID: id, ExpiresAt: startedAt.Add(service.ttl)}, key: key,
		operation: operationStart, generation: 1,
	}
	service.mu.Lock()
	if current := service.byKey[key]; current != nil {
		service.mu.Unlock()
		return Attempt{}, ErrAttemptActive
	}
	if service.byID[id] != nil {
		service.mu.Unlock()
		return Attempt{}, ErrAttemptActive
	}
	service.byKey[key], service.byID[id] = active, active
	service.mu.Unlock()
	prior, err := service.repository.BeginPairing(ctx, tenantID, connectionID, id, service.ttl)
	if err != nil {
		service.remove(active)
		if errors.Is(err, ErrAttemptActive) {
			return Attempt{}, ErrAttemptActive
		}
		if errors.Is(err, ErrInvalidConnectionState) {
			return Attempt{}, ErrInvalidConnectionState
		}
		return Attempt{}, ErrSessionPersistence
	}
	active.mu.Lock()
	active.original = prior
	active.pairingPersisted = true
	service.scheduleExpiryLocked(active, active.ExpiresAt.Sub(service.now()))
	active.mu.Unlock()

	handle, devices, err := service.provider.Discover(ctx, Credentials{
		Cookies: cloneCookies(credentials.Cookies), GoogleAuthUser: credentials.GoogleAuthUser,
	})
	if err != nil {
		active.mu.Lock()
		active.handle = handle
		active.mu.Unlock()
		if cleanupErr := service.finishReserved(ctx, active, 1, StateFailed, true); cleanupErr != nil {
			return Attempt{}, ErrSessionPersistence
		}
		if errors.Is(err, ErrInvalidCookieBundle) {
			return Attempt{}, ErrInvalidCookieBundle
		}
		return Attempt{}, ErrProviderOperation
	}
	active.mu.Lock()
	if active.operation != operationStart || active.generation != 1 || !service.isCurrentLocked(active) {
		active.mu.Unlock()
		if handle != nil {
			service.provider.Dispose(ctx, handle, true)
		}
		return Attempt{}, ErrAttemptNotFound
	}
	active.handle = handle
	active.deviceIDs = make(map[string]struct{}, len(devices))
	for _, device := range devices {
		if !ValidDeviceID(device.ID) || device.Label == "" || len(device.Label) > 128 {
			active.mu.Unlock()
			service.fail(ctx, active, true)
			return Attempt{}, ErrInvalidProviderData
		}
		if _, duplicate := active.deviceIDs[device.ID]; duplicate {
			active.mu.Unlock()
			service.fail(ctx, active, true)
			return Attempt{}, ErrInvalidProviderData
		}
		active.deviceIDs[device.ID] = struct{}{}
	}
	active.mu.Unlock()
	if len(devices) == 0 {
		service.fail(ctx, active, true)
		return Attempt{}, ErrInvalidProviderData
	}
	active.mu.Lock()
	active.operation = operationIdle
	active.mu.Unlock()
	if len(devices) > 1 {
		active.mu.Lock()
		active.State = StateAwaitingDeviceSelection
		active.Devices = append([]Device(nil), devices...)
		result := publicAttemptLocked(active)
		active.mu.Unlock()
		return result, nil
	}
	return service.startApproval(ctx, active, devices[0].ID)
}

func (service *Service) SelectDevice(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, pairingID, deviceID string) (Attempt, error) {
	active, err := service.get(tenantID, connectionID, pairingID)
	if err != nil {
		return Attempt{}, err
	}
	active.mu.Lock()
	if !service.isCurrentLocked(active) {
		active.mu.Unlock()
		return Attempt{}, ErrAttemptNotFound
	}
	if active.operation != operationIdle {
		active.mu.Unlock()
		return Attempt{}, ErrAttemptBusy
	}
	if service.now().After(active.ExpiresAt) {
		active.operation = operationCleanup
		active.generation++
		generation := active.generation
		active.mu.Unlock()
		if err := service.finishReserved(ctx, active, generation, StateExpired, true); err != nil {
			return Attempt{}, ErrSessionPersistence
		}
		return Attempt{}, ErrAttemptExpired
	}
	if active.State != StateAwaitingDeviceSelection {
		active.mu.Unlock()
		return Attempt{}, ErrUnknownDevice
	}
	if _, ok := active.deviceIDs[deviceID]; !ok {
		active.mu.Unlock()
		return Attempt{}, ErrUnknownDevice
	}
	active.operation = operationSelect
	active.generation++
	generation := active.generation
	handle := active.handle
	active.mu.Unlock()
	return service.startApprovalReserved(ctx, active, generation, handle, deviceID)
}

func (service *Service) startApproval(ctx context.Context, active *activeAttempt, deviceID string) (Attempt, error) {
	active.mu.Lock()
	if active.operation != operationIdle {
		active.mu.Unlock()
		return Attempt{}, ErrAttemptBusy
	}
	active.operation = operationSelect
	active.generation++
	generation := active.generation
	handle := active.handle
	active.mu.Unlock()
	return service.startApprovalReserved(ctx, active, generation, handle, deviceID)
}

func (service *Service) startApprovalReserved(ctx context.Context, active *activeAttempt, generation uint64, handle any, deviceID string) (Attempt, error) {
	emoji, err := service.provider.StartApproval(ctx, handle, deviceID)
	if err != nil || emoji == "" {
		if cleanupErr := service.finishReserved(ctx, active, generation, StateFailed, true); cleanupErr != nil {
			return Attempt{}, ErrSessionPersistence
		}
		return Attempt{}, ErrProviderOperation
	}
	active.mu.Lock()
	if active.operation != operationSelect || active.generation != generation || !service.isCurrentLocked(active) {
		active.mu.Unlock()
		return Attempt{}, ErrAttemptNotFound
	}
	active.State = StateAwaitingPhoneApproval
	active.Emoji = emoji
	active.Devices = nil
	active.operation = operationIdle
	result := publicAttemptLocked(active)
	active.mu.Unlock()
	return result, nil
}

func (service *Service) Complete(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, pairingID string) (Attempt, error) {
	active, err := service.get(tenantID, connectionID, pairingID)
	if err != nil {
		return Attempt{}, err
	}
	active.mu.Lock()
	if !service.isCurrentLocked(active) {
		active.mu.Unlock()
		return Attempt{}, ErrAttemptNotFound
	}
	if active.operation != operationIdle {
		active.mu.Unlock()
		return Attempt{}, ErrAttemptBusy
	}
	if service.now().After(active.ExpiresAt) {
		active.operation = operationCleanup
		active.generation++
		generation := active.generation
		active.mu.Unlock()
		if err := service.finishReserved(ctx, active, generation, StateExpired, true); err != nil {
			return Attempt{}, ErrSessionPersistence
		}
		return Attempt{}, ErrAttemptExpired
	}
	if active.State != StateAwaitingPhoneApproval {
		active.mu.Unlock()
		return Attempt{}, ErrAttemptNotFound
	}
	active.operation = operationComplete
	active.generation++
	generation := active.generation
	handle := active.handle
	pending := active.pending
	active.mu.Unlock()
	if pending == nil {
		completed, err := service.provider.Complete(ctx, handle)
		if err != nil || len(completed.Plaintext) == 0 || len(completed.DeviceFingerprint) != sha256.Size {
			zero(completed.Plaintext)
			if cleanupErr := service.finishReserved(ctx, active, generation, StateFailed, true); cleanupErr != nil {
				return Attempt{}, ErrSessionPersistence
			}
			return Attempt{}, ErrProviderOperation
		}
		envelope, err := service.sessions.Seal(ctx, session.Scope{
			TenantID: string(tenantID), ConnectionID: string(connectionID), Provider: service.provider.Name(),
		}, completed.Plaintext)
		zero(completed.Plaintext)
		if err != nil {
			if cleanupErr := service.finishReserved(ctx, active, generation, StateFailed, false); cleanupErr != nil {
				return Attempt{}, ErrSessionPersistence
			}
			return Attempt{}, ErrSessionPersistence
		}
		active.mu.Lock()
		if active.operation != operationComplete || active.generation != generation || !service.isCurrentLocked(active) {
			active.mu.Unlock()
			zero(completed.DeviceFingerprint)
			return Attempt{}, ErrAttemptNotFound
		}
		active.pending = &envelope
		active.fingerprint = append([]byte(nil), completed.DeviceFingerprint...)
		zero(completed.DeviceFingerprint)
		active.handle = nil
		pending = active.pending
		active.mu.Unlock()
		service.provider.Dispose(ctx, handle, false)
	}
	active.mu.Lock()
	fingerprint := append([]byte(nil), active.fingerprint...)
	active.mu.Unlock()
	if err := service.repository.CommitPairedSession(ctx, tenantID, connectionID, active.ID, pending.Clone(), fingerprint); err != nil {
		zero(fingerprint)
		active.mu.Lock()
		if active.operation == operationComplete && active.generation == generation {
			if errors.Is(err, ErrAttemptSuperseded) {
				active.pending = nil
				zero(active.fingerprint)
				active.fingerprint = nil
				active.State = StateFailed
				service.removeLocked(active)
			}
			active.operation = operationIdle
		}
		active.mu.Unlock()
		return Attempt{}, ErrSessionPersistence
	}
	zero(fingerprint)
	active.mu.Lock()
	if active.operation != operationComplete || active.generation != generation || !service.isCurrentLocked(active) {
		active.mu.Unlock()
		return Attempt{}, ErrAttemptNotFound
	}
	service.removeLocked(active)
	active.pending = nil
	zero(active.fingerprint)
	active.fingerprint = nil
	active.State = StateComplete
	active.Emoji = ""
	active.operation = operationIdle
	result := publicAttemptLocked(active)
	active.mu.Unlock()
	return result, nil
}

func (service *Service) Cancel(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, pairingID string) error {
	active, err := service.get(tenantID, connectionID, pairingID)
	if err != nil {
		return err
	}
	active.mu.Lock()
	if !service.isCurrentLocked(active) {
		active.mu.Unlock()
		return ErrAttemptNotFound
	}
	if active.operation != operationIdle {
		active.mu.Unlock()
		return ErrAttemptBusy
	}
	active.operation = operationCleanup
	active.generation++
	generation := active.generation
	active.mu.Unlock()
	if err := service.finishReserved(ctx, active, generation, StateCancelled, true); err != nil {
		return ErrSessionPersistence
	}
	return nil
}

func (service *Service) finishReserved(ctx context.Context, active *activeAttempt, generation uint64, state State, cancel bool) error {
	active.mu.Lock()
	if active.generation != generation || (active.operation != operationCleanup && active.operation != operationStart && active.operation != operationSelect && active.operation != operationComplete) {
		active.mu.Unlock()
		return ErrAttemptBusy
	}
	active.operation = operationCleanup
	active.cleanupPending = true
	cancelProvider := active.pending == nil
	if !cancel {
		cancelProvider = false
	}
	handle := active.handle
	active.handle, active.pending = nil, nil
	zero(active.fingerprint)
	active.fingerprint = nil
	active.State = state
	active.cleanupCancel = cancelProvider
	if active.timer != nil {
		active.timer.Stop()
		active.timer = nil
	}
	persisted := active.pairingPersisted
	active.mu.Unlock()
	if handle != nil {
		service.provider.Dispose(ctx, handle, cancelProvider)
	}
	if persisted {
		if err := service.restore(ctx, active); err != nil {
			if errors.Is(err, ErrAttemptSuperseded) {
				active.mu.Lock()
				active.cleanupPending = false
				active.pairingPersisted = false
				service.removeLocked(active)
				active.operation = operationIdle
				active.mu.Unlock()
				return err
			}
			active.mu.Lock()
			active.operation = operationIdle
			service.scheduleExpiryLocked(active, time.Second)
			active.mu.Unlock()
			return err
		}
	}
	active.mu.Lock()
	active.cleanupPending = false
	active.pairingPersisted = false
	service.removeLocked(active)
	active.operation = operationIdle
	active.mu.Unlock()
	return nil
}

func (service *Service) retryCleanup(ctx context.Context, active *activeAttempt) (bool, error) {
	active.mu.Lock()
	if !service.isCurrentLocked(active) {
		active.mu.Unlock()
		return true, nil
	}
	if !active.cleanupPending {
		active.mu.Unlock()
		return false, nil
	}
	if active.operation != operationIdle {
		active.mu.Unlock()
		return false, ErrAttemptBusy
	}
	active.operation = operationCleanup
	active.generation++
	generation, state, cancel := active.generation, active.State, active.cleanupCancel
	active.mu.Unlock()
	if err := service.finishReserved(ctx, active, generation, state, cancel); err != nil {
		return false, ErrSessionPersistence
	}
	return true, nil
}

func (service *Service) SweepExpired(ctx context.Context) (int, error) {
	service.mu.Lock()
	active := make([]*activeAttempt, 0, len(service.byKey))
	for _, attempt := range service.byKey {
		active = append(active, attempt)
	}
	service.mu.Unlock()
	cleaned := 0
	var cleanupErr error
	for _, attempt := range active {
		attempt.mu.Lock()
		if !service.isCurrentLocked(attempt) {
			attempt.mu.Unlock()
			continue
		}
		due := attempt.cleanupPending || !service.now().Before(attempt.ExpiresAt)
		if attempt.operation != operationIdle {
			if due {
				service.scheduleExpiryLocked(attempt, 50*time.Millisecond)
			}
			attempt.mu.Unlock()
			continue
		}
		if !due {
			attempt.mu.Unlock()
			continue
		}
		state := attempt.State
		cancel := attempt.cleanupCancel
		if !attempt.cleanupPending {
			state, cancel = StateExpired, true
		}
		attempt.operation = operationCleanup
		attempt.generation++
		generation := attempt.generation
		attempt.mu.Unlock()
		if err := service.finishReserved(ctx, attempt, generation, state, cancel); err != nil {
			cleanupErr = ErrSessionPersistence
			continue
		}
		cleaned++
	}
	return cleaned, cleanupErr
}

func (service *Service) ReconcileStalePairings(ctx context.Context, tenantID domain.TenantID) (int, error) {
	return service.repository.ReconcileStalePairings(ctx, tenantID, service.ttl)
}

func (service *Service) scheduleExpiryLocked(active *activeAttempt, delay time.Duration) {
	if delay < 0 {
		delay = 0
	}
	if active.timer != nil {
		active.timer.Stop()
	}
	active.timer = time.AfterFunc(delay, func() {
		_, _ = service.SweepExpired(context.Background())
	})
}

func (service *Service) MarkAuthorizationFailure(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID) (AuthorizationTransition, error) {
	transition, err := service.repository.MarkReauthorizationRequired(ctx, tenantID, connectionID)
	if err != nil || transition.EventID == "" {
		return AuthorizationTransition{}, ErrSessionPersistence
	}
	return transition, nil
}

func (service *Service) lookup(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, pairingID string) (*activeAttempt, error) {
	active, err := service.get(tenantID, connectionID, pairingID)
	if err != nil {
		return nil, err
	}
	active.mu.Lock()
	if !service.isCurrentLocked(active) {
		active.mu.Unlock()
		return nil, ErrAttemptNotFound
	}
	if active.operation != operationIdle {
		active.mu.Unlock()
		return nil, ErrAttemptBusy
	}
	if service.now().After(active.ExpiresAt) {
		active.operation = operationCleanup
		active.generation++
		generation := active.generation
		active.mu.Unlock()
		if err := service.finishReserved(ctx, active, generation, StateExpired, true); err != nil {
			return nil, ErrSessionPersistence
		}
		return nil, ErrAttemptExpired
	}
	active.mu.Unlock()
	return active, nil
}

func (service *Service) get(tenantID domain.TenantID, connectionID domain.ConnectionID, pairingID string) (*activeAttempt, error) {
	if !ValidPairingID(pairingID) {
		return nil, ErrAttemptNotFound
	}
	service.mu.Lock()
	active := service.byID[pairingID]
	if active == nil || active.key != (attemptKey{tenantID: tenantID, connectionID: connectionID}) {
		service.mu.Unlock()
		return nil, ErrAttemptNotFound
	}
	service.mu.Unlock()
	return active, nil
}

func (service *Service) fail(ctx context.Context, active *activeAttempt, cancel bool) {
	active.mu.Lock()
	active.operation = operationCleanup
	active.generation++
	generation := active.generation
	active.mu.Unlock()
	_ = service.finishReserved(ctx, active, generation, StateFailed, cancel)
}

func (service *Service) restore(ctx context.Context, active *activeAttempt) error {
	_, err := service.repository.RestorePairing(ctx, active.key.tenantID, active.key.connectionID, active.ID)
	return err
}

func (service *Service) remove(active *activeAttempt) {
	active.mu.Lock()
	service.removeLocked(active)
	active.mu.Unlock()
}

// Lock order is always activeAttempt.mu followed by Service.mu. Code that
// obtains Service.mu releases it before touching an attempt.
func (service *Service) removeLocked(active *activeAttempt) {
	service.mu.Lock()
	if service.byID[active.ID] == active {
		delete(service.byID, active.ID)
	}
	if service.byKey[active.key] == active {
		delete(service.byKey, active.key)
	}
	if active.timer != nil {
		active.timer.Stop()
		active.timer = nil
	}
	service.mu.Unlock()
}

func publicAttemptLocked(active *activeAttempt) Attempt {
	result := active.Attempt
	result.Devices = append([]Device(nil), active.Devices...)
	return result
}

func (service *Service) isCurrentLocked(active *activeAttempt) bool {
	service.mu.Lock()
	defer service.mu.Unlock()
	return service.byID[active.ID] == active && service.byKey[active.key] == active
}

func cloneCookies(input map[string]string) map[string]string {
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func randomID() string {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(buffer)
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
