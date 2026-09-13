package pairing

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
)

func TestSelectDeviceReservationExcludesCancel(t *testing.T) {
	service, _, repository := newServiceFixture(t)
	provider := newBarrierProvider([]Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}})
	service.provider = provider
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	selected := make(chan error, 1)
	go func() {
		_, selectErr := service.SelectDevice(context.Background(), "tenant-a", "connection-1", attempt.ID, "a")
		selected <- selectErr
	}()
	<-provider.startEntered
	if err := service.Cancel(context.Background(), "tenant-a", "connection-1", attempt.ID); !errors.Is(err, ErrAttemptBusy) {
		close(provider.startRelease)
		t.Fatalf("Cancel during selection = %v, want ErrAttemptBusy", err)
	}
	if provider.disposeCalls.Load() != 0 {
		close(provider.startRelease)
		t.Fatal("Cancel disposed a provider handle owned by selection")
	}
	close(provider.startRelease)
	if err := <-selected; err != nil {
		t.Fatalf("SelectDevice: %v", err)
	}
}

func TestCompleteReservationAllowsOnlyOneProviderCall(t *testing.T) {
	service, _, repository := newServiceFixture(t)
	provider := newBarrierProvider([]Device{{ID: "a", Label: "A"}})
	close(provider.startRelease)
	provider.completed = CompletedSession{Plaintext: []byte("finished-private-session"), DeviceFingerprint: make([]byte, 32)}
	service.provider = provider
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	first := make(chan error, 1)
	go func() {
		_, completeErr := service.Complete(context.Background(), "tenant-a", "connection-1", attempt.ID)
		first <- completeErr
	}()
	<-provider.completeEntered
	second := make(chan error, 1)
	go func() {
		_, completeErr := service.Complete(context.Background(), "tenant-a", "connection-1", attempt.ID)
		second <- completeErr
	}()
	select {
	case err := <-second:
		if !errors.Is(err, ErrAttemptBusy) {
			close(provider.completeRelease)
			t.Fatalf("second Complete = %v, want ErrAttemptBusy", err)
		}
	case <-provider.completeEntered:
		close(provider.completeRelease)
		t.Fatal("second Complete called the provider")
	case <-time.After(250 * time.Millisecond):
		close(provider.completeRelease)
		t.Fatal("second Complete blocked instead of returning ErrAttemptBusy")
	}
	if provider.completeCalls.Load() != 1 {
		close(provider.completeRelease)
		t.Fatalf("provider Complete calls = %d, want 1", provider.completeCalls.Load())
	}
	close(provider.completeRelease)
	if err := <-first; err != nil {
		t.Fatalf("first Complete: %v", err)
	}
}

func TestCompleteReservationExcludesCancelAndCommitSurvives(t *testing.T) {
	service, _, repository := newServiceFixture(t)
	provider := newBarrierProvider([]Device{{ID: "a", Label: "A"}})
	close(provider.startRelease)
	provider.completed = CompletedSession{Plaintext: []byte("finished-private-session"), DeviceFingerprint: make([]byte, 32)}
	service.provider = provider
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	completed := make(chan error, 1)
	go func() {
		_, completeErr := service.Complete(context.Background(), "tenant-a", "connection-1", attempt.ID)
		completed <- completeErr
	}()
	<-provider.completeEntered
	if err := service.Cancel(context.Background(), "tenant-a", "connection-1", attempt.ID); !errors.Is(err, ErrAttemptBusy) {
		close(provider.completeRelease)
		t.Fatalf("Cancel during Complete = %v, want ErrAttemptBusy", err)
	}
	if provider.disposeCalls.Load() != 0 {
		close(provider.completeRelease)
		t.Fatal("Cancel disposed the provider handle during Complete")
	}
	close(provider.completeRelease)
	if err := <-completed; err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if repository.state("tenant-a", "connection-1") != domain.ConnectionStateConnected {
		t.Fatal("reserved Complete did not commit")
	}
}

func TestExpirySkipsInUseAttemptUntilOperationFinishes(t *testing.T) {
	service, _, repository := newServiceFixture(t)
	provider := newBarrierProvider([]Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}})
	service.provider = provider
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	selected := make(chan error, 1)
	go func() {
		_, selectErr := service.SelectDevice(context.Background(), "tenant-a", "connection-1", attempt.ID, "a")
		selected <- selectErr
	}()
	<-provider.startEntered
	service.now = func() time.Time { return attempt.ExpiresAt.Add(time.Second) }
	if cleaned, err := service.SweepExpired(context.Background()); err != nil || cleaned != 0 {
		close(provider.startRelease)
		t.Fatalf("SweepExpired during selection = %d, %v", cleaned, err)
	}
	if provider.disposeCalls.Load() != 0 {
		close(provider.startRelease)
		t.Fatal("expiry disposed a handle owned by selection")
	}
	close(provider.startRelease)
	if err := <-selected; err != nil {
		t.Fatalf("SelectDevice: %v", err)
	}
	select {
	case <-provider.disposed:
	case <-time.After(time.Second):
		t.Fatal("expiry skipped the in-use operation but did not retry active cleanup")
	}
}

type barrierProvider struct {
	devices         []Device
	completed       CompletedSession
	startEntered    chan struct{}
	startRelease    chan struct{}
	completeEntered chan struct{}
	completeRelease chan struct{}
	completeCalls   atomic.Int32
	disposeCalls    atomic.Int32
	disposed        chan struct{}
}

func newBarrierProvider(devices []Device) *barrierProvider {
	return &barrierProvider{
		devices: devices, startEntered: make(chan struct{}, 2), startRelease: make(chan struct{}),
		completeEntered: make(chan struct{}, 2), completeRelease: make(chan struct{}),
		disposed: make(chan struct{}, 4),
	}
}

func (*barrierProvider) Name() string { return "gmessages" }
func (provider *barrierProvider) Discover(context.Context, Credentials) (any, []Device, error) {
	return &struct{}{}, append([]Device(nil), provider.devices...), nil
}
func (provider *barrierProvider) StartApproval(context.Context, any, string) (string, error) {
	provider.startEntered <- struct{}{}
	<-provider.startRelease
	return "fox", nil
}
func (provider *barrierProvider) Complete(context.Context, any) (CompletedSession, error) {
	provider.completeCalls.Add(1)
	provider.completeEntered <- struct{}{}
	<-provider.completeRelease
	return CompletedSession{
		Plaintext:         append([]byte(nil), provider.completed.Plaintext...),
		DeviceFingerprint: append([]byte(nil), provider.completed.DeviceFingerprint...),
	}, nil
}
func (provider *barrierProvider) Dispose(context.Context, any, bool) {
	provider.disposeCalls.Add(1)
	provider.disposed <- struct{}{}
}
