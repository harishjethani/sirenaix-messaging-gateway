package pairing

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/session"
)

func TestStartAtomicallyReplacesStalePairingRowAfterRestart(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.devices = []Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStatePairing))
	repository.pairingPrior = map[string]domain.ConnectionState{"tenant-a/connection-1": domain.ConnectionStateUnpaired}
	repository.pairingStarted = map[string]time.Time{"tenant-a/connection-1": time.Date(2026, 8, 23, 10, 0, 0, 0, time.UTC)}
	repository.pairingAttempt = map[string]string{"tenant-a/connection-1": "old-attempt"}

	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start after restart: %v", err)
	}
	if attempt.State != StateAwaitingDeviceSelection || repository.restoreCalls != 0 || repository.owner("tenant-a", "connection-1") != attempt.ID {
		t.Fatalf("attempt=%#v restore calls=%d owner=%q", attempt, repository.restoreCalls, repository.owner("tenant-a", "connection-1"))
	}
}

func TestActiveExpiryDisposesSecretsWithoutAnotherRequest(t *testing.T) {
	provider := newBarrierProvider([]Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}})
	repository := &fakeRepository{connections: make(map[string]domain.Connection), eventIDs: make(map[string]string)}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	manager, err := session.NewManager(&testWrapper{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	service, err := NewService(Dependencies{Provider: provider, Repository: repository, Sessions: manager, Now: time.Now, TTL: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	if _, err = service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()}); err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-provider.disposed:
	case <-time.After(time.Second):
		t.Fatal("active expiry did not dispose the secret-bearing handle")
	}
	if repository.state("tenant-a", "connection-1") != domain.ConnectionStateUnpaired {
		t.Fatal("active expiry did not restore the durable prior state")
	}
}

func TestCleanupFailureDisposesSecretsAndRetriesDurableRestore(t *testing.T) {
	service, provider, repository := newServiceFixture(t)
	provider.devices = []Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateReauthorizationRequired))
	attempt, err := service.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	repository.restoreErr = errors.New("database unavailable")
	if err = service.Cancel(context.Background(), "tenant-a", "connection-1", attempt.ID); !errors.Is(err, ErrSessionPersistence) {
		t.Fatalf("Cancel = %v", err)
	}
	active, getErr := service.get("tenant-a", "connection-1", attempt.ID)
	if getErr != nil {
		t.Fatalf("cleanup ownership was lost: %v", getErr)
	}
	active.mu.Lock()
	hasHandle := active.handle != nil
	cleanupPending := active.cleanupPending
	active.mu.Unlock()
	if hasHandle || !cleanupPending || provider.cancelCalls != 1 {
		t.Fatalf("handle=%v cleanup pending=%v dispose calls=%d", hasHandle, cleanupPending, provider.cancelCalls)
	}
	repository.restoreErr = nil
	if cleaned, sweepErr := service.SweepExpired(context.Background()); sweepErr != nil || cleaned != 1 {
		t.Fatalf("cleanup retry = %d, %v", cleaned, sweepErr)
	}
	if repository.state("tenant-a", "connection-1") != domain.ConnectionStateReauthorizationRequired {
		t.Fatal("reauthorization cleanup restored the wrong prior state")
	}
}

func TestStartupReconciliationRestoresOnlyStalePairingRows(t *testing.T) {
	service, _, repository := newServiceFixture(t)
	now := time.Now()
	repository.put(connection("tenant-a", "old", domain.ConnectionStatePairing))
	repository.put(connection("tenant-a", "new", domain.ConnectionStatePairing))
	repository.pairingPrior = map[string]domain.ConnectionState{
		"tenant-a/old": domain.ConnectionStateUnpaired,
		"tenant-a/new": domain.ConnectionStateReauthorizationRequired,
	}
	repository.pairingStarted = map[string]time.Time{
		"tenant-a/old": now.Add(-time.Hour),
		"tenant-a/new": now,
	}
	repository.pairingAttempt = map[string]string{"tenant-a/old": "attempt-old", "tenant-a/new": "attempt-new"}
	repository.databaseNow = now
	restored, err := service.ReconcileStalePairings(context.Background(), "tenant-a")
	if err != nil || restored != 1 {
		t.Fatalf("ReconcileStalePairings = %d, %v", restored, err)
	}
	if repository.state("tenant-a", "old") != domain.ConnectionStateUnpaired || repository.state("tenant-a", "new") != domain.ConnectionStatePairing {
		t.Fatal("startup reconciliation restored the wrong rows")
	}
}
