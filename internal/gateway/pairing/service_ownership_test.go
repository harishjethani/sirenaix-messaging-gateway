package pairing

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/session"
)

func TestSecondServiceCannotStealFreshDurablePairingAttempt(t *testing.T) {
	repository := &fakeRepository{connections: make(map[string]domain.Connection), eventIDs: make(map[string]string)}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository.databaseNow = now
	firstProvider := &fakeProvider{name: "gmessages", devices: []Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}}
	secondProvider := &fakeProvider{name: "gmessages", devices: firstProvider.devices}
	first := newOwnershipService(t, repository, firstProvider, func() time.Time { return now }, "attempt-first")
	second := newOwnershipService(t, repository, secondProvider, func() time.Time { return now.Add(12 * time.Hour) }, "attempt-second")

	started, err := first.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if _, err = second.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()}); !errors.Is(err, ErrAttemptActive) {
		t.Fatalf("second Start = %v, want ErrAttemptActive", err)
	}
	if owner := repository.owner("tenant-a", "connection-1"); owner != started.ID {
		t.Fatalf("durable owner = %q, want %q", owner, started.ID)
	}
	if secondProvider.discoverCalls != 0 {
		t.Fatal("fresh attempt ownership was checked only after exposing cookies to provider discovery")
	}
}

func TestStaleAttemptCanBeAtomicallyReplacedAndOldCleanupIsFenced(t *testing.T) {
	repository := &fakeRepository{connections: make(map[string]domain.Connection), eventIDs: make(map[string]string)}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository.databaseNow = now
	firstProvider := &fakeProvider{name: "gmessages", devices: []Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}}
	secondProvider := &fakeProvider{name: "gmessages", devices: firstProvider.devices}
	first := newOwnershipService(t, repository, firstProvider, func() time.Time { return now }, "attempt-first")
	second := newOwnershipService(t, repository, secondProvider, func() time.Time { return now.Add(6 * time.Minute) }, "attempt-second")

	oldAttempt, err := first.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	repository.databaseNow = now.Add(6 * time.Minute)
	newAttempt, err := second.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("stale replacement Start: %v", err)
	}
	if owner := repository.owner("tenant-a", "connection-1"); owner != newAttempt.ID {
		t.Fatalf("durable owner = %q, want %q", owner, newAttempt.ID)
	}
	if err = first.Cancel(context.Background(), "tenant-a", "connection-1", oldAttempt.ID); !errors.Is(err, ErrSessionPersistence) {
		t.Fatalf("old Cancel = %v, want ErrSessionPersistence", err)
	}
	if owner := repository.owner("tenant-a", "connection-1"); owner != newAttempt.ID || repository.state("tenant-a", "connection-1") != domain.ConnectionStatePairing {
		t.Fatalf("old cleanup changed new ownership: owner=%q state=%q", owner, repository.state("tenant-a", "connection-1"))
	}
	if _, err = first.get("tenant-a", "connection-1", oldAttempt.ID); !errors.Is(err, ErrAttemptNotFound) {
		t.Fatalf("superseded cleanup retained retry ownership: %v", err)
	}
}

func TestStaleAttemptLateCompletionCannotCommitOverNewOwner(t *testing.T) {
	repository := &fakeRepository{connections: make(map[string]domain.Connection), eventIDs: make(map[string]string)}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository.databaseNow = now
	firstProvider := &fakeProvider{
		name: "gmessages", devices: []Device{{ID: "a", Label: "A"}}, emoji: "fox",
		completed: CompletedSession{Plaintext: []byte("old-private-session"), DeviceFingerprint: make([]byte, 32)},
	}
	secondProvider := &fakeProvider{name: "gmessages", devices: []Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}}
	first := newOwnershipService(t, repository, firstProvider, func() time.Time { return now }, "attempt-first")
	second := newOwnershipService(t, repository, secondProvider, func() time.Time { return now.Add(6 * time.Minute) }, "attempt-second")

	oldAttempt, err := first.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	repository.databaseNow = now.Add(6 * time.Minute)
	newAttempt, err := second.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("stale replacement Start: %v", err)
	}
	if _, err = first.Complete(context.Background(), "tenant-a", "connection-1", oldAttempt.ID); !errors.Is(err, ErrSessionPersistence) {
		t.Fatalf("late Complete = %v, want ErrSessionPersistence", err)
	}
	if owner := repository.owner("tenant-a", "connection-1"); owner != newAttempt.ID || repository.state("tenant-a", "connection-1") != domain.ConnectionStatePairing {
		t.Fatalf("late commit changed new ownership: owner=%q state=%q", owner, repository.state("tenant-a", "connection-1"))
	}
	if len(repository.saved.Ciphertext) != 0 {
		t.Fatal("late completion persisted a session for the new owner")
	}
	if _, err = first.get("tenant-a", "connection-1", oldAttempt.ID); !errors.Is(err, ErrAttemptNotFound) {
		t.Fatalf("superseded completion retained retry ownership: %v", err)
	}
}

func TestGlobalReconciliationUsesRepositoryTimeAndFencesOldCleanup(t *testing.T) {
	repository := &fakeRepository{connections: make(map[string]domain.Connection), eventIDs: make(map[string]string)}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository.databaseNow = now
	firstProvider := &fakeProvider{name: "gmessages", devices: []Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}}
	secondProvider := &fakeProvider{name: "gmessages", devices: firstProvider.devices}
	first := newOwnershipService(t, repository, firstProvider, func() time.Time { return now }, "attempt-first")
	second := newOwnershipService(t, repository, secondProvider, func() time.Time { return now.Add(30 * time.Second) }, "attempt-second")

	oldAttempt, err := first.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	if count, err := second.ReconcileStalePairings(context.Background(), "tenant-a"); err != nil || count != 0 {
		t.Fatalf("immediate reconciliation = %d, %v", count, err)
	}
	if owner := repository.owner("tenant-a", "connection-1"); owner != oldAttempt.ID {
		t.Fatalf("fresh durable owner was erased: %q", owner)
	}
	repository.databaseNow = now.Add(6 * time.Minute)
	if count, err := second.ReconcileStalePairings(context.Background(), "tenant-a"); err != nil || count != 1 {
		t.Fatalf("expired reconciliation = %d, %v", count, err)
	}
	newAttempt, err := second.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start after reconciliation: %v", err)
	}
	if err = first.Cancel(context.Background(), "tenant-a", "connection-1", oldAttempt.ID); !errors.Is(err, ErrSessionPersistence) {
		t.Fatalf("old cleanup = %v", err)
	}
	if owner := repository.owner("tenant-a", "connection-1"); owner != newAttempt.ID {
		t.Fatalf("old cleanup changed reconciled replacement owner: %q", owner)
	}
}

func TestGlobalReconciliationFencesOldLateCompletion(t *testing.T) {
	repository := &fakeRepository{connections: make(map[string]domain.Connection), eventIDs: make(map[string]string)}
	repository.put(connection("tenant-a", "connection-1", domain.ConnectionStateUnpaired))
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	repository.databaseNow = now
	firstProvider := &fakeProvider{
		name: "gmessages", devices: []Device{{ID: "a", Label: "A"}}, emoji: "fox",
		completed: CompletedSession{Plaintext: []byte("old-private-session"), DeviceFingerprint: make([]byte, 32)},
	}
	secondProvider := &fakeProvider{name: "gmessages", devices: []Device{{ID: "a", Label: "A"}, {ID: "b", Label: "B"}}}
	first := newOwnershipService(t, repository, firstProvider, func() time.Time { return now }, "attempt-first")
	second := newOwnershipService(t, repository, secondProvider, func() time.Time { return now.Add(30 * time.Second) }, "attempt-second")

	oldAttempt, err := first.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	repository.databaseNow = now.Add(6 * time.Minute)
	if count, err := second.ReconcileStalePairings(context.Background(), "tenant-a"); err != nil || count != 1 {
		t.Fatalf("expired reconciliation = %d, %v", count, err)
	}
	newAttempt, err := second.Start(context.Background(), "tenant-a", "connection-1", Credentials{Cookies: validCookies()})
	if err != nil {
		t.Fatalf("Start after reconciliation: %v", err)
	}
	if _, err = first.Complete(context.Background(), "tenant-a", "connection-1", oldAttempt.ID); !errors.Is(err, ErrSessionPersistence) {
		t.Fatalf("old late Complete = %v", err)
	}
	if owner := repository.owner("tenant-a", "connection-1"); owner != newAttempt.ID || len(repository.saved.Ciphertext) != 0 {
		t.Fatalf("old completion changed reconciled replacement: owner=%q saved=%d", owner, len(repository.saved.Ciphertext))
	}
}

func TestServiceRejectsOutOfRangeAttemptTTL(t *testing.T) {
	provider := &fakeProvider{name: "gmessages"}
	repository := &fakeRepository{connections: make(map[string]domain.Connection), eventIDs: make(map[string]string)}
	manager, err := session.NewManager(&testWrapper{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for _, ttl := range []time.Duration{-time.Second, 24*time.Hour + time.Nanosecond} {
		if _, err = NewService(Dependencies{Provider: provider, Repository: repository, Sessions: manager, TTL: ttl}); !errors.Is(err, ErrInvalidDependencies) {
			t.Fatalf("NewService TTL %s = %v", ttl, err)
		}
	}
}

func newOwnershipService(t *testing.T, repository Repository, provider Provider, now func() time.Time, id string) *Service {
	t.Helper()
	manager, err := session.NewManager(&testWrapper{})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	service, err := NewService(Dependencies{
		Provider: provider, Repository: repository, Sessions: manager, Now: now,
		TTL: 5 * time.Minute, NewID: func() string { return id },
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

func (repository *fakeRepository) owner(tenant, connection string) string {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.pairingAttempt[tenant+"/"+connection]
}
