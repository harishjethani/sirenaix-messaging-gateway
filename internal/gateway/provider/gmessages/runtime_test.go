package gmessages

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-gmessages/internal/gateway/connectionactor"
	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/ingress"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/events"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

type lineRuntimeClient struct {
	authorizationRefreshClient
	eventHandler libgm.EventHandler
}

func (client *lineRuntimeClient) SetEventHandler(handler libgm.EventHandler) {
	client.eventHandler = handler
}

type fullSizeRuntimeClient struct {
	lineRuntimeClient
	release  chan struct{}
	mu       sync.Mutex
	requests []string
	ctxs     []context.Context
	called   chan struct{}
}

func (client *fullSizeRuntimeClient) GetFullSizeImage(ctx context.Context, messageID, actionMessageID string) (*gmproto.GetFullSizeImageResponse, error) {
	client.mu.Lock()
	client.requests = append(client.requests, messageID+"/"+actionMessageID)
	client.ctxs = append(client.ctxs, ctx)
	client.mu.Unlock()
	client.called <- struct{}{}
	select {
	case <-client.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &gmproto.GetFullSizeImageResponse{}, nil
}

func thumbnailOnlyMessage(messageID string, part *gmproto.MediaContent, actionMessageID string) *libgm.WrappedMessage {
	info := &gmproto.MessageInfo{Data: &gmproto.MessageInfo_MediaContent{MediaContent: part}}
	if actionMessageID != "" {
		info.ActionMessageID = &actionMessageID
	}
	return &libgm.WrappedMessage{Message: &gmproto.Message{
		MessageID: messageID, ConversationID: "conversation-a", MessageInfo: []*gmproto.MessageInfo{info},
	}}
}

// Thumbnail-only RCS images must trigger exactly one asynchronous full-size request
// per attachment; the event handler runs on the long-poll goroutine and must not block.
func TestRuntimeRequestsFullSizeImageOnceWithoutBlockingEventHandler(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	client := &fullSizeRuntimeClient{release: make(chan struct{}), called: make(chan struct{}, 8)}
	factory := &RuntimeFactory{
		logger:    zerolog.Nop(),
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client },
	}
	ctx := connectionactor.ContextWithProviderOwnership(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9, LeaseTTL: 30 * time.Second,
	})
	restored, err := factory.Restore(ctx, plaintext, connectionactor.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	thumbnail := &gmproto.MediaContent{ThumbnailMediaID: "thumbnail-a", MimeType: "image/jpeg"}

	returned := make(chan struct{})
	go func() {
		client.eventHandler(thumbnailOnlyMessage("provider-a", thumbnail, "action-a"))
		client.eventHandler(thumbnailOnlyMessage("provider-a", thumbnail, "action-a")) // redelivery
		client.eventHandler(thumbnailOnlyMessage("provider-b", &gmproto.MediaContent{MediaID: "media-b", ThumbnailMediaID: "thumbnail-b"}, "action-b"))
		client.eventHandler(thumbnailOnlyMessage("provider-c", &gmproto.MediaContent{ThumbnailMediaID: "thumbnail-c"}, ""))
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("event handler blocked on the full-size request")
	}
	select {
	case <-client.called:
	case <-time.After(2 * time.Second):
		t.Fatal("full-size image was not requested")
	}
	close(client.release)
	time.Sleep(50 * time.Millisecond)
	client.mu.Lock()
	requests := append([]string(nil), client.requests...)
	requestCtx := client.ctxs[0]
	client.mu.Unlock()
	if len(requests) != 1 || requests[0] != "provider-a/action-a" {
		t.Fatalf("full-size requests = %q", requests)
	}
	if err := restored.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requestCtx.Err() == nil {
		t.Fatal("full-size request context outlived the provider generation")
	}
}

func TestRuntimeNeverPerformsPostCommitSettingsLineWrite(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	client := &lineRuntimeClient{}
	factory := &RuntimeFactory{
		logger:    zerolog.Nop(),
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client },
	}
	ctx := connectionactor.ContextWithProviderOwnership(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9, LeaseTTL: 30 * time.Second,
	})
	restored, err := factory.Restore(ctx, plaintext, connectionactor.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	settings := &gmproto.Settings{SIMCards: []*gmproto.SIMCard{{
		SIMParticipant: &gmproto.SIMParticipant{ID: "outgoing-a"},
		SIMData: &gmproto.SIMData{
			InternationalPhoneNumber: "+12025550101", CarrierName: "Carrier A", ColorHex: "#123456",
			SIMPayload: &gmproto.SIMPayload{SIMNumber: 2, Two: 7},
		},
		RCSChats: &gmproto.RCSChats{Enabled: true},
	}}}
	client.eventHandler(settings)
	client.eventHandler(&libgm.AuthenticatedSettings{Settings: settings, IsOld: true})
	client.eventHandler(&libgm.AuthenticatedSettings{Settings: settings})
	if failure := restored.(*runtimeProvider).terminalFailure(); failure != nil {
		t.Fatalf("ignored compatibility Settings event produced runtime failure: %v", failure)
	}
}

func TestRuntimeMapsInitialRefreshAuthorizationCause(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatalf("EncodeSession() error = %v", err)
	}
	auth.ClearSecrets()
	client := &authorizationRefreshClient{connectErr: fmt.Errorf("refresh failed: %w", events.HTTPError{
		Action: "refreshing authentication", StatusCode: http.StatusUnauthorized, Classification: "authorization",
	})}
	factory := &RuntimeFactory{
		logger: zerolog.Nop(),
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient {
			return client
		},
	}
	provider, err := factory.Restore(context.Background(), plaintext, connectionactor.Hooks{})
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if err = provider.Connect(context.Background()); !errors.Is(err, connectionactor.ErrProviderAuthorization) {
		t.Fatalf("Connect() error = %v, want ErrProviderAuthorization", err)
	}
}

func TestRuntimeInitialRefreshAuthorizationTransitionsActorOnceWithoutReconnect(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatalf("EncodeSession() error = %v", err)
	}
	auth.ClearSecrets()
	store := &runtimeAuthorizationStore{}
	var clients atomic.Int32
	factory := &RuntimeFactory{
		logger: zerolog.Nop(),
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient {
			clients.Add(1)
			return &authorizationRefreshClient{connectErr: fmt.Errorf("refresh failed: %w", events.HTTPError{
				Action: "refreshing authentication", StatusCode: http.StatusForbidden, Classification: "authorization",
			})}
		},
	}
	actor, err := connectionactor.NewActor(connectionactor.ActorConfig{
		OwnerID: "owner-a", Store: store,
		Sessions:  &runtimeAuthorizationSessions{snapshot: connectionactor.SessionSnapshot{Plaintext: plaintext, Revision: 3}},
		Providers: factory,
	})
	if err != nil {
		t.Fatalf("NewActor() error = %v", err)
	}
	if err = actor.Run(context.Background(), connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-1"}); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got := store.reauthorizationCalls.Load(); got != 1 {
		t.Fatalf("reauthorization transitions = %d, want 1", got)
	}
	if got := clients.Load(); got != 1 {
		t.Fatalf("runtime client generations = %d, want 1", got)
	}
	health := store.lastHealth()
	if health.ConnectionState != domain.ConnectionStateReauthorizationRequired || !health.RequiresReauthorization || health.LastSafeReason != connectionactor.ReasonProviderAuth {
		t.Fatalf("authorization health = %#v", health)
	}
}

func TestRuntimeBindsDurableEnvelopeAndACKToActorOwnership(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	client := &durableRuntimeClient{authorizationRefreshClient: authorizationRefreshClient{}}
	sink := &runtimeDurableSink{pending: []string{"response-pending-after-crash"}}
	factory := &RuntimeFactory{
		logger: zerolog.Nop(), durable: sink,
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client },
	}
	ownership := connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 77, LeaseTTL: 30 * time.Second,
	}
	ctx := connectionactor.ContextWithProviderOwnership(context.Background(), ownership)
	if _, err = factory.Restore(ctx, plaintext, connectionactor.Hooks{}); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if client.envelope == nil || client.coordinator == nil {
		t.Fatal("runtime did not install durable handlers")
	}
	client.hooks.OnReady()
	if outcome, envelopeErr := client.envelope(context.Background(), libgm.DurableEnvelope{ResponseID: "response-a", Raw: []byte("raw")}); envelopeErr != nil || outcome != libgm.DurableOutcomeCommitted {
		t.Fatalf("durable envelope = (%v, %v)", outcome, envelopeErr)
	}
	ackResult, ackErr := client.coordinator(context.Background(), []string{"response-a"}, func(context.Context, []string) error { return nil })
	if ackErr != nil || ackResult.ProviderError != nil {
		t.Fatalf("coordinated ACK = (%+v, %v)", ackResult, ackErr)
	}
	if sink.ownership != ownership || sink.responseID != "response-a" || len(sink.acked) != 1 || sink.acked[0] != "response-a" ||
		len(client.queued) == 0 || client.queued[0] != "response-pending-after-crash" {
		t.Fatalf("sink = %+v queued=%v", sink, client.queued)
	}
}

type durableRuntimeClient struct {
	authorizationRefreshClient
	envelope    libgm.DurableEnvelopeHandler
	failure     libgm.DurableFailureObserver
	coordinator libgm.ACKCoordinator
	hooks       libgm.LifecycleHooks
	queued      []string
}

func (client *durableRuntimeClient) SetDurableEnvelopeHandler(handler libgm.DurableEnvelopeHandler) {
	client.envelope = handler
}
func (client *durableRuntimeClient) SetDurableFailureObserver(observer libgm.DurableFailureObserver) {
	client.failure = observer
}
func (client *durableRuntimeClient) SetACKCoordinator(coordinator libgm.ACKCoordinator) {
	client.coordinator = coordinator
}
func (client *durableRuntimeClient) SetLifecycleHooks(hooks libgm.LifecycleHooks) {
	client.hooks = hooks
}
func (client *durableRuntimeClient) QueueDurableACKs(ids []string) error {
	client.queued = append(client.queued, ids...)
	return nil
}

type failureRuntimeClient struct {
	durableRuntimeClient
	connected chan struct{}
	stopped   chan struct{}
	stopOnce  sync.Once
}

type priorityRuntimeClient struct {
	durableRuntimeClient
	connected         chan struct{}
	disconnectStarted chan struct{}
	releaseDisconnect chan struct{}
	stopped           chan struct{}
	eventHandler      libgm.EventHandler
	connectOnce       sync.Once
	disconnectOnce    sync.Once
}

func (client *priorityRuntimeClient) ConnectContext(context.Context) error {
	client.connectOnce.Do(func() { close(client.connected) })
	return nil
}
func (client *priorityRuntimeClient) WaitContext(context.Context) error {
	<-client.stopped
	return nil
}
func (client *priorityRuntimeClient) DisconnectContext(context.Context) error {
	client.disconnectOnce.Do(func() {
		close(client.disconnectStarted)
		<-client.releaseDisconnect
		close(client.stopped)
	})
	return nil
}
func (client *priorityRuntimeClient) SetEventHandler(handler libgm.EventHandler) {
	client.eventHandler = handler
}
func (*priorityRuntimeClient) SnapshotSession() (*libgm.AuthData, *libgm.PushKeys) {
	return validSessionAuth(), nil
}

func TestRuntimeDisconnectJoinReturnsStrongestConcurrentTerminalFailure(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	client := &priorityRuntimeClient{
		connected: make(chan struct{}), disconnectStarted: make(chan struct{}),
		releaseDisconnect: make(chan struct{}), stopped: make(chan struct{}),
	}
	factory := &RuntimeFactory{
		logger: zerolog.Nop(), durable: &runtimeDurableSink{},
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client },
	}
	ctx := connectionactor.ContextWithProviderOwnership(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 3, LeaseTTL: 30 * time.Second,
	})
	provider, err := factory.Restore(ctx, plaintext, connectionactor.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- provider.Connect(context.Background()) }()
	<-client.connected
	client.eventHandler(&events.GaiaLoggedOut{})
	<-client.disconnectStarted
	client.failure(libgm.ErrDurablePoisoned)
	close(client.releaseDisconnect)
	select {
	case connectErr := <-done:
		if !errors.Is(connectErr, libgm.ErrDurablePoisoned) || !errors.Is(connectErr, connectionactor.ErrProviderPermanentProtocol) {
			t.Fatalf("concurrent terminal failure = %v, want permanent durable poison", connectErr)
		}
		if errors.Is(connectErr, connectionactor.ErrProviderAuthorization) {
			t.Fatalf("weaker authorization failure won terminal race: %v", connectErr)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not join after concurrent terminal failures")
	}
}

func TestRuntimeCancellationStillReturnsPoisonCommittedDuringDisconnectJoin(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	client := &priorityRuntimeClient{
		connected: make(chan struct{}), disconnectStarted: make(chan struct{}),
		releaseDisconnect: make(chan struct{}), stopped: make(chan struct{}),
	}
	factory := &RuntimeFactory{
		logger: zerolog.Nop(), durable: &runtimeDurableSink{},
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client },
	}
	ctx := connectionactor.ContextWithProviderOwnership(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 3, LeaseTTL: 30 * time.Second,
	})
	provider, err := factory.Restore(ctx, plaintext, connectionactor.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	connectCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- provider.Connect(connectCtx) }()
	<-client.connected
	cancel()
	<-client.disconnectStarted
	client.failure(libgm.ErrDurablePoisoned)
	close(client.releaseDisconnect)
	select {
	case connectErr := <-done:
		if !errors.Is(connectErr, libgm.ErrDurablePoisoned) || !errors.Is(connectErr, connectionactor.ErrProviderPermanentProtocol) {
			t.Fatalf("cancel-first terminal failure = %v, want permanent durable poison", connectErr)
		}
		if errors.Is(connectErr, context.Canceled) {
			t.Fatalf("cancellation masked durable poison: %v", connectErr)
		}
	case <-time.After(time.Second):
		t.Fatal("runtime did not join after cancel-first durable poison")
	}
}

func TestRuntimeCancellationPoisonDuringJoinTombstonesActorPool(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	client := &priorityRuntimeClient{
		connected: make(chan struct{}), disconnectStarted: make(chan struct{}),
		releaseDisconnect: make(chan struct{}), stopped: make(chan struct{}),
	}
	factory := &RuntimeFactory{
		logger: zerolog.Nop(), durable: &runtimeDurableSink{},
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client },
	}
	store := &runtimeAuthorizationStore{}
	sessions := &runtimeAuthorizationSessions{snapshot: connectionactor.SessionSnapshot{Plaintext: plaintext, Revision: 3}}
	var actorCreations atomic.Int32
	pool, err := connectionactor.NewPool(connectionactor.PoolConfig{NewActor: func(connectionactor.Key) (connectionactor.RunnerExecutor, error) {
		actorCreations.Add(1)
		return connectionactor.NewActor(connectionactor.ActorConfig{OwnerID: "owner-a", Store: store, Sessions: sessions, Providers: factory})
	}})
	if err != nil {
		t.Fatal(err)
	}
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-1"}
	runCtx, cancel := context.WithCancel(context.Background())
	if err = pool.Start(runCtx, key); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.connected:
	case <-time.After(time.Second):
		t.Fatal("actor runtime did not connect")
	}
	client.hooks.OnReady()
	cancel()
	select {
	case <-client.disconnectStarted:
	case <-time.After(time.Second):
		t.Fatal("actor runtime did not start disconnect join")
	}
	client.failure(libgm.ErrDurablePoisoned)
	close(client.releaseDisconnect)
	deadline := time.Now().Add(time.Second)
	for {
		startErr := pool.Start(context.Background(), key)
		if errors.Is(startErr, connectionactor.ErrProviderPermanentProtocol) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancel-first poison was not retained by pool: %v", startErr)
		}
		time.Sleep(time.Millisecond)
	}
	if got := actorCreations.Load(); got != 1 {
		t.Fatalf("cancel-first poisoned actor was recreated %d times", got)
	}
	if health := store.lastHealth(); health.LastSafeReason != connectionactor.ReasonProviderProtocol || health.ActorState != "stopped" {
		t.Fatalf("cancel-first poisoned actor health = %#v", health)
	}
}

func TestRuntimePoisonSurvivesFinalSessionCASFailureIntoActorPool(t *testing.T) {
	for _, fixture := range []struct {
		name    string
		swapErr error
	}{
		{name: "fence rejected"},
		{name: "repository error", swapErr: errors.New("session CAS unavailable")},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			auth := validSessionAuth()
			plaintext, err := EncodeSession(auth, nil)
			if err != nil {
				t.Fatal(err)
			}
			auth.ClearSecrets()
			client := &priorityRuntimeClient{
				connected: make(chan struct{}), disconnectStarted: make(chan struct{}),
				releaseDisconnect: make(chan struct{}), stopped: make(chan struct{}),
			}
			factory := &RuntimeFactory{
				logger: zerolog.Nop(), durable: &runtimeDurableSink{},
				newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client },
			}
			store := &runtimeAuthorizationStore{}
			sessions := &runtimeAuthorizationSessions{
				snapshot: connectionactor.SessionSnapshot{Plaintext: plaintext, Revision: 3}, swapErr: fixture.swapErr,
			}
			var actorCreations atomic.Int32
			pool, err := connectionactor.NewPool(connectionactor.PoolConfig{NewActor: func(connectionactor.Key) (connectionactor.RunnerExecutor, error) {
				actorCreations.Add(1)
				return connectionactor.NewActor(connectionactor.ActorConfig{OwnerID: "owner-a", Store: store, Sessions: sessions, Providers: factory})
			}})
			if err != nil {
				t.Fatal(err)
			}
			key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-1"}
			runCtx, cancel := context.WithCancel(context.Background())
			if err = pool.Start(runCtx, key); err != nil {
				t.Fatal(err)
			}
			select {
			case <-client.connected:
			case <-time.After(time.Second):
				t.Fatal("actor runtime did not connect")
			}
			client.hooks.OnReady()
			client.hooks.OnSessionChange()
			cancel()
			select {
			case <-client.disconnectStarted:
			case <-time.After(time.Second):
				t.Fatal("actor runtime did not start disconnect join")
			}
			client.failure(libgm.ErrDurablePoisoned)
			close(client.releaseDisconnect)
			deadline := time.Now().Add(time.Second)
			for {
				startErr := pool.Start(context.Background(), key)
				if errors.Is(startErr, connectionactor.ErrProviderPermanentProtocol) {
					break
				}
				if time.Now().After(deadline) || actorCreations.Load() > 1 {
					t.Fatalf("session CAS failure discarded poison tombstone: start=%v creations=%d", startErr, actorCreations.Load())
				}
				time.Sleep(time.Millisecond)
			}
			if health := store.lastHealth(); health.LastSafeReason != connectionactor.ReasonProviderProtocol {
				t.Fatalf("session CAS poison health = %#v", health)
			}
		})
	}
}

func TestRuntimePermanentPoisonDominatesConcurrentStaleDurableFailure(t *testing.T) {
	provider := &runtimeProvider{}
	provider.signalFailure(&durablePersistenceFailureForTest{cause: ErrDurableFenceLost})
	provider.signalFailure(libgm.ErrDurablePoisoned)
	failure := provider.terminalFailure()
	if !errors.Is(failure, libgm.ErrDurablePoisoned) || !errors.Is(failure, connectionactor.ErrProviderPermanentProtocol) {
		t.Fatalf("strongest terminal failure = %v, want permanent poison", failure)
	}
	if errors.Is(failure, connectionactor.ErrStaleGeneration) {
		t.Fatalf("stale generation masked permanent poison: %v", failure)
	}
}

func TestRuntimeACKAdmissionCongestionDoesNotTerminateProvider(t *testing.T) {
	provider := &runtimeProvider{}
	provider.signalFailure(&durablePersistenceFailureForTest{cause: errors.Join(ErrACKAdmissionLimited, context.DeadlineExceeded)})
	if failure := provider.terminalFailure(); failure != nil {
		t.Fatalf("local ACK admission congestion became terminal: %v", failure)
	}
}

func (client *failureRuntimeClient) ConnectContext(context.Context) error {
	close(client.connected)
	return nil
}
func (client *failureRuntimeClient) WaitContext(ctx context.Context) error {
	select {
	case <-client.stopped:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (client *failureRuntimeClient) DisconnectContext(context.Context) error {
	client.stopOnce.Do(func() { close(client.stopped) })
	return nil
}

func TestRuntimeUnsolicitedDurableFailureMakesActorGenerationUnhealthy(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	client := &failureRuntimeClient{connected: make(chan struct{}), stopped: make(chan struct{})}
	factory := &RuntimeFactory{logger: zerolog.Nop(), durable: &runtimeDurableSink{}, newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client }}
	ctx := connectionactor.ContextWithProviderOwnership(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 3, LeaseTTL: 30 * time.Second,
	})
	provider, err := factory.Restore(ctx, plaintext, connectionactor.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- provider.Connect(context.Background()) }()
	<-client.connected
	if client.failure == nil {
		t.Fatal("durable failure observer was not installed")
	}
	databaseFailure := errors.New("durable inbox unavailable")
	client.failure(&durablePersistenceFailureForTest{cause: databaseFailure})
	select {
	case connectErr := <-done:
		if !errors.Is(connectErr, libgm.ErrDurablePersistence) || !errors.Is(connectErr, databaseFailure) {
			t.Fatalf("Connect() durable failure = %v", connectErr)
		}
	case <-time.After(time.Second):
		t.Fatal("durable failure did not stop the provider generation")
	}
}

func TestRuntimeUnmatchedCommittedPoisonStopsOnlyProviderGeneration(t *testing.T) {
	provider := &runtimeProvider{}
	provider.signalFailure(libgm.ErrDurablePoisoned)
	failure := provider.terminalFailure()
	if !errors.Is(failure, libgm.ErrDurablePoisoned) || !errors.Is(failure, connectionactor.ErrProviderPermanentProtocol) {
		t.Fatalf("unmatched poison classification = %v", failure)
	}
	if errors.Is(failure, connectionactor.ErrSharedInfrastructure) {
		t.Fatalf("provider poison stopped shared infrastructure: %v", failure)
	}
}

func TestRuntimeUnmatchedCommittedPoisonTombstonesActorPool(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	client := &failureRuntimeClient{connected: make(chan struct{}), stopped: make(chan struct{})}
	factory := &RuntimeFactory{
		logger: zerolog.Nop(), durable: &runtimeDurableSink{},
		newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client },
	}
	store := &runtimeAuthorizationStore{}
	sessions := &runtimeAuthorizationSessions{snapshot: connectionactor.SessionSnapshot{Plaintext: plaintext, Revision: 3}}
	var actorCreations atomic.Int32
	pool, err := connectionactor.NewPool(connectionactor.PoolConfig{NewActor: func(connectionactor.Key) (connectionactor.RunnerExecutor, error) {
		actorCreations.Add(1)
		return connectionactor.NewActor(connectionactor.ActorConfig{OwnerID: "owner-a", Store: store, Sessions: sessions, Providers: factory})
	}})
	if err != nil {
		t.Fatal(err)
	}
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-1"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = pool.Start(ctx, key); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.connected:
	case <-time.After(time.Second):
		t.Fatal("actor runtime did not connect")
	}
	client.hooks.OnReady()
	readyDeadline := time.Now().Add(time.Second)
	for !pool.Ready(context.Background(), key) {
		if time.Now().After(readyDeadline) {
			t.Fatal("actor did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	client.failure(libgm.ErrDurablePoisoned)
	deadline := time.Now().Add(time.Second)
	for {
		startErr := pool.Start(ctx, key)
		if errors.Is(startErr, connectionactor.ErrProviderPermanentProtocol) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("pool did not retain provider-protocol tombstone: %v", startErr)
		}
		time.Sleep(time.Millisecond)
	}
	if got := actorCreations.Load(); got != 1 {
		t.Fatalf("poisoned actor was recreated %d times", got)
	}
	if pool.Ready(context.Background(), key) {
		t.Fatal("poisoned actor remained ready")
	}
	if health := store.lastHealth(); health.LastSafeReason != connectionactor.ReasonProviderProtocol || health.ActorState != "stopped" {
		t.Fatalf("poisoned actor health = %#v", health)
	}
}

func TestRuntimeDurableFenceLossDoesNotMasqueradeAsSharedInfrastructure(t *testing.T) {
	provider := &runtimeProvider{}
	provider.signalFailure(&durablePersistenceFailureForTest{cause: ErrDurableFenceLost})
	failure := provider.terminalFailure()
	if !errors.Is(failure, libgm.ErrDurablePersistence) || !errors.Is(failure, ErrDurableFenceLost) {
		t.Fatalf("durable fence failure = %v", failure)
	}
	if !errors.Is(failure, connectionactor.ErrStaleGeneration) || errors.Is(failure, connectionactor.ErrSharedInfrastructure) {
		t.Fatalf("stale connection fence classification = %v", failure)
	}
}

func TestRuntimeEnvelopeConflictIsProviderLocalNotSharedInfrastructure(t *testing.T) {
	provider := &runtimeProvider{}
	provider.signalFailure(&durablePersistenceFailureForTest{cause: ingress.ErrConflictingEnvelope})
	failure := provider.terminalFailure()
	if !errors.Is(failure, ingress.ErrConflictingEnvelope) || !errors.Is(failure, connectionactor.ErrProviderPermanentProtocol) {
		t.Fatalf("conflicting envelope classification = %v", failure)
	}
	if errors.Is(failure, connectionactor.ErrSharedInfrastructure) {
		t.Fatalf("provider-local conflict classified shared: %v", failure)
	}
}

func TestRuntimeLegacyInvalidPendingACKIsProviderLocalNotSharedInfrastructure(t *testing.T) {
	provider := &runtimeProvider{}
	provider.signalFailure(&durablePersistenceFailureForTest{cause: ingress.ErrInvalidProviderResponseID})
	failure := provider.terminalFailure()
	if !errors.Is(failure, ingress.ErrInvalidProviderResponseID) || !errors.Is(failure, connectionactor.ErrProviderPermanentProtocol) {
		t.Fatalf("legacy invalid pending ACK classification = %v", failure)
	}
	if errors.Is(failure, connectionactor.ErrSharedInfrastructure) {
		t.Fatalf("legacy provider-local corruption classified shared: %v", failure)
	}
}

func TestRuntimePendingACKRepositoryFailurePreservesSharedInfrastructureCause(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	databaseFailure := errors.New("pending ACK repository unavailable")
	sink := &runtimeDurableSink{pendingErr: errors.Join(ErrDurableInfrastructure, databaseFailure)}
	client := &failureRuntimeClient{connected: make(chan struct{}), stopped: make(chan struct{})}
	factory := &RuntimeFactory{logger: zerolog.Nop(), durable: sink, newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client }}
	ctx := connectionactor.ContextWithProviderOwnership(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 3, LeaseTTL: 30 * time.Second,
	})
	provider, err := factory.Restore(ctx, plaintext, connectionactor.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- provider.Connect(context.Background()) }()
	<-client.connected
	client.hooks.OnReady()
	select {
	case connectErr := <-done:
		if !errors.Is(connectErr, connectionactor.ErrSharedInfrastructure) || !errors.Is(connectErr, databaseFailure) {
			t.Fatalf("PendingACKs failure = %v", connectErr)
		}
	case <-time.After(time.Second):
		t.Fatal("PendingACKs infrastructure failure did not stop the actor runtime")
	}
}

func TestRuntimeOnReadyBareInvalidPendingACKIsProviderLocalPermanent(t *testing.T) {
	auth := validSessionAuth()
	plaintext, err := EncodeSession(auth, nil)
	if err != nil {
		t.Fatal(err)
	}
	auth.ClearSecrets()
	sink := &runtimeDurableSink{pendingErr: errors.Join(ingress.ErrInvalidProviderResponseID, domain.ErrInvalidIdentifier)}
	client := &failureRuntimeClient{connected: make(chan struct{}), stopped: make(chan struct{})}
	factory := &RuntimeFactory{logger: zerolog.Nop(), durable: sink, newClient: func(*libgm.AuthData, *libgm.PushKeys, zerolog.Logger) runtimeClient { return client }}
	ctx := connectionactor.ContextWithProviderOwnership(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 3, LeaseTTL: 30 * time.Second,
	})
	provider, err := factory.Restore(ctx, plaintext, connectionactor.Hooks{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- provider.Connect(context.Background()) }()
	<-client.connected
	client.hooks.OnReady()
	select {
	case connectErr := <-done:
		if !errors.Is(connectErr, ingress.ErrInvalidProviderResponseID) || !errors.Is(connectErr, connectionactor.ErrProviderPermanentProtocol) {
			t.Fatalf("bare invalid PendingACKs error = %v", connectErr)
		}
		if errors.Is(connectErr, connectionactor.ErrSharedInfrastructure) {
			t.Fatalf("bare invalid PendingACKs error became shared: %v", connectErr)
		}
	case <-time.After(time.Second):
		t.Fatal("bare invalid PendingACKs corruption did not stop the provider generation")
	}
}

type durablePersistenceFailureForTest struct{ cause error }

func (failure *durablePersistenceFailureForTest) Error() string {
	return libgm.ErrDurablePersistence.Error()
}
func (failure *durablePersistenceFailureForTest) Unwrap() error { return failure.cause }
func (failure *durablePersistenceFailureForTest) Is(target error) bool {
	return target == libgm.ErrDurablePersistence
}

type runtimeDurableSink struct {
	ownership  connectionactor.ProviderOwnership
	responseID string
	acked      []string
	pending    []string
	pendingErr error
}

func (sink *runtimeDurableSink) PersistEnvelopeOutcome(_ context.Context, ownership connectionactor.ProviderOwnership, envelope libgm.DurableEnvelope) (libgm.DurableOutcome, error) {
	sink.ownership, sink.responseID = ownership, envelope.ResponseID
	return libgm.DurableOutcomeCommitted, nil
}

func (sink *runtimeDurableSink) MarkACKed(_ context.Context, ownership connectionactor.ProviderOwnership, ids []string) error {
	sink.ownership, sink.acked = ownership, append([]string(nil), ids...)
	return nil
}

func (*runtimeDurableSink) ACKTimeout() time.Duration { return DefaultACKCoordinationTimeout }

func (sink *runtimeDurableSink) CoordinateACKs(ctx context.Context, ownership connectionactor.ProviderOwnership, ids []string, send libgm.ACKBatchSender) (libgm.ACKCoordinationResult, error) {
	sink.ownership = ownership
	result := libgm.ACKCoordinationResult{AdmittedIDs: append([]string(nil), ids...)}
	if err := send(ctx, append([]string(nil), ids...)); err != nil {
		result.ProviderError = err
		result.RetryIDs = append([]string(nil), ids...)
		return result, nil
	}
	sink.acked = append([]string(nil), ids...)
	return result, nil
}

func (sink *runtimeDurableSink) PendingACKs(_ context.Context, ownership connectionactor.ProviderOwnership, _ int) ([]string, error) {
	sink.ownership = ownership
	if sink.pendingErr != nil {
		return nil, sink.pendingErr
	}
	return append([]string(nil), sink.pending...), nil
}

type authorizationRefreshClient struct {
	connectErr error
}

func (client *authorizationRefreshClient) ConnectContext(context.Context) error {
	return client.connectErr
}
func (*authorizationRefreshClient) DisconnectContext(context.Context) error { return nil }
func (*authorizationRefreshClient) WaitContext(context.Context) error       { return nil }
func (*authorizationRefreshClient) SetLifecycleHooks(libgm.LifecycleHooks)  {}
func (*authorizationRefreshClient) SetEventHandler(libgm.EventHandler)      {}
func (*authorizationRefreshClient) SnapshotSession() (*libgm.AuthData, *libgm.PushKeys) {
	return nil, nil
}
func (*authorizationRefreshClient) ClearSessionSecrets() {}

type runtimeAuthorizationStore struct {
	mu                   sync.Mutex
	health               []connectionactor.Health
	reauthorizationCalls atomic.Int32
}

func (*runtimeAuthorizationStore) GetConnection(context.Context, domain.TenantID, domain.ConnectionID) (domain.Connection, error) {
	return domain.Connection{ID: "connection-1", TenantID: "tenant-a", Name: "Phone", State: domain.ConnectionStateConnected}, nil
}
func (*runtimeAuthorizationStore) AcquireConnectionLease(context.Context, domain.TenantID, domain.ConnectionID, string, time.Duration) (connectionactor.Lease, bool, error) {
	return connectionactor.Lease{OwnerID: "owner-a", FencingToken: 5, ExpiresAt: time.Now().Add(time.Minute)}, true, nil
}
func (*runtimeAuthorizationStore) RenewConnectionLease(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, time.Duration) (bool, error) {
	return true, nil
}
func (*runtimeAuthorizationStore) ReleaseConnectionLease(context.Context, domain.TenantID, domain.ConnectionID, string, uint64) (bool, error) {
	return true, nil
}
func (store *runtimeAuthorizationStore) WriteConnectionHealthFenced(_ context.Context, _ domain.TenantID, _ domain.ConnectionID, _ string, _ uint64, health connectionactor.Health) (bool, error) {
	store.mu.Lock()
	store.health = append(store.health, health)
	store.mu.Unlock()
	return true, nil
}
func (store *runtimeAuthorizationStore) MarkReauthorizationRequiredFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64) (bool, error) {
	store.reauthorizationCalls.Add(1)
	return true, nil
}
func (store *runtimeAuthorizationStore) lastHealth() connectionactor.Health {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.health[len(store.health)-1]
}

type runtimeAuthorizationSessions struct {
	snapshot connectionactor.SessionSnapshot
	swapErr  error
}

func (sessions *runtimeAuthorizationSessions) LoadVersioned(context.Context, connectionactor.Key) (connectionactor.SessionSnapshot, error) {
	return connectionactor.SessionSnapshot{Plaintext: append([]byte(nil), sessions.snapshot.Plaintext...), Revision: sessions.snapshot.Revision}, nil
}
func (sessions *runtimeAuthorizationSessions) CompareAndSwapFenced(context.Context, connectionactor.Key, string, uint64, uint64, []byte) (bool, error) {
	return false, sessions.swapErr
}
