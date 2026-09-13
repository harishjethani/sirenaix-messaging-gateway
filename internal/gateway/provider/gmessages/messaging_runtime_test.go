package gmessages

import (
	"bytes"
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-gmessages/internal/gateway/connectionactor"
	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/ingress"
	"go.mau.fi/mautrix-gmessages/internal/gateway/media"
	"go.mau.fi/mautrix-gmessages/internal/gateway/messaging"
	"go.mau.fi/mautrix-gmessages/internal/gateway/session"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

type inlineExecutor struct{ provider connectionactor.Provider }

func (executor inlineExecutor) Execute(ctx context.Context, _ connectionactor.Key, operation connectionactor.ProviderOperation) error {
	return operation(connectionactor.ContextWithProviderOwnership(ctx, connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}), executor.provider)
}

type messagingClientFake struct {
	conversation *gmproto.Conversation
	created      *gmproto.GetOrCreateConversationResponse
	createErr    error
	sent         *gmproto.SendMessageRequest
	sequence     []string
	downloaded   []byte
}

func (client *messagingClientFake) GetConversation(context.Context, string) (*gmproto.Conversation, error) {
	client.sequence = append(client.sequence, "get-conversation")
	return client.conversation, nil
}
func (client *messagingClientFake) GetOrCreateConversation(context.Context, *gmproto.GetOrCreateConversationRequest) (*gmproto.GetOrCreateConversationResponse, error) {
	client.sequence = append(client.sequence, "get-or-create")
	return client.created, client.createErr
}
func (client *messagingClientFake) SendMessage(_ context.Context, request *gmproto.SendMessageRequest) (*gmproto.SendMessageResponse, error) {
	client.sequence = append(client.sequence, "send")
	client.sent = request
	return &gmproto.SendMessageResponse{Status: gmproto.SendMessageResponse_SUCCESS}, nil
}
func (client *messagingClientFake) UploadMediaContext(_ context.Context, source io.Reader, size int64, filename, mime string, maximum int64) (*gmproto.MediaContent, error) {
	client.sequence = append(client.sequence, "upload")
	data, _ := io.ReadAll(io.LimitReader(source, maximum+1))
	if int64(len(data)) != size {
		return nil, media.ErrLengthMismatch
	}
	return &gmproto.MediaContent{MediaID: "provider-media", MediaName: filename, MimeType: mime, Size: size}, nil
}
func (client *messagingClientFake) DownloadMediaContext(context.Context, string, []byte, int64) ([]byte, error) {
	return append([]byte(nil), client.downloaded...), nil
}

type messagingProviderFake struct{ client gatewayMessagingClient }

func (*messagingProviderFake) Connect(context.Context) error    { return nil }
func (*messagingProviderFake) Disconnect(context.Context) error { return nil }
func (provider *messagingProviderFake) gatewayMessagingClient() gatewayMessagingClient {
	return provider.client
}

type lineResolverFake struct{ line domain.Line }

func (resolver lineResolverFake) GetLine(context.Context, domain.TenantID, domain.ConnectionID, domain.LineID) (domain.Line, error) {
	return resolver.line, nil
}

type mediaSourceFake struct{ record media.Record }

func (source mediaSourceFake) Open(context.Context, domain.TenantID, domain.MediaID) (io.ReadCloser, media.Record, error) {
	return io.NopCloser(bytes.NewReader([]byte("png"))), source.record, nil
}

type routeRecorder struct {
	sequence     *[]string
	conversation *gmproto.Conversation
}

func (recorder *routeRecorder) RecordCreatedConversationFenced(_ context.Context, _ domain.TenantID, _ domain.ConnectionID, _ domain.MessageID, conversationID, defaultOutgoingID string, isGroup bool, _ string, _ uint64) error {
	*recorder.sequence = append(*recorder.sequence, "persist-route")
	recorder.conversation = &gmproto.Conversation{ConversationID: conversationID, DefaultOutgoingID: defaultOutgoingID, IsGroupChat: isGroup}
	return nil
}

func TestActorSenderMapsExistingTextAndImageWithoutForcingTransport(t *testing.T) {
	client := &messagingClientFake{conversation: &gmproto.Conversation{ConversationID: "conversation-a", DefaultOutgoingID: "outgoing-primary"}}
	provider := &messagingProviderFake{client: client}
	sender, err := NewActorSender(ActorSenderConfig{
		Executor: inlineExecutor{provider: provider}, Lines: lineResolverFake{line: domain.Line{
			ID: "line-a", TenantID: "tenant-a", ConnectionID: "connection-a", ProviderOutgoingID: "outgoing-primary",
		}}, Media: mediaSourceFake{record: media.Record{
			ID: "media-a", TenantID: "tenant-a", MIMEType: "image/png", Size: 3, DisplayFilename: "photo.png", State: "ready",
		}}, Routes: &routeRecorder{sequence: &client.sequence}, MaxMediaBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.SendOnce(context.Background(), messaging.ProviderSendCommand{Message: messaging.OutboundMessage{
		ID: "message-a", TenantID: "tenant-a", ConnectionID: "connection-a", ConversationID: "conversation-a",
		LineID: "line-a", Text: "hello", MediaIDs: []domain.MediaID{"media-a"}, ProviderTmpID: "sx-temp",
	}, FencingToken: 9})
	if err != nil || !result.Accepted {
		t.Fatalf("SendOnce() = (%+v, %v)", result, err)
	}
	request := client.sent
	if request == nil || request.ForceRCS || request.GetTmpID() != "sx-temp" || request.GetConversationID() != "conversation-a" || request.GetMessagePayload().GetParticipantID() != "outgoing-primary" || len(request.GetMessagePayload().GetMessageInfo()) != 2 {
		t.Fatalf("provider request = %+v", request)
	}
}

func TestActorSenderPersistsNewPhoneDefaultConversationBeforeSend(t *testing.T) {
	client := &messagingClientFake{created: &gmproto.GetOrCreateConversationResponse{
		Status:       gmproto.GetOrCreateConversationResponse_SUCCESS,
		Conversation: &gmproto.Conversation{ConversationID: "created-conversation", DefaultOutgoingID: "outgoing-phone-default"},
	}}
	routes := &routeRecorder{sequence: &client.sequence}
	sender, _ := NewActorSender(ActorSenderConfig{Executor: inlineExecutor{provider: &messagingProviderFake{client: client}}, Lines: lineResolverFake{}, Media: mediaSourceFake{}, Routes: routes})
	result, err := sender.SendOnce(context.Background(), messaging.ProviderSendCommand{Message: messaging.OutboundMessage{
		ID: "message-a", TenantID: "tenant-a", ConnectionID: "connection-a", Recipient: "+12025550123",
		RouteMode: messaging.RouteModePhoneDefault, Text: "hello", ProviderTmpID: "sx-temp",
	}, FencingToken: 9})
	if err != nil || !result.Accepted {
		t.Fatalf("SendOnce() = (%+v, %v)", result, err)
	}
	want := []string{"get-or-create", "persist-route", "send"}
	if len(client.sequence) != len(want) {
		t.Fatalf("sequence = %v", client.sequence)
	}
	for index := range want {
		if client.sequence[index] != want[index] {
			t.Fatalf("sequence = %v, want %v", client.sequence, want)
		}
	}
	if routes.conversation.GetConversationID() != "created-conversation" || client.sent.GetConversationID() != "created-conversation" || client.sent.GetForceRCS() {
		t.Fatalf("route=%+v request=%+v", routes.conversation, client.sent)
	}
}

func TestActorSenderRejectsReservedProviderConversationBeforeRouteRecordOrSend(t *testing.T) {
	for name, message := range map[string]messaging.OutboundMessage{
		"claimed existing route": {
			ID: "message-a", TenantID: "tenant-a", ConnectionID: "connection-a",
			ConversationID: domain.ProviderPageCursorID, Text: "hello", ProviderTmpID: "sx-temp",
		},
		"get-or-create response": {
			ID: "message-a", TenantID: "tenant-a", ConnectionID: "connection-a", Recipient: "+12025550123",
			RouteMode: messaging.RouteModePhoneDefault, Text: "hello", ProviderTmpID: "sx-temp",
		},
	} {
		t.Run(name, func(t *testing.T) {
			client := &messagingClientFake{
				conversation: &gmproto.Conversation{ConversationID: domain.ProviderPageCursorID, DefaultOutgoingID: "outgoing-default"},
				created: &gmproto.GetOrCreateConversationResponse{
					Status: gmproto.GetOrCreateConversationResponse_SUCCESS,
					Conversation: &gmproto.Conversation{
						ConversationID: domain.ProviderPageCursorID, DefaultOutgoingID: "outgoing-default",
					},
				},
			}
			routes := &routeRecorder{sequence: &client.sequence}
			sender, err := NewActorSender(ActorSenderConfig{
				Executor: inlineExecutor{provider: &messagingProviderFake{client: client}},
				Lines:    lineResolverFake{}, Media: mediaSourceFake{}, Routes: routes,
			})
			if err != nil {
				t.Fatal(err)
			}
			result, sendErr := sender.SendOnce(context.Background(), messaging.ProviderSendCommand{Message: message, FencingToken: 9})
			if !errors.Is(sendErr, connectionactor.ErrProviderPermanentProtocol) || result.Accepted {
				t.Fatalf("reserved provider conversation result = (%+v, %v)", result, sendErr)
			}
			if routes.conversation != nil || client.sent != nil {
				t.Fatalf("reserved provider conversation mutated route/send: route=%+v send=%+v sequence=%v", routes.conversation, client.sent, client.sequence)
			}
		})
	}
}

func TestActorSenderStopsAfterAmbiguousNewConversationCreation(t *testing.T) {
	client := &messagingClientFake{createErr: context.DeadlineExceeded}
	routes := &routeRecorder{sequence: &client.sequence}
	sender, err := NewActorSender(ActorSenderConfig{
		Executor: inlineExecutor{provider: &messagingProviderFake{client: client}},
		Lines:    lineResolverFake{},
		Media:    mediaSourceFake{},
		Routes:   routes,
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := sender.SendOnce(context.Background(), messaging.ProviderSendCommand{Message: messaging.OutboundMessage{
		ID: "message-a", TenantID: "tenant-a", ConnectionID: "connection-a", Recipient: "+12025550123",
		RouteMode: messaging.RouteModePhoneDefault, Text: "hello", ProviderTmpID: "sx-temp",
	}, FencingToken: 9})
	if !errors.Is(err, context.DeadlineExceeded) || result.Accepted {
		t.Fatalf("SendOnce() = (%+v, %v)", result, err)
	}
	if len(client.sequence) != 1 || client.sequence[0] != "get-or-create" || client.sent != nil || routes.conversation != nil {
		t.Fatalf("ambiguous creation continued mutation: sequence=%v sent=%+v route=%+v", client.sequence, client.sent, routes.conversation)
	}
}

func TestActorSenderRejectsClaimFromDifferentActorGeneration(t *testing.T) {
	client := &messagingClientFake{conversation: &gmproto.Conversation{ConversationID: "conversation-a", DefaultOutgoingID: "outgoing-primary"}}
	sender, err := NewActorSender(ActorSenderConfig{
		Executor: inlineExecutor{provider: &messagingProviderFake{client: client}},
		Lines:    lineResolverFake{}, Media: mediaSourceFake{}, Routes: &routeRecorder{sequence: &client.sequence},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sender.SendOnce(context.Background(), messaging.ProviderSendCommand{Message: messaging.OutboundMessage{
		ID: "message-a", TenantID: "tenant-a", ConnectionID: "connection-a", ConversationID: "conversation-a",
		Text: "hello", ProviderTmpID: "sx-temp",
	}, FencingToken: 8})
	if !errors.Is(err, connectionactor.ErrProviderUnavailable) || len(client.sequence) != 0 {
		t.Fatalf("stale SendOnce error=%v provider sequence=%v", err, client.sequence)
	}
}

type keyOpenerFake struct{ key []byte }

func (opener keyOpenerFake) Open(context.Context, session.Scope, session.Envelope) ([]byte, error) {
	return append([]byte(nil), opener.key...), nil
}

func TestActorMediaFetcherDecryptsAndDownloadsInsideActor(t *testing.T) {
	client := &messagingClientFake{downloaded: []byte("image")}
	fetcher, err := NewActorMediaFetcher(ActorMediaFetcherConfig{
		Executor: inlineExecutor{provider: &messagingProviderFake{client: client}}, Keys: keyOpenerFake{key: bytes.Repeat([]byte{1}, 32)}, MaxBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	content, err := fetcher.Fetch(context.Background(), media.FetchJob{
		TenantID: "tenant-a", ConnectionID: "connection-a", Locator: "gmessages:cHJvdmlkZXItbWVkaWE",
		DeclaredMIME: "image/png", DisplayFilename: "photo.png", KeyEnvelope: session.Envelope{Version: 1, Provider: "gmessages-media"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer content.Body.Close()
	data, _ := io.ReadAll(content.Body)
	if string(data) != "image" || content.ContentLength != 5 || content.MIMEType != "image/png" {
		t.Fatalf("fetch content = %+v data=%q", content, data)
	}
}

type backfillCursorStoreFake struct {
	mu         sync.Mutex
	cursors    map[string][]byte
	checkpoint *messaging.BackfillCheckpoint
	loadErr    error
}

func (store *backfillCursorStoreFake) LoadCommittedCursor(_ context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, conversationID string) ([]byte, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	return append([]byte(nil), store.cursors[string(tenantID)+"/"+string(connectionID)+"/"+conversationID]...), nil
}

func (store *backfillCursorStoreFake) set(tenantID domain.TenantID, connectionID domain.ConnectionID, conversationID string, cursor *gmproto.Cursor) {
	encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(cursor)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.cursors[string(tenantID)+"/"+string(connectionID)+"/"+conversationID] = encoded
}

func (store *backfillCursorStoreFake) LoadBackfillCheckpoint(context.Context, domain.TenantID, domain.ConnectionID) (*messaging.BackfillCheckpoint, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint == nil {
		return nil, nil
	}
	checkpoint := *store.checkpoint
	checkpoint.NextCursor = append([]byte(nil), checkpoint.NextCursor...)
	checkpoint.Items = append([]messaging.BackfillItem(nil), checkpoint.Items...)
	return &checkpoint, nil
}

func (store *backfillCursorStoreFake) StageBackfillPageFenced(_ context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, _ string, _ uint64, page messaging.BackfillPage) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint != nil {
		return nil
	}
	committed := store.cursors[string(tenantID)+"/"+string(connectionID)+"/"+providerPageCursorID]
	if !bytes.Equal(committed, page.BaseCursor) {
		return messaging.ErrBackfillCheckpointConflict
	}
	store.checkpoint = &messaging.BackfillCheckpoint{
		ID: "checkpoint-a", NextCursor: append([]byte(nil), page.NextCursor...), Terminal: page.Terminal,
		Items: append([]messaging.BackfillItem(nil), page.Items...),
	}
	return nil
}

func (store *backfillCursorStoreFake) MarkBackfillItemFenced(_ context.Context, _ domain.TenantID, _ domain.ConnectionID, _ string, _ uint64, checkpointID string, ordinal int, state messaging.BackfillItemState, safeError string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint == nil || store.checkpoint.ID != checkpointID || ordinal < 0 || ordinal >= len(store.checkpoint.Items) {
		return messaging.ErrBackfillCheckpointConflict
	}
	store.checkpoint.Items[ordinal].State = state
	store.checkpoint.Items[ordinal].SafeError = safeError
	return nil
}

func (store *backfillCursorStoreFake) CompleteBackfillPageFenced(_ context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, _ string, _ uint64, checkpointID string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.checkpoint == nil || store.checkpoint.ID != checkpointID {
		return messaging.ErrBackfillCheckpointConflict
	}
	for _, item := range store.checkpoint.Items {
		if item.State != messaging.BackfillItemComplete {
			return messaging.ErrBackfillCheckpointConflict
		}
	}
	if store.checkpoint.Terminal {
		store.checkpoint.ScanComplete = true
		return nil
	}
	store.cursors[string(tenantID)+"/"+string(connectionID)+"/"+providerPageCursorID] = append([]byte(nil), store.checkpoint.NextCursor...)
	store.checkpoint = nil
	return nil
}

type backfillClientFake struct {
	mu                 sync.Mutex
	listCursor         *gmproto.Cursor
	fetchCursor        *gmproto.Cursor
	listCalls          int
	fetchConversations []string
	listResponse       *gmproto.ListConversationsResponse
	listErr            error
	listOutcome        libgm.DurableOutcome
	list               func(*gmproto.Cursor) (*gmproto.ListConversationsResponse, error)
	afterDurableCommit func()
	fetch              func(string, *gmproto.Cursor) (*gmproto.ListMessagesResponse, error)
	fetchOutcome       libgm.DurableOutcome
}

func (client *backfillClientFake) ListConversationsWithCursor(_ context.Context, _ int, _ gmproto.ListConversationsRequest_Folder, cursor *gmproto.Cursor) (*gmproto.ListConversationsResponse, error) {
	client.mu.Lock()
	client.listCalls++
	client.listCursor = proto.Clone(cursor).(*gmproto.Cursor)
	hook := client.afterDurableCommit
	list := client.list
	response, err := client.listResponse, client.listErr
	client.mu.Unlock()
	if hook != nil {
		hook()
	}
	if list != nil {
		return list(cursor)
	}
	return response, err
}

func (client *backfillClientFake) ListConversationsWithCursorDurable(ctx context.Context, count int, folder gmproto.ListConversationsRequest_Folder, cursor *gmproto.Cursor) (libgm.DurableListConversationsResult, error) {
	response, err := client.ListConversationsWithCursor(ctx, count, folder, cursor)
	outcome := client.listOutcome
	if outcome == libgm.DurableOutcomeUnknown {
		outcome = libgm.DurableOutcomeCommitted
	}
	return libgm.DurableListConversationsResult{Response: response, Outcome: outcome}, err
}

func (client *backfillClientFake) FetchMessagesDurable(_ context.Context, conversationID string, _ int64, cursor *gmproto.Cursor) (libgm.DurableListMessagesResult, error) {
	client.mu.Lock()
	client.fetchCursor = proto.Clone(cursor).(*gmproto.Cursor)
	client.fetchConversations = append(client.fetchConversations, conversationID)
	fetch := client.fetch
	client.mu.Unlock()
	if fetch != nil {
		response, err := fetch(conversationID, cursor)
		return libgm.DurableListMessagesResult{Response: response, Outcome: client.durableFetchOutcome()}, err
	}
	return libgm.DurableListMessagesResult{Response: &gmproto.ListMessagesResponse{}, Outcome: client.durableFetchOutcome()}, nil
}

func (client *backfillClientFake) durableFetchOutcome() libgm.DurableOutcome {
	if client.fetchOutcome == libgm.DurableOutcomeUnknown {
		return libgm.DurableOutcomeCommitted
	}
	return client.fetchOutcome
}

type backfillProviderFake struct{ client gatewayBackfillClient }

func (*backfillProviderFake) Connect(context.Context) error    { return nil }
func (*backfillProviderFake) Disconnect(context.Context) error { return nil }
func (provider *backfillProviderFake) gatewayBackfillClient() gatewayBackfillClient {
	return provider.client
}

type fullSizeBackfillProviderFake struct {
	backfillProviderFake
	requested []string
}

func (provider *fullSizeBackfillProviderFake) requestFullSizeImages(message *gmproto.Message) {
	provider.requested = append(provider.requested, message.GetMessageID())
}

// Backfilled pages go to a response waiter and never raise a WrappedMessage event, so the
// worker itself must hand committed page messages to the full-size image requester.
func TestActorBackfillWorkerRequestsFullSizeImagesForCommittedPage(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	actionMessageID := "action-a"
	client := &backfillClientFake{
		listResponse: &gmproto.ListConversationsResponse{Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}}},
		fetch: func(string, *gmproto.Cursor) (*gmproto.ListMessagesResponse, error) {
			return &gmproto.ListMessagesResponse{Messages: []*gmproto.Message{{
				MessageID: "provider-thumbnail", ConversationID: "conversation-a",
				MessageInfo: []*gmproto.MessageInfo{{ActionMessageID: &actionMessageID, Data: &gmproto.MessageInfo_MediaContent{
					MediaContent: &gmproto.MediaContent{ThumbnailMediaID: "thumbnail-a", MimeType: "image/jpeg"},
				}}},
			}}}, nil
		},
	}
	provider := &fullSizeBackfillProviderFake{backfillProviderFake: backfillProviderFake{client: client}}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: provider}, Cursors: store, Checkpoints: store,
		ConversationPageSize: 25, MessagePageSize: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ {
		if processed, runErr := worker.RunConnection(context.Background(), key); runErr != nil || !processed {
			t.Fatalf("RunConnection() #%d = (%v, %v)", run, processed, runErr)
		}
	}
	if len(provider.requested) != 1 || provider.requested[0] != "provider-thumbnail" {
		t.Fatalf("full-size requests = %q", provider.requested)
	}
}

func TestActorBackfillWorkerUsesCommittedCursorsInsideFencedActor(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	listCursor := &gmproto.Cursor{LastItemID: "conversation-old", LastItemTimestamp: 1700000000000}
	messageCursor := &gmproto.Cursor{LastItemID: "message-old", LastItemTimestamp: 1699999999000}
	store.set(key.TenantID, key.ConnectionID, providerPageCursorID, listCursor)
	store.set(key.TenantID, key.ConnectionID, "conversation-a", messageCursor)
	client := &backfillClientFake{listResponse: &gmproto.ListConversationsResponse{Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}}}}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
		ConversationPageSize: 25, MessagePageSize: 50,
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := worker.RunConnection(context.Background(), key)
	if err != nil || !processed {
		t.Fatalf("RunConnection() = (%v, %v)", processed, err)
	}
	processed, err = worker.RunConnection(context.Background(), key)
	if err != nil || !processed {
		t.Fatalf("second RunConnection() = (%v, %v)", processed, err)
	}
	if !proto.Equal(client.listCursor, listCursor) || !proto.Equal(client.fetchCursor, messageCursor) {
		t.Fatalf("provider cursors = list:%v messages:%v", client.listCursor, client.fetchCursor)
	}
}

func TestActorBackfillWorkerRejectsPageSizeAboveDurableCheckpointCap(t *testing.T) {
	_, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor:             inlineExecutor{provider: &backfillProviderFake{client: &backfillClientFake{}}},
		Cursors:              &backfillCursorStoreFake{cursors: make(map[string][]byte)},
		Checkpoints:          &backfillCursorStoreFake{cursors: make(map[string][]byte)},
		ConversationPageSize: messaging.MaxBackfillConversationsPerPage + 1,
	})
	if !errors.Is(err, domain.ErrInvalidIdentifier) {
		t.Fatalf("oversized durable backfill page error = %v", err)
	}
}

func TestActorBackfillWorkerDoesNotStageDurablyPoisonedConversationPage(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	client := &backfillClientFake{
		listResponse: &gmproto.ListConversationsResponse{
			Conversations: []*gmproto.Conversation{{ConversationID: "conversation-looks-valid"}},
		},
		listOutcome: libgm.DurableOutcomePoisoned,
	}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	processed, err := worker.RunConnection(context.Background(), key)
	if !processed || !errors.Is(err, messaging.ErrBackfillPoisoned) {
		t.Fatalf("RunConnection() = (%v, %v), want durable poison", processed, err)
	}
	if store.checkpoint != nil || len(store.cursors) != 0 {
		t.Fatalf("durably poisoned list page staged progress: checkpoint=%+v cursors=%+v", store.checkpoint, store.cursors)
	}
}

func TestActorBackfillWorkerStagesReservedParentIDAsPoisonedChild(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	client := &backfillClientFake{listResponse: &gmproto.ListConversationsResponse{
		Conversations: []*gmproto.Conversation{{ConversationID: ingress.ProviderPageCursorID}},
	}}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if processed, runErr := worker.RunConnection(context.Background(), key); runErr != nil || !processed {
		t.Fatalf("stage reserved page = (%v, %v)", processed, runErr)
	}
	checkpoint, _ := store.LoadBackfillCheckpoint(context.Background(), key.TenantID, key.ConnectionID)
	if checkpoint == nil || len(checkpoint.Items) != 1 || checkpoint.Items[0].State != messaging.BackfillItemPoisoned || checkpoint.Items[0].ConversationID != "" {
		t.Fatalf("reserved child checkpoint = %+v", checkpoint)
	}
	if parent := store.cursors[string(key.TenantID)+"/"+string(key.ConnectionID)+"/"+ingress.ProviderPageCursorID]; len(parent) != 0 {
		t.Fatalf("reserved child aliased parent cursor = %x", parent)
	}
}

func TestActorBackfillWorkerPoisonsCommittedZeroValueNonterminalCursor(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	client := &backfillClientFake{
		listResponse: &gmproto.ListConversationsResponse{Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}}},
		fetch: func(string, *gmproto.Cursor) (*gmproto.ListMessagesResponse, error) {
			return &gmproto.ListMessagesResponse{Cursor: &gmproto.Cursor{}}, nil
		},
	}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = worker.RunConnection(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err = worker.RunConnection(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	checkpoint, _ := store.LoadBackfillCheckpoint(context.Background(), key.TenantID, key.ConnectionID)
	if checkpoint == nil || checkpoint.Items[0].State != messaging.BackfillItemPoisoned || checkpoint.Items[0].SafeError != "invalid_provider_message_cursor" {
		t.Fatalf("zero cursor checkpoint = %+v", checkpoint)
	}
}

func TestActorBackfillWorkerPreservesDurableInfrastructureFailure(t *testing.T) {
	durableFailure := errors.Join(libgm.ErrDurablePersistence, ErrDurableInfrastructure, errors.New("unavailable tenant transaction"))
	for name, fixture := range map[string]struct {
		client *backfillClientFake
		runs   int
	}{
		"conversation list": {client: &backfillClientFake{listErr: durableFailure}, runs: 1},
		"message page": {client: &backfillClientFake{
			listResponse: &gmproto.ListConversationsResponse{Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}}},
			fetch:        func(string, *gmproto.Cursor) (*gmproto.ListMessagesResponse, error) { return nil, durableFailure },
		}, runs: 2},
	} {
		t.Run(name, func(t *testing.T) {
			key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
			store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
			worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
				Executor: inlineExecutor{provider: &backfillProviderFake{client: fixture.client}}, Cursors: store, Checkpoints: store,
			})
			if err != nil {
				t.Fatal(err)
			}
			for run := 1; run < fixture.runs; run++ {
				if _, err = worker.RunConnection(context.Background(), key); err != nil {
					t.Fatalf("setup run %d: %v", run, err)
				}
			}
			_, err = worker.RunConnection(context.Background(), key)
			if !errors.Is(err, libgm.ErrDurablePersistence) || !errors.Is(err, connectionactor.ErrSharedInfrastructure) || errors.Is(err, messaging.ErrBackfillProviderUnavailable) {
				t.Fatalf("durable infrastructure error = %v", err)
			}
		})
	}
}

func TestClassifyBackfillProviderErrorPreservesLocalFenceAndSharedCauses(t *testing.T) {
	databaseFailure := errors.New("database unavailable")
	for name, fixture := range map[string]struct {
		input       error
		want        error
		wantCause   error
		forbidFatal bool
	}{
		"provider conflict": {
			input: errors.Join(libgm.ErrDurablePersistence, ingress.ErrConflictingEnvelope),
			want:  messaging.ErrBackfillPoisoned, wantCause: ingress.ErrConflictingEnvelope, forbidFatal: true,
		},
		"committed provider poison": {
			input: errors.Join(libgm.ErrDurablePersistence, libgm.ErrDurablePoisoned),
			want:  messaging.ErrBackfillPoisoned, wantCause: libgm.ErrDurablePoisoned, forbidFatal: true,
		},
		"provider response capacity": {
			input: ingress.ErrProviderResponseCapacity,
			want:  messaging.ErrBackfillPoisoned, wantCause: ingress.ErrProviderResponseCapacity, forbidFatal: true,
		},
		"durable fence": {
			input: errors.Join(libgm.ErrDurablePersistence, ErrDurableFenceLost),
			want:  connectionactor.ErrStaleGeneration, wantCause: ErrDurableFenceLost, forbidFatal: true,
		},
		"typed infrastructure": {
			input: errors.Join(libgm.ErrDurablePersistence, ErrDurableInfrastructure, databaseFailure),
			want:  connectionactor.ErrSharedInfrastructure, wantCause: databaseFailure,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := classifyBackfillProviderError(fixture.input)
			if !errors.Is(got, fixture.want) || !errors.Is(got, fixture.wantCause) {
				t.Fatalf("classification = %v, want %v and cause %v", got, fixture.want, fixture.wantCause)
			}
			if fixture.forbidFatal && errors.Is(got, connectionactor.ErrSharedInfrastructure) {
				t.Fatalf("connection-local error became shared fatal: %v", got)
			}
		})
	}
}

func TestActorBackfillWorkerTypesRepositoryLoadFailureAsSharedInfrastructure(t *testing.T) {
	databaseFailure := errors.New("cursor repository unavailable")
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte), loadErr: databaseFailure}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: &backfillClientFake{}}}, Cursors: store, Checkpoints: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = worker.RunConnection(context.Background(), key)
	if !errors.Is(err, connectionactor.ErrSharedInfrastructure) || !errors.Is(err, databaseFailure) {
		t.Fatalf("repository load classification = %v", err)
	}
}

func TestActorBackfillWorkerRestartsFromCursorCommittedBeforeCallerCrash(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	committed := &gmproto.Cursor{LastItemID: "conversation-committed", LastItemTimestamp: 1700000001000}
	first := &backfillClientFake{
		listResponse: &gmproto.ListConversationsResponse{}, listErr: context.Canceled,
		afterDurableCommit: func() { store.set(key.TenantID, key.ConnectionID, providerPageCursorID, committed) },
	}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{Executor: inlineExecutor{provider: &backfillProviderFake{client: first}}, Cursors: store, Checkpoints: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = worker.RunConnection(context.Background(), key); !errors.Is(err, context.Canceled) {
		t.Fatalf("first RunConnection() error = %v", err)
	}
	second := &backfillClientFake{listResponse: &gmproto.ListConversationsResponse{}}
	restarted, _ := NewActorBackfillWorker(ActorBackfillWorkerConfig{Executor: inlineExecutor{provider: &backfillProviderFake{client: second}}, Cursors: store, Checkpoints: store})
	if _, err = restarted.RunConnection(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(second.listCursor, committed) {
		t.Fatalf("restart cursor = %v, want committed %v", second.listCursor, committed)
	}
}

func TestActorBackfillWorkerResumesEveryConversationAndMessagePageBeforeAdvancingList(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	base := &gmproto.Cursor{LastItemID: "conversation-before", LastItemTimestamp: 1700000000000}
	store.set(key.TenantID, key.ConnectionID, providerPageCursorID, base)
	client := &backfillClientFake{listResponse: &gmproto.ListConversationsResponse{
		Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}, {ConversationID: "conversation-b"}},
		Cursor:        &gmproto.Cursor{LastItemID: "conversation-b", LastItemTimestamp: 1700000001000},
	}}
	client.fetch = func(conversationID string, cursor *gmproto.Cursor) (*gmproto.ListMessagesResponse, error) {
		if conversationID == "conversation-a" && cursor == nil {
			next := &gmproto.Cursor{LastItemID: "message-a-1", LastItemTimestamp: 1700000000001}
			store.set(key.TenantID, key.ConnectionID, conversationID, next)
			return &gmproto.ListMessagesResponse{Cursor: next}, nil
		}
		return &gmproto.ListMessagesResponse{}, nil
	}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err = worker.RunConnection(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.listCalls != 1 {
		t.Fatalf("list calls = %d, want one staged provider page", client.listCalls)
	}
	want := []string{"conversation-a", "conversation-a", "conversation-b"}
	if !reflect.DeepEqual(client.fetchConversations, want) {
		t.Fatalf("fetched conversations = %v, want %v", client.fetchConversations, want)
	}
	committed, _ := store.LoadCommittedCursor(context.Background(), key.TenantID, key.ConnectionID, providerPageCursorID)
	wantCommitted, _ := proto.MarshalOptions{Deterministic: true}.Marshal(client.listResponse.GetCursor())
	if !bytes.Equal(committed, wantCommitted) {
		t.Fatalf("committed list cursor = %x, want %x after all children", committed, wantCommitted)
	}
}

func TestActorBackfillWorkerCheckpointsMultipleConversationPagesAcrossRestart(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	listNext := &gmproto.Cursor{LastItemID: "conversation-a", LastItemTimestamp: 1700000001000}
	client := &backfillClientFake{}
	client.list = func(cursor *gmproto.Cursor) (*gmproto.ListConversationsResponse, error) {
		if cursor == nil {
			return &gmproto.ListConversationsResponse{Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}}, Cursor: listNext}, nil
		}
		if proto.Equal(cursor, listNext) {
			return &gmproto.ListConversationsResponse{Conversations: []*gmproto.Conversation{{ConversationID: "conversation-b"}}}, nil
		}
		return nil, errors.New("unexpected list cursor")
	}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Restart the worker between every durable boundary. Only the repository
	// state survives, which is the production crash-recovery contract.
	for range 6 {
		worker, err = NewActorBackfillWorker(ActorBackfillWorkerConfig{
			Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
		})
		if err != nil {
			t.Fatal(err)
		}
		if processed, runErr := worker.RunConnection(context.Background(), key); runErr != nil || !processed {
			t.Fatalf("restart boundary = (%v, %v)", processed, runErr)
		}
	}
	processed, err := worker.RunConnection(context.Background(), key)
	if err != nil || processed {
		t.Fatalf("completed scan = (%v, %v), want idle", processed, err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.listCalls != 2 || !reflect.DeepEqual(client.fetchConversations, []string{"conversation-a", "conversation-b"}) {
		t.Fatalf("provider calls: list=%d fetch=%v", client.listCalls, client.fetchConversations)
	}
}

func TestActorBackfillWorkerIsolatesPoisonWithoutAdvancingPastIt(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	next := &gmproto.Cursor{LastItemID: "conversation-b", LastItemTimestamp: 1700000001000}
	client := &backfillClientFake{listResponse: &gmproto.ListConversationsResponse{
		Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}, nil, {ConversationID: "conversation-b"}}, Cursor: next,
	}}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 { // stage, healthy A, healthy B
		if _, err = worker.RunConnection(context.Background(), key); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = worker.RunConnection(context.Background(), key); !errors.Is(err, messaging.ErrBackfillPoisoned) {
		t.Fatalf("poison boundary error = %v", err)
	}
	client.mu.Lock()
	if got := append([]string(nil), client.fetchConversations...); !reflect.DeepEqual(got, []string{"conversation-a", "conversation-b"}) {
		client.mu.Unlock()
		t.Fatalf("healthy siblings fetched = %v", got)
	}
	client.mu.Unlock()
	committed, _ := store.LoadCommittedCursor(context.Background(), key.TenantID, key.ConnectionID, providerPageCursorID)
	if len(committed) != 0 {
		t.Fatalf("parent cursor advanced over poison: %x", committed)
	}
}

func TestActorBackfillWorkerBlocksCheckpointOnDurablyACKedProviderPagePoison(t *testing.T) {
	key := connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}
	store := &backfillCursorStoreFake{cursors: make(map[string][]byte)}
	client := &backfillClientFake{
		listResponse: &gmproto.ListConversationsResponse{
			Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}},
			Cursor:        &gmproto.Cursor{LastItemID: "conversation-a", LastItemTimestamp: 1724400000024},
		},
		fetchOutcome: libgm.DurableOutcomePoisoned,
		fetch: func(string, *gmproto.Cursor) (*gmproto.ListMessagesResponse, error) {
			return &gmproto.ListMessagesResponse{Cursor: &gmproto.Cursor{
				LastItemID: "message-poison", LastItemTimestamp: 1724400000023,
			}}, nil
		},
	}
	worker, err := NewActorBackfillWorker(ActorBackfillWorkerConfig{
		Executor: inlineExecutor{provider: &backfillProviderFake{client: client}}, Cursors: store, Checkpoints: store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = worker.RunConnection(context.Background(), key); err != nil { // stage parent page
		t.Fatal(err)
	}
	if _, err = worker.RunConnection(context.Background(), key); err != nil { // persist child poison state
		t.Fatal(err)
	}
	checkpoint, _ := store.LoadBackfillCheckpoint(context.Background(), key.TenantID, key.ConnectionID)
	if checkpoint == nil || checkpoint.Items[0].State != messaging.BackfillItemPoisoned || checkpoint.Items[0].SafeError != "durable_provider_page_poisoned" {
		t.Fatalf("poison checkpoint = %+v", checkpoint)
	}
	child, _ := store.LoadCommittedCursor(context.Background(), key.TenantID, key.ConnectionID, "conversation-a")
	parent, _ := store.LoadCommittedCursor(context.Background(), key.TenantID, key.ConnectionID, providerPageCursorID)
	if len(child) != 0 || len(parent) != 0 {
		t.Fatalf("poison advanced cursors: child=%x parent=%x", child, parent)
	}
	if _, err = worker.RunConnection(context.Background(), key); !errors.Is(err, messaging.ErrBackfillPoisoned) {
		t.Fatalf("operator boundary error = %v", err)
	}
}
