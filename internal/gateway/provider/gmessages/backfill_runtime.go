package gmessages

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-gmessages/internal/gateway/connectionactor"
	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/ingress"
	"go.mau.fi/mautrix-gmessages/internal/gateway/messaging"
	"go.mau.fi/mautrix-gmessages/internal/gateway/store/postgres"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

const providerPageCursorID = ingress.ProviderPageCursorID

var ErrInvalidBackfillCursor = errors.New("invalid committed provider backfill cursor")

type gatewayBackfillClient interface {
	ListConversationsWithCursorDurable(context.Context, int, gmproto.ListConversationsRequest_Folder, *gmproto.Cursor) (libgm.DurableListConversationsResult, error)
	FetchMessagesDurable(context.Context, string, int64, *gmproto.Cursor) (libgm.DurableListMessagesResult, error)
}

type gatewayBackfillProvider interface {
	gatewayBackfillClient() gatewayBackfillClient
}

// fullSizeImageProvider asynchronously requests full-size images for thumbnail-only
// attachments. Backfilled pages resolve a response waiter and never raise a
// WrappedMessage event, so the worker must hand committed page messages over itself.
type fullSizeImageProvider interface {
	requestFullSizeImages(*gmproto.Message)
}

type BackfillCursorStore interface {
	LoadCommittedCursor(context.Context, domain.TenantID, domain.ConnectionID, string) ([]byte, error)
}

type BackfillCheckpointStore interface {
	LoadBackfillCheckpoint(context.Context, domain.TenantID, domain.ConnectionID) (*messaging.BackfillCheckpoint, error)
	StageBackfillPageFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, messaging.BackfillPage) error
	MarkBackfillItemFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, string, int, messaging.BackfillItemState, string) error
	CompleteBackfillPageFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, string) error
}

type ActorBackfillWorkerConfig struct {
	Executor             connectionactor.ProviderExecutor
	Cursors              BackfillCursorStore
	Checkpoints          BackfillCheckpointStore
	ConversationPageSize int
	MessagePageSize      int64
}

// ActorBackfillWorker performs one bounded provider call or one durable
// checkpoint transition per invocation. Conversation-list cursors advance only
// after every child conversation reaches its terminal message page.
type ActorBackfillWorker struct {
	executor             connectionactor.ProviderExecutor
	cursors              BackfillCursorStore
	checkpoints          BackfillCheckpointStore
	conversationPageSize int
	messagePageSize      int64
}

func NewActorBackfillWorker(config ActorBackfillWorkerConfig) (*ActorBackfillWorker, error) {
	if config.Executor == nil || config.Cursors == nil || config.Checkpoints == nil {
		return nil, domain.ErrInvalidIdentifier
	}
	if config.ConversationPageSize == 0 {
		config.ConversationPageSize = 25
	}
	if config.MessagePageSize == 0 {
		config.MessagePageSize = 50
	}
	if config.ConversationPageSize < 1 || config.ConversationPageSize > messaging.MaxBackfillConversationsPerPage || config.MessagePageSize < 1 || config.MessagePageSize > ingress.MaxProjectedMessages {
		return nil, domain.ErrInvalidIdentifier
	}
	return &ActorBackfillWorker{
		executor: config.Executor, cursors: config.Cursors, checkpoints: config.Checkpoints,
		conversationPageSize: config.ConversationPageSize, messagePageSize: config.MessagePageSize,
	}, nil
}

func (worker *ActorBackfillWorker) RunConnection(ctx context.Context, key connectionactor.Key) (bool, error) {
	if ctx == nil || key.TenantID == "" || key.ConnectionID == "" {
		return false, domain.ErrInvalidIdentifier
	}
	processed := false
	err := worker.executor.Execute(ctx, key, func(operationCtx context.Context, provider connectionactor.Provider) error {
		ownership, owned := connectionactor.ProviderOwnershipFromContext(operationCtx)
		if !owned || ownership.Key != key {
			return connectionactor.ErrProviderUnavailable
		}
		backfillProvider, ok := provider.(gatewayBackfillProvider)
		if !ok || backfillProvider.gatewayBackfillClient() == nil {
			return errors.New("active provider does not support cursor backfill")
		}
		checkpoint, loadErr := worker.checkpoints.LoadBackfillCheckpoint(operationCtx, key.TenantID, key.ConnectionID)
		if loadErr != nil {
			return classifyBackfillStoreError(loadErr)
		}
		if checkpoint == nil {
			processed = true
			return worker.stageConversationPage(operationCtx, ownership, backfillProvider.gatewayBackfillClient())
		}
		if checkpoint.ScanComplete {
			return nil
		}
		for _, item := range checkpoint.Items {
			if item.State != messaging.BackfillItemPending {
				continue
			}
			processed = true
			return worker.fetchMessagePage(operationCtx, ownership, backfillProvider, checkpoint.ID, item)
		}
		for _, item := range checkpoint.Items {
			if item.State == messaging.BackfillItemPoisoned {
				return fmt.Errorf("%w: %s", messaging.ErrBackfillPoisoned, item.SafeError)
			}
		}
		processed = true
		return classifyBackfillStoreError(worker.checkpoints.CompleteBackfillPageFenced(
			operationCtx, key.TenantID, key.ConnectionID, ownership.OwnerID, ownership.FencingToken, checkpoint.ID,
		))
	})
	return processed, classifyBackfillExecutionError(err)
}

func (worker *ActorBackfillWorker) stageConversationPage(ctx context.Context, ownership connectionactor.ProviderOwnership, client gatewayBackfillClient) error {
	baseEncoded, err := worker.cursors.LoadCommittedCursor(ctx, ownership.Key.TenantID, ownership.Key.ConnectionID, providerPageCursorID)
	if err != nil {
		return classifyBackfillStoreError(err)
	}
	baseCursor, err := decodeBackfillCursor(baseEncoded)
	if err != nil {
		return err
	}
	result, err := client.ListConversationsWithCursorDurable(ctx, worker.conversationPageSize, gmproto.ListConversationsRequest_INBOX, baseCursor)
	if result.Outcome == libgm.DurableOutcomePoisoned || result.Outcome == libgm.DurableOutcomeDuplicatePoisoned {
		return messaging.ErrBackfillPoisoned
	}
	if err != nil {
		return classifyBackfillProviderError(err)
	}
	if result.Outcome != libgm.DurableOutcomeCommitted {
		return errors.New("provider conversation page has no committed durable outcome")
	}
	page := result.Response
	if page == nil || len(page.GetConversations()) > worker.conversationPageSize {
		return fmt.Errorf("%w: provider conversation page is absent or excessive", messaging.ErrBackfillPoisoned)
	}
	next, terminal, err := responseBackfillCursor(page.GetCursorBytes(), page.GetCursor())
	if err != nil {
		return err
	}
	items := make([]messaging.BackfillItem, 0, len(page.GetConversations()))
	seen := make(map[string]struct{}, len(page.GetConversations()))
	for index, conversation := range page.GetConversations() {
		item := messaging.BackfillItem{Ordinal: index, State: messaging.BackfillItemPending}
		if conversation == nil || !validBackfillIdentifier(conversation.GetConversationID()) {
			item.State, item.SafeError = messaging.BackfillItemPoisoned, "invalid_provider_conversation"
		} else if _, duplicate := seen[conversation.GetConversationID()]; duplicate {
			item.State, item.SafeError = messaging.BackfillItemPoisoned, "duplicate_provider_conversation"
		} else {
			item.ConversationID = conversation.GetConversationID()
			seen[item.ConversationID] = struct{}{}
		}
		items = append(items, item)
	}
	return classifyBackfillStoreError(worker.checkpoints.StageBackfillPageFenced(ctx,
		ownership.Key.TenantID, ownership.Key.ConnectionID, ownership.OwnerID, ownership.FencingToken,
		messaging.BackfillPage{BaseCursor: baseEncoded, NextCursor: next, Terminal: terminal, Items: items},
	))
}

func (worker *ActorBackfillWorker) fetchMessagePage(
	ctx context.Context, ownership connectionactor.ProviderOwnership, provider gatewayBackfillProvider,
	checkpointID string, item messaging.BackfillItem,
) error {
	client := provider.gatewayBackfillClient()
	cursor, err := worker.loadCursor(ctx, ownership.Key, item.ConversationID)
	if err != nil {
		return err
	}
	result, err := client.FetchMessagesDurable(ctx, item.ConversationID, worker.messagePageSize, cursor)
	if result.Outcome == libgm.DurableOutcomePoisoned || result.Outcome == libgm.DurableOutcomeDuplicatePoisoned {
		return classifyBackfillStoreError(worker.checkpoints.MarkBackfillItemFenced(ctx,
			ownership.Key.TenantID, ownership.Key.ConnectionID, ownership.OwnerID, ownership.FencingToken,
			checkpointID, item.Ordinal, messaging.BackfillItemPoisoned, "durable_provider_page_poisoned",
		))
	}
	if err != nil {
		return classifyBackfillProviderError(err)
	}
	if result.Outcome != libgm.DurableOutcomeCommitted {
		return errors.New("provider message page has no committed durable outcome")
	}
	page := result.Response
	if page == nil || len(page.GetMessages()) > int(worker.messagePageSize) || validateMessageEvent(&gmproto.MessageEvent{Data: page.GetMessages()}) != nil {
		return classifyBackfillStoreError(worker.checkpoints.MarkBackfillItemFenced(ctx,
			ownership.Key.TenantID, ownership.Key.ConnectionID, ownership.OwnerID, ownership.FencingToken,
			checkpointID, item.Ordinal, messaging.BackfillItemPoisoned, "invalid_provider_message_page",
		))
	}
	if requester, ok := provider.(fullSizeImageProvider); ok {
		// The page is already durably committed; requests are asynchronous and never hold the actor.
		for _, message := range page.GetMessages() {
			requester.requestFullSizeImages(message)
		}
	}
	if page.GetCursor() != nil {
		if _, _, err = responseBackfillCursor(nil, page.GetCursor()); err != nil {
			return classifyBackfillStoreError(worker.checkpoints.MarkBackfillItemFenced(ctx,
				ownership.Key.TenantID, ownership.Key.ConnectionID, ownership.OwnerID, ownership.FencingToken,
				checkpointID, item.Ordinal, messaging.BackfillItemPoisoned, "invalid_provider_message_cursor",
			))
		}
		// The durable response handler committed this message page and cursor
		// before the provider method returned. The item remains pending so the
		// next invocation resumes with that committed cursor.
		return nil
	}
	return classifyBackfillStoreError(worker.checkpoints.MarkBackfillItemFenced(ctx,
		ownership.Key.TenantID, ownership.Key.ConnectionID, ownership.OwnerID, ownership.FencingToken,
		checkpointID, item.Ordinal, messaging.BackfillItemComplete, "",
	))
}

func classifyBackfillProviderError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	switch {
	case errors.Is(err, ErrDurableFenceLost), errors.Is(err, connectionactor.ErrStaleGeneration), errors.Is(err, postgres.ErrConnectionLeaseLost):
		return errors.Join(connectionactor.ErrStaleGeneration, err)
	case errors.Is(err, ingress.ErrConflictingEnvelope), errors.Is(err, ingress.ErrInvalidProviderResponseID),
		errors.Is(err, ingress.ErrProviderResponseCapacity), errors.Is(err, libgm.ErrDurablePoisoned):
		return errors.Join(messaging.ErrBackfillPoisoned, err)
	case errors.Is(err, ErrDurableInfrastructure), errors.Is(err, connectionactor.ErrSharedInfrastructure):
		return errors.Join(connectionactor.ErrSharedInfrastructure, err)
	case errors.Is(err, messaging.ErrBackfillPoisoned), errors.Is(err, messaging.ErrBackfillProviderUnavailable),
		errors.Is(err, connectionactor.ErrProviderUnavailable), errors.Is(err, connectionactor.ErrProviderTransient),
		errors.Is(err, connectionactor.ErrProviderPermanentProtocol):
		return err
	default:
		// Untyped provider/RPC failures, including a bare durable-persistence
		// wrapper with no trusted DB/KMS cause, are connection-local. Only a
		// typed shared-infrastructure error can terminate the gateway.
		return errors.Join(messaging.ErrBackfillProviderUnavailable, err)
	}
}

func classifyBackfillStoreError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	if errors.Is(err, postgres.ErrConnectionLeaseLost) || errors.Is(err, messaging.ErrBackfillCheckpointConflict) ||
		errors.Is(err, ErrDurableFenceLost) || errors.Is(err, connectionactor.ErrStaleGeneration) {
		return errors.Join(connectionactor.ErrStaleGeneration, err)
	}
	return errors.Join(connectionactor.ErrSharedInfrastructure, err)
}

func classifyBackfillExecutionError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	return classifyBackfillProviderError(err)
}

func (worker *ActorBackfillWorker) loadCursor(ctx context.Context, key connectionactor.Key, conversationID string) (*gmproto.Cursor, error) {
	encoded, err := worker.cursors.LoadCommittedCursor(ctx, key.TenantID, key.ConnectionID, conversationID)
	if err != nil {
		return nil, classifyBackfillStoreError(err)
	}
	return decodeBackfillCursor(encoded)
}

func responseBackfillCursor(opaque []byte, cursor *gmproto.Cursor) ([]byte, bool, error) {
	if cursor != nil && len(opaque) > 0 {
		return nil, false, ErrInvalidBackfillCursor
	}
	if cursor == nil && len(opaque) == 0 {
		return nil, true, nil
	}
	encoded, err := backfillCursor(opaque, cursor)
	if err != nil {
		return nil, false, err
	}
	if _, err = decodeBackfillCursor(encoded); err != nil {
		return nil, false, err
	}
	return encoded, false, nil
}

func decodeBackfillCursor(encoded []byte) (*gmproto.Cursor, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	canonical, err := ingress.CanonicalProviderCursor(encoded)
	if err != nil {
		return nil, ErrInvalidBackfillCursor
	}
	var cursor gmproto.Cursor
	if err := proto.Unmarshal(canonical, &cursor); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidBackfillCursor, err)
	}
	return &cursor, nil
}

func validBackfillIdentifier(value string) bool {
	return domain.ValidProviderIdentifier(value)
}
