package gmessages

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-gmessages/internal/gateway/connectionactor"
	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/ingress"
	"go.mau.fi/mautrix-gmessages/internal/gateway/session"
	"go.mau.fi/mautrix-gmessages/internal/gateway/store/postgres"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

var (
	ErrDurableFenceLost        = errors.New("durable message write rejected by connection fence")
	ErrDurableInfrastructure   = errors.New("durable messaging infrastructure failure")
	ErrInvalidSettingsSnapshot = errors.New("authenticated settings line snapshot is invalid")
	// ErrACKAdmissionLimited is a local capacity signal. The durable ACK remains
	// pending and the bounded libgm queue retries it; it must not quarantine a
	// connection or escalate as a shared database outage.
	ErrACKAdmissionLimited = errors.New("durable ACK admission capacity unavailable")
)

var errMalformedProviderEnvelope = errors.New("malformed or unknown provider envelope")

type InboxProcessor interface {
	Process(context.Context, ingress.Envelope) (ingress.ProcessResult, error)
}

type ProviderACKStore interface {
	MarkProviderACKedFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, []string) (bool, error)
	ListPendingProviderACKsFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, int) ([]string, error)
	CoordinateProviderACKsFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, time.Duration, []string, func(context.Context, []string) error) (ingress.ACKCoordinationResult, error)
}

const (
	MinimumACKCoordinationTimeout = 100 * time.Millisecond
	DefaultACKCoordinationTimeout = 4 * time.Second
	// DefaultACKConcurrency reserves most of the production 32-connection DB
	// pool for lease renewal, ingress, and API work while ACK HTTP is in flight.
	DefaultACKConcurrency = 8
	MaxACKConcurrency     = 16
)

// processACKSlots is a defense-in-depth process-wide ceiling. The configured
// sink limit is normally lower (eight in production), while this shared cap
// prevents independently composed runtimes in one process from consuming an
// entire 32-connection PostgreSQL pool with lock-holding ACK transactions.
var processACKSlots = make(chan struct{}, MaxACKConcurrency)

func (sink *DurableSink) PendingACKs(ctx context.Context, ownership connectionactor.ProviderOwnership, limit int) ([]string, error) {
	if ownership.Key.TenantID == "" || ownership.Key.ConnectionID == "" || ownership.OwnerID == "" || ownership.FencingToken == 0 || limit < 1 || limit > 256 {
		return nil, domain.ErrInvalidIdentifier
	}
	ids, err := sink.acks.ListPendingProviderACKsFenced(
		ctx, ownership.Key.TenantID, ownership.Key.ConnectionID, ownership.OwnerID, ownership.FencingToken, limit,
	)
	if err != nil {
		return nil, classifyDurablePersistenceError(err)
	}
	for _, id := range ids {
		if !domain.ValidProviderResponseID(id) {
			return nil, errors.Join(ingress.ErrInvalidProviderResponseID, domain.ErrInvalidIdentifier)
		}
	}
	return ids, nil
}

type MediaKeySealer interface {
	Seal(context.Context, session.Scope, []byte) (session.Envelope, error)
}

type DurableSinkConfig struct {
	Inbox      InboxProcessor
	ACKs       ProviderACKStore
	Sealer     MediaKeySealer
	ACKTimeout time.Duration
	// ACKConcurrency bounds process-local transactions that hold connection and
	// lease locks across provider I/O. Production creates one shared DurableSink.
	ACKConcurrency int
}

type DurableSink struct {
	inbox      InboxProcessor
	acks       ProviderACKStore
	sealer     MediaKeySealer
	ackTimeout time.Duration
	ackSlots   chan struct{}
}

func NewDurableSink(config DurableSinkConfig) (*DurableSink, error) {
	if config.Inbox == nil || config.ACKs == nil || config.Sealer == nil {
		return nil, errors.New("durable inbox, ACK store, and media-key sealer are required")
	}
	if config.ACKTimeout == 0 {
		config.ACKTimeout = DefaultACKCoordinationTimeout
	}
	if config.ACKTimeout < MinimumACKCoordinationTimeout || config.ACKTimeout > DefaultACKCoordinationTimeout ||
		config.ACKTimeout >= libgm.ProviderACKRequestTimeout {
		return nil, errors.New("durable ACK transport timeout must be between 100ms and 4s and strictly below the provider request timeout")
	}
	if config.ACKConcurrency == 0 {
		config.ACKConcurrency = DefaultACKConcurrency
	}
	if config.ACKConcurrency < 1 || config.ACKConcurrency > MaxACKConcurrency {
		return nil, errors.New("durable ACK concurrency must be between 1 and 16")
	}
	return &DurableSink{
		inbox: config.Inbox, acks: config.ACKs, sealer: config.Sealer, ackTimeout: config.ACKTimeout,
		ackSlots: make(chan struct{}, config.ACKConcurrency),
	}, nil
}

func (sink *DurableSink) PersistEnvelope(ctx context.Context, ownership connectionactor.ProviderOwnership, envelope libgm.DurableEnvelope) error {
	_, err := sink.PersistEnvelopeOutcome(ctx, ownership, envelope)
	return err
}

func (sink *DurableSink) PersistEnvelopeOutcome(ctx context.Context, ownership connectionactor.ProviderOwnership, envelope libgm.DurableEnvelope) (libgm.DurableOutcome, error) {
	if ownership.Key.TenantID == "" || ownership.Key.ConnectionID == "" || ownership.OwnerID == "" || ownership.FencingToken == 0 {
		return libgm.DurableOutcomeUnknown, ErrDurableFenceLost
	}
	if !domain.ValidProviderResponseID(envelope.ResponseID) {
		return libgm.DurableOutcomeUnknown, errors.Join(ingress.ErrInvalidProviderResponseID, domain.ErrInvalidIdentifier)
	}
	var projection ingress.Projection
	var mediaJobs []ingress.MediaLocator
	decodeErr := envelope.DecodeError
	withholdACK := false
	if decodeErr == nil {
		var err error
		projection, mediaJobs, err = sink.project(ctx, ownership, envelope.Decoded, envelope.Request)
		if err != nil {
			if errors.Is(err, ErrInvalidSettingsSnapshot) {
				withholdACK = true
			}
			if !errors.Is(err, errMalformedProviderEnvelope) {
				// KMS/session failures are operational: withhold ACK and retry the
				// whole durable transaction rather than poisoning valid media.
				return libgm.DurableOutcomeUnknown, classifyDurablePersistenceError(err)
			}
			decodeErr = err
		}
	}
	poisonReason := ""
	if withholdACK {
		poisonReason = ingress.PoisonReasonInvalidSettingsSnapshot
	}
	result, err := sink.inbox.Process(ctx, ingress.Envelope{
		TenantID: ownership.Key.TenantID, ConnectionID: ownership.Key.ConnectionID,
		OwnerID: ownership.OwnerID, FencingToken: ownership.FencingToken,
		ProviderResponseID: envelope.ResponseID, Raw: envelope.Raw,
		Projection: projection, Media: mediaJobs, DecodeError: decodeErr,
		ACKWithheld: withholdACK, PoisonReason: poisonReason,
	})
	if err != nil {
		return libgm.DurableOutcomeUnknown, classifyDurablePersistenceError(err)
	}
	if !result.ACKEligible {
		if result.ACKWithheld && result.Poisoned {
			return libgm.DurableOutcomeUnknown, errors.Join(libgm.ErrDurablePoisoned, ErrInvalidSettingsSnapshot)
		}
		return libgm.DurableOutcomeUnknown, ErrDurableFenceLost
	}
	if result.Poisoned {
		if result.Duplicate {
			return libgm.DurableOutcomeDuplicatePoisoned, nil
		}
		return libgm.DurableOutcomePoisoned, nil
	}
	return libgm.DurableOutcomeCommitted, nil
}

func (sink *DurableSink) MarkACKed(ctx context.Context, ownership connectionactor.ProviderOwnership, ids []string) error {
	if len(ids) == 0 || len(ids) > 256 {
		return domain.ErrInvalidIdentifier
	}
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if !domain.ValidProviderResponseID(id) {
			return domain.ErrInvalidIdentifier
		}
		if _, duplicate := seen[id]; duplicate {
			return domain.ErrInvalidIdentifier
		}
		seen[id] = struct{}{}
	}
	owned, err := sink.acks.MarkProviderACKedFenced(ctx, ownership.Key.TenantID, ownership.Key.ConnectionID, ownership.OwnerID, ownership.FencingToken, append([]string(nil), ids...))
	if err != nil {
		return classifyDurablePersistenceError(err)
	}
	if !owned {
		return ErrDurableFenceLost
	}
	return nil
}

func (sink *DurableSink) ACKTimeout() time.Duration { return sink.ackTimeout }

func (sink *DurableSink) CoordinateACKs(
	ctx context.Context,
	ownership connectionactor.ProviderOwnership,
	candidates []string,
	send libgm.ACKBatchSender,
) (libgm.ACKCoordinationResult, error) {
	result := libgm.ACKCoordinationResult{}
	if ctx == nil || ownership.Key.TenantID == "" || ownership.Key.ConnectionID == "" || ownership.OwnerID == "" ||
		ownership.FencingToken == 0 || len(candidates) == 0 || len(candidates) > 256 || send == nil {
		return result, domain.ErrInvalidIdentifier
	}
	if contextErr := ctx.Err(); contextErr != nil {
		result.RetryIDs = append([]string(nil), candidates...)
		return result, errors.Join(ErrACKAdmissionLimited, contextErr)
	}
	if ownership.LeaseTTL <= postgres.ProviderACKCoordinationHardTimeout || sink.ackTimeout*3 >= ownership.LeaseTTL {
		return result, errors.New("durable ACK timeout must be strictly below one third of the connection lease TTL")
	}
	select {
	case sink.ackSlots <- struct{}{}:
		defer func() { <-sink.ackSlots }()
	case <-ctx.Done():
		result.RetryIDs = append([]string(nil), candidates...)
		return result, errors.Join(ErrACKAdmissionLimited, ctx.Err())
	}
	select {
	case processACKSlots <- struct{}{}:
		defer func() { <-processACKSlots }()
	case <-ctx.Done():
		result.RetryIDs = append([]string(nil), candidates...)
		return result, errors.Join(ErrACKAdmissionLimited, ctx.Err())
	}
	stored, err := sink.acks.CoordinateProviderACKsFenced(
		ctx, ownership.Key.TenantID, ownership.Key.ConnectionID, ownership.OwnerID,
		ownership.FencingToken, ownership.LeaseTTL, append([]string(nil), candidates...), func(sendCtx context.Context, admitted []string) error {
			transportCtx, cancel := context.WithTimeout(sendCtx, sink.ackTimeout)
			defer cancel()
			return send(transportCtx, append([]string(nil), admitted...))
		},
	)
	result.AdmittedIDs = append([]string(nil), stored.AdmittedIDs...)
	if stored.ProviderError != nil {
		result.RetryIDs = append([]string(nil), stored.AdmittedIDs...)
		result.ProviderError = stored.ProviderError
		return result, nil
	}
	if err != nil {
		if len(result.AdmittedIDs) > 0 {
			result.RetryIDs = append([]string(nil), result.AdmittedIDs...)
		} else {
			result.RetryIDs = append([]string(nil), candidates...)
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return result, contextErr
		}
		return result, classifyDurablePersistenceError(err)
	}
	return result, nil
}

func classifyDurablePersistenceError(err error) error {
	if err == nil || errors.Is(err, context.Canceled) {
		return err
	}
	switch {
	case errors.Is(err, ErrDurableFenceLost), errors.Is(err, postgres.ErrConnectionLeaseLost):
		return errors.Join(ErrDurableFenceLost, err)
	case errors.Is(err, ingress.ErrConflictingEnvelope), errors.Is(err, ingress.ErrInvalidProviderResponseID),
		errors.Is(err, ingress.ErrProviderResponseCapacity):
		return err
	case errors.Is(err, ErrDurableInfrastructure):
		return err
	default:
		return errors.Join(ErrDurableInfrastructure, err)
	}
}

func (sink *DurableSink) project(ctx context.Context, ownership connectionactor.ProviderOwnership, decoded *libgm.IncomingRPCMessage, request libgm.DurableRequest) (ingress.Projection, []ingress.MediaLocator, error) {
	if decoded == nil {
		return ingress.Projection{}, nil, fmt.Errorf("%w: decoded message is absent", errMalformedProviderEnvelope)
	}
	if decoded.IncomingRPCMessage != nil && decoded.BugleRoute == gmproto.BugleRoute_PairEvent && decoded.Pair != nil {
		return ingress.Projection{}, nil, nil
	}
	if decoded.IncomingRPCMessage != nil && decoded.BugleRoute == gmproto.BugleRoute_GaiaEvent && decoded.Gaia != nil {
		return ingress.Projection{}, nil, nil
	}
	if decoded.PayloadSource == libgm.PayloadSourceLogoutControl {
		if request.Action != gmproto.ActionType_UNSPECIFIED || request.ConversationID != "" || len(request.Cursor) != 0 ||
			!libgm.IsLegacyLogoutControl(decoded.Message) || decoded.DecryptedMessage != nil ||
			decoded.SecondaryMessage != nil {
			return ingress.Projection{}, nil, fmt.Errorf("%w: legacy logout control is malformed", errMalformedProviderEnvelope)
		}
		// The exact raw control is the durable evidence. It projects no provider
		// data and is delivered as GaiaLoggedOut only after Commit returns.
		return ingress.Projection{}, nil, nil
	}
	if decoded.PayloadSource == libgm.PayloadSourceEncryptedData2 {
		account := decoded.SecondaryMessage.GetAccountChange().GetAccount()
		if request.Action != gmproto.ActionType_UNSPECIFIED || request.ConversationID != "" || len(request.Cursor) != 0 ||
			decoded.Message == nil || decoded.Message.GetAction() != gmproto.ActionType_GET_UPDATES || decoded.Message.GetSessionID() != "" ||
			len(account) == 0 || len(account) > 512 || !utf8.ValidString(account) || !strings.ContainsRune(account, '@') || strings.IndexFunc(account, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return ingress.Projection{}, nil, fmt.Errorf("%w: secondary provider payload is not an account change", errMalformedProviderEnvelope)
		}
		return ingress.Projection{}, nil, nil
	}
	if decoded.PayloadSource != libgm.PayloadSourceEncryptedData {
		return ingress.Projection{}, nil, fmt.Errorf("%w: provider response payload is not authenticated", errMalformedProviderEnvelope)
	}
	switch response := decoded.DecryptedMessage.(type) {
	case *gmproto.ListConversationsResponse:
		if request.Action != gmproto.ActionType_LIST_CONVERSATIONS {
			return ingress.Projection{}, nil, fmt.Errorf("%w: list-conversations request action is absent or mismatched", errMalformedProviderEnvelope)
		}
		next, terminal, err := responseBackfillCursor(response.GetCursorBytes(), response.GetCursor())
		if err != nil {
			return ingress.Projection{}, nil, fmt.Errorf("%w: provider conversation cursor is invalid", errMalformedProviderEnvelope)
		}
		projection, err := projectConversations(response.GetConversations())
		if err == nil && !terminal {
			projection.CursorBase = append([]byte(nil), request.Cursor...)
			projection.CursorCandidate = next
			projection.CursorSource = ingress.CursorSourceListConversations
			projection.CursorConversationID = ingress.ProviderPageCursorID
		}
		// The provider's conversation-list cursor covers every conversation in
		// the page and all of their message pages. It is checkpointed by the
		// actor-owned backfill coordinator only after those children complete.
		return projection, nil, err
	case *gmproto.ListMessagesResponse:
		if request.Action != gmproto.ActionType_LIST_MESSAGES || !domain.ValidProviderConversationID(request.ConversationID) {
			return ingress.Projection{}, nil, fmt.Errorf("%w: list-messages request target is absent or invalid", errMalformedProviderEnvelope)
		}
		for _, message := range response.GetMessages() {
			if message == nil || message.GetConversationID() != request.ConversationID {
				return ingress.Projection{}, nil, fmt.Errorf("%w: list-messages response crossed its requested conversation", errMalformedProviderEnvelope)
			}
		}
		projection, mediaJobs, err := sink.projectMessages(ctx, ownership, &gmproto.MessageEvent{Data: response.GetMessages()}, ingress.MessageProvenanceHistory)
		if err != nil {
			return ingress.Projection{}, nil, err
		}
		projection.Cursor, err = backfillCursor(nil, response.GetCursor())
		if err == nil && len(projection.Cursor) > 0 {
			projection.CursorBase = append([]byte(nil), request.Cursor...)
			projection.CursorCandidate = append([]byte(nil), projection.Cursor...)
			projection.CursorSource = ingress.CursorSourceListMessages
			projection.CursorConversationID = request.ConversationID
		}
		return projection, mediaJobs, err
	}
	if decoded.Message != nil && decoded.Message.Action == request.Action &&
		libgm.IsKnownCorrelatedRPCResponse(request.Action, decoded.DecryptedMessage, decoded.PayloadSource, decoded.DecryptedData) {
		// The exact raw provider response is the durable record for correlated
		// query/mutation replies. Outbound dispatch persists/rechecks its own
		// attempt and route transitions around provider I/O; inventing an inbox
		// message projection here would conflate relay acceptance with delivery.
		return ingress.Projection{}, nil, nil
	}
	updates, ok := decoded.DecryptedMessage.(*gmproto.UpdateEvents)
	if !ok {
		switch decoded.BugleRoute {
		case gmproto.BugleRoute_PairEvent, gmproto.BugleRoute_GaiaEvent:
			return ingress.Projection{}, nil, nil
		default:
			return ingress.Projection{}, nil, fmt.Errorf("%w: data event has an unknown projection", errMalformedProviderEnvelope)
		}
	}
	switch event := updates.Event.(type) {
	case *gmproto.UpdateEvents_ConversationEvent:
		if event.ConversationEvent == nil {
			return ingress.Projection{}, nil, fmt.Errorf("%w: conversation event is absent", errMalformedProviderEnvelope)
		}
		projection, err := projectConversations(event.ConversationEvent.GetData())
		return projection, nil, err
	case *gmproto.UpdateEvents_MessageEvent:
		if event.MessageEvent == nil {
			return ingress.Projection{}, nil, fmt.Errorf("%w: message event is absent", errMalformedProviderEnvelope)
		}
		provenance := ingress.MessageProvenanceLive
		if decoded.IsOld {
			provenance = ingress.MessageProvenanceReplay
		}
		return sink.projectMessages(ctx, ownership, event.MessageEvent, provenance)
	case *gmproto.UpdateEvents_SettingsEvent:
		if event.SettingsEvent == nil {
			return ingress.Projection{}, nil, fmt.Errorf("%w: settings event is absent", errMalformedProviderEnvelope)
		}
		if len(event.SettingsEvent.GetSIMCards()) == 0 {
			// Empty Settings events are not evidence that the phone no longer has
			// lines; preserve the last authenticated non-empty snapshot.
			return ingress.Projection{}, nil, nil
		}
		if len(event.SettingsEvent.GetSIMCards()) > ingress.MaxProjectedLines {
			return ingress.Projection{}, nil, errors.Join(errMalformedProviderEnvelope, ErrInvalidSettingsSnapshot)
		}
		connection := domain.Connection{ID: ownership.Key.ConnectionID, TenantID: ownership.Key.TenantID}
		mapped := MapSettingsLines(connection, event.SettingsEvent)
		if len(mapped.Rejected) != 0 || len(mapped.Lines) != len(event.SettingsEvent.GetSIMCards()) || len(mapped.Lines) == 0 {
			return ingress.Projection{}, nil, errors.Join(errMalformedProviderEnvelope, ErrInvalidSettingsSnapshot)
		}
		projection := ingress.Projection{LineSnapshot: true, Lines: make([]ingress.ProjectedLine, 0, len(mapped.Lines))}
		for _, discovered := range mapped.Lines {
			projection.Lines = append(projection.Lines, ingress.ProjectedLine{
				ID: discovered.Line.ID, TenantID: discovered.Line.TenantID, ConnectionID: discovered.Line.ConnectionID,
				ProviderParticipantID: discovered.Line.ProviderParticipantID, ProviderOutgoingID: discovered.Line.ProviderOutgoingID,
				Phone: discovered.Phone.String(), DisplayName: discovered.Line.DisplayName,
				CarrierName: discovered.CarrierName, ColorHex: discovered.ColorHex, RCSEnabled: discovered.RCSEnabled,
				ProviderSIMNumber: discovered.ProviderSIMNumber, ProviderSIMPayloadType: discovered.ProviderSIMPayloadType,
				DiscoverySource: ingress.LineDiscoveryAuthenticatedGoogleSettings,
			})
		}
		if err := ingress.ValidateProjection(projection, nil); err != nil {
			return ingress.Projection{}, nil, errors.Join(errMalformedProviderEnvelope, ErrInvalidSettingsSnapshot, err)
		}
		return projection, nil, nil
	case *gmproto.UpdateEvents_UserAlertEvent,
		*gmproto.UpdateEvents_TypingEvent,
		*gmproto.UpdateEvents_BrowserPresenceCheckEvent,
		*gmproto.UpdateEvents_AccountChange:
		return ingress.Projection{}, nil, nil
	default:
		return ingress.Projection{}, nil, fmt.Errorf("%w: update event is unknown", errMalformedProviderEnvelope)
	}
}

func projectConversations(conversations []*gmproto.Conversation) (ingress.Projection, error) {
	if len(conversations) > ingress.MaxProjectedConversations {
		return ingress.Projection{}, fmt.Errorf("%w: too many provider conversations", errMalformedProviderEnvelope)
	}
	projection := ingress.Projection{Conversations: make([]ingress.ProjectedConversation, 0, len(conversations))}
	for _, conversation := range conversations {
		if conversation == nil || !domain.ValidProviderConversationID(conversation.GetConversationID()) ||
			!boundedProviderID(strings.TrimSpace(conversation.GetDefaultOutgoingID()), true) {
			return ingress.Projection{}, fmt.Errorf("%w: provider conversation identity is incomplete or excessive", errMalformedProviderEnvelope)
		}
		projection.Conversations = append(projection.Conversations, ingress.ProjectedConversation{
			ConversationID: conversation.GetConversationID(), DefaultOutgoingID: strings.TrimSpace(conversation.GetDefaultOutgoingID()),
			IsGroup: conversation.GetIsGroupChat(),
		})
	}
	return projection, nil
}

func backfillCursor(opaque []byte, cursor *gmproto.Cursor) ([]byte, error) {
	if cursor != nil {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(cursor)
		if err != nil {
			return nil, fmt.Errorf("%w: provider cursor is invalid or excessive", errMalformedProviderEnvelope)
		}
		canonical, canonicalErr := ingress.CanonicalProviderCursor(encoded)
		if canonicalErr != nil {
			return nil, fmt.Errorf("%w: provider cursor is invalid or excessive", errMalformedProviderEnvelope)
		}
		return canonical, nil
	}
	canonical, err := ingress.CanonicalProviderCursor(opaque)
	if err != nil {
		return nil, fmt.Errorf("%w: provider cursor is invalid or excessive", errMalformedProviderEnvelope)
	}
	return canonical, nil
}

func (sink *DurableSink) projectMessages(ctx context.Context, ownership connectionactor.ProviderOwnership, event *gmproto.MessageEvent, provenance ingress.MessageProvenance) (ingress.Projection, []ingress.MediaLocator, error) {
	if err := validateMessageEvent(event); err != nil {
		return ingress.Projection{}, nil, err
	}
	projection := ingress.Projection{Messages: make([]ingress.ProjectedMessage, 0, len(event.GetData()))}
	var mediaJobs []ingress.MediaLocator
	for _, providerMessage := range event.GetData() {
		if providerMessage == nil || !domain.ValidProviderIdentifier(providerMessage.GetMessageID()) ||
			!domain.ValidProviderConversationID(providerMessage.GetConversationID()) {
			return ingress.Projection{}, nil, fmt.Errorf("%w: provider message identity is incomplete", errMalformedProviderEnvelope)
		}
		var text strings.Builder
		attachmentIndex := 0
		for _, info := range providerMessage.GetMessageInfo() {
			if content := info.GetMessageContent(); content != nil {
				text.WriteString(content.GetContent())
			}
			mediaContent := info.GetMediaContent()
			if mediaContent == nil {
				continue
			}
			position := attachmentIndex
			attachmentIndex++
			if mediaContent.GetMediaID() == "" {
				// Thumbnail-only attachment: project the message without a media job. The
				// full-size update re-delivers this message with a MediaID at the same position,
				// so positions must not shift when an attachment is skipped.
				continue
			}
			job, err := sink.mediaJob(ctx, ownership, providerMessage, mediaContent)
			if err != nil {
				return ingress.Projection{}, nil, err
			}
			job.Position = position
			mediaJobs = append(mediaJobs, job)
		}
		providerStatus := providerMessage.GetMessageStatus().GetStatus()
		direction := providerMessageDirection(providerStatus)
		projection.Messages = append(projection.Messages, ingress.ProjectedMessage{
			ProviderMessageID: providerMessage.GetMessageID(), ProviderTmpID: providerMessage.GetTmpID(),
			ConversationID: providerMessage.GetConversationID(), Direction: direction, Provenance: provenance,
			ProviderStatus: providerStatus.String(), ProviderOccurredAt: trustedProviderMessageTime(providerMessage.GetTimestamp()),
			Actionable: provenance == ingress.MessageProvenanceLive && direction == "inbound" && providerInboundReady(providerStatus),
			Sender:     exactParticipantE164(providerMessage.GetSenderParticipant()), Text: text.String(),
			Transport: mapProviderTransport(providerMessage.GetType()), State: MapProviderMessageState(providerStatus),
		})
	}
	return projection, mediaJobs, nil
}

func exactParticipantE164(participant *gmproto.Participant) string {
	if participant == nil {
		return ""
	}
	for _, candidate := range []string{participant.GetFormattedNumber(), participant.GetID().GetNumber()} {
		phone, err := domain.ParseE164(candidate)
		if err == nil {
			return phone.String()
		}
	}
	return ""
}

func validateMessageEvent(event *gmproto.MessageEvent) error {
	if len(event.GetData()) > ingress.MaxProjectedMessages {
		return fmt.Errorf("%w: too many provider messages", errMalformedProviderEnvelope)
	}
	totalInfos, totalMedia, totalText := 0, 0, 0
	seenMessages := make(map[string]struct{}, len(event.GetData()))
	for _, message := range event.GetData() {
		if message == nil || !boundedProviderID(message.GetMessageID(), false) ||
			!boundedProviderID(message.GetConversationID(), false) || !boundedProviderID(message.GetTmpID(), true) {
			return fmt.Errorf("%w: provider message identity is incomplete or excessive", errMalformedProviderEnvelope)
		}
		if _, duplicate := seenMessages[message.GetMessageID()]; duplicate {
			return fmt.Errorf("%w: provider message identity is duplicated", errMalformedProviderEnvelope)
		}
		seenMessages[message.GetMessageID()] = struct{}{}
		infos := message.GetMessageInfo()
		totalInfos += len(infos)
		if len(infos) > 256 || totalInfos > 1024 {
			return fmt.Errorf("%w: provider message info cardinality exceeds limit", errMalformedProviderEnvelope)
		}
		messageMedia := 0
		for _, info := range infos {
			if info == nil {
				return fmt.Errorf("%w: provider message info is absent", errMalformedProviderEnvelope)
			}
			if content := info.GetMessageContent(); content != nil {
				if !validProviderText(content.GetContent()) {
					return fmt.Errorf("%w: provider message text exceeds limit", errMalformedProviderEnvelope)
				}
				totalText += len(content.GetContent())
				if totalText > ingress.MaxProjectionTextBytes {
					return fmt.Errorf("%w: aggregate provider text exceeds limit", errMalformedProviderEnvelope)
				}
			}
			media := info.GetMediaContent()
			if media == nil {
				continue
			}
			messageMedia++
			totalMedia++
			if messageMedia > ingress.MaxAttachmentsPerMessage || totalMedia > ingress.MaxProjectedAttachments ||
				// MediaID is empty for thumbnail-only RCS images until the full-size image is requested.
				!boundedProviderID(media.GetMediaID(), true) || !boundedProviderID(media.GetThumbnailMediaID(), true) ||
				!boundedProviderMetadata(media.GetMimeType()) ||
				!boundedProviderMetadata(media.GetMediaName()) || media.GetSize() < 0 || media.GetSize() > ingress.MaxDeclaredMediaBytes ||
				len(media.GetDecryptionKey()) > 4096 || len(media.GetThumbnailDecryptionKey()) > 4096 {
				return fmt.Errorf("%w: provider media fields exceed limit", errMalformedProviderEnvelope)
			}
		}
	}
	return nil
}

func boundedProviderID(value string, optional bool) bool {
	if value == "" {
		return optional
	}
	return domain.ValidProviderIdentifier(value)
}

func boundedProviderMetadata(value string) bool {
	return len(value) <= ingress.MaxMediaMetadataBytes && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func validProviderText(value string) bool {
	return len(value) <= ingress.MaxMessageTextBytes && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func (sink *DurableSink) mediaJob(ctx context.Context, ownership connectionactor.ProviderOwnership, message *gmproto.Message, content *gmproto.MediaContent) (ingress.MediaLocator, error) {
	if content.GetMediaID() == "" {
		return ingress.MediaLocator{}, fmt.Errorf("%w: provider media locator is missing", errMalformedProviderEnvelope)
	}
	scope := session.Scope{TenantID: string(ownership.Key.TenantID), ConnectionID: string(ownership.Key.ConnectionID), Provider: "gmessages-media"}
	var keyEnvelope, thumbnailEnvelope session.Envelope
	var keyDigest, thumbnailDigest [sha256.Size]byte
	var err error
	if key := content.GetDecryptionKey(); len(key) > 0 {
		plaintext := append([]byte(nil), key...)
		keyDigest = sha256.Sum256(plaintext)
		keyEnvelope, err = sink.sealer.Seal(ctx, scope, plaintext)
		zeroBytes(plaintext)
		if err != nil {
			return ingress.MediaLocator{}, err
		}
	}
	if key := content.GetThumbnailDecryptionKey(); len(key) > 0 {
		plaintext := append([]byte(nil), key...)
		thumbnailDigest = sha256.Sum256(plaintext)
		thumbnailEnvelope, err = sink.sealer.Seal(ctx, scope, plaintext)
		zeroBytes(plaintext)
		if err != nil {
			return ingress.MediaLocator{}, err
		}
	}
	return ingress.MediaLocator{
		ProviderMessageID: message.GetMessageID(),
		Locator:           "gmessages:" + base64.RawURLEncoding.EncodeToString([]byte(content.GetMediaID())),
		MIMEType:          content.GetMimeType(), DeclaredSize: content.GetSize(), DisplayFilename: content.GetMediaName(),
		KeyEnvelope: keyEnvelope, ThumbnailKeyEnvelope: thumbnailEnvelope,
		KeyDigest: keyDigest, ThumbnailKeyDigest: thumbnailDigest,
	}, nil
}

func MapProviderMessageState(status gmproto.MessageStatusType) domain.MessageState {
	switch status {
	case gmproto.MessageStatusType_OUTGOING_COMPLETE:
		return domain.MessageStateSent
	case gmproto.MessageStatusType_OUTGOING_DELIVERED:
		return domain.MessageStateDelivered
	case gmproto.MessageStatusType_OUTGOING_DISPLAYED:
		return domain.MessageStateRead
	case gmproto.MessageStatusType_INCOMING_COMPLETE, gmproto.MessageStatusType_INCOMING_DELIVERED:
		return domain.MessageStateDelivered
	case gmproto.MessageStatusType_INCOMING_DISPLAYED:
		return domain.MessageStateRead
	case gmproto.MessageStatusType_OUTGOING_FAILED_GENERIC,
		gmproto.MessageStatusType_OUTGOING_FAILED_EMERGENCY_NUMBER,
		gmproto.MessageStatusType_OUTGOING_CANCELED,
		gmproto.MessageStatusType_OUTGOING_FAILED_TOO_LARGE,
		gmproto.MessageStatusType_OUTGOING_FAILED_RECIPIENT_LOST_RCS,
		gmproto.MessageStatusType_OUTGOING_FAILED_NO_RETRY_NO_FALLBACK,
		gmproto.MessageStatusType_OUTGOING_FAILED_RECIPIENT_DID_NOT_DECRYPT,
		gmproto.MessageStatusType_OUTGOING_FAILED_RECIPIENT_LOST_ENCRYPTION,
		gmproto.MessageStatusType_OUTGOING_FAILED_RECIPIENT_DID_NOT_DECRYPT_NO_MORE_RETRY,
		gmproto.MessageStatusType_OUTGOING_FAILED_RECIPIENT_NEGATIVE_DELIVERY,
		gmproto.MessageStatusType_MESSAGE_STATUS_OUTGOING_FAILED_EMERGENCY_PROTOCOL_DETERMINATION_MESSAGE,
		gmproto.MessageStatusType_OUTGOING_RESTRICTED,
		gmproto.MessageStatusType_OUTGOING_FAILED_TO_ENCRYPT:
		return domain.MessageStateFailed
	default:
		return ""
	}
}

func providerMessageDirection(status gmproto.MessageStatusType) string {
	switch {
	case status >= gmproto.MessageStatusType_OUTGOING_COMPLETE && status <= gmproto.MessageStatusType_OUTGOING_FAILED_TO_ENCRYPT:
		return "outbound"
	case status >= gmproto.MessageStatusType_INCOMING_COMPLETE && status <= gmproto.MessageStatusType_INCOMING_DOWNLOAD_RESTRICTED:
		return "inbound"
	default:
		return "unknown"
	}
}

func providerInboundReady(status gmproto.MessageStatusType) bool {
	return status == gmproto.MessageStatusType_INCOMING_COMPLETE
}

func trustedProviderMessageTime(microseconds int64) time.Time {
	const earliest = int64(946684800000000) // 2000-01-01T00:00:00Z
	const latest = int64(7258118400000000)  // 2200-01-01T00:00:00Z
	if microseconds < earliest || microseconds >= latest {
		return time.Time{}
	}
	return time.UnixMicro(microseconds).UTC()
}

func mapProviderTransport(providerType int64) string {
	switch providerType {
	case 1:
		return "sms"
	case 2, 3:
		return "mms"
	case 4:
		return "rcs"
	default:
		return ""
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

var _ DurableMessageSink = (*DurableSink)(nil)
