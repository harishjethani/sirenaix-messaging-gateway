// Package messaging owns tenant-scoped command validation and outbound
// idempotency. HTTP and broker adapters both call Service.Submit.
package messaging

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
)

const (
	RouteModePhoneDefault = "phone_default"
	maxTextBytes          = 64 * 1024
	maxIdempotencyBytes   = 200
)

var (
	ErrInvalidCommand      = errors.New("invalid message command")
	ErrInvalidRoute        = errors.New("invalid message route")
	ErrIdempotencyConflict = errors.New("idempotency key reused with different request")
	ErrNotFound            = errors.New("message not found")
)

type SendInput struct {
	ConnectionID   domain.ConnectionID
	ConversationID string
	Recipient      string
	LineID         domain.LineID
	RouteMode      string
	Text           string
	MediaIDs       []domain.MediaID
}

type OutboundMessage struct {
	ID                domain.MessageID
	TenantID          domain.TenantID
	ConnectionID      domain.ConnectionID
	ConversationID    string
	Recipient         string
	LineID            domain.LineID
	RouteMode         string
	Text              string
	MediaIDs          []domain.MediaID
	ProviderTmpID     string
	ProviderMessageID string
	Direction         string
	Transport         string
	Attachments       []Attachment
	State             domain.MessageState
	CreatedAt         time.Time
}

type Attachment struct {
	MediaID  domain.MediaID
	Position int
}

type CreateOutcome uint8

const (
	CreateInserted CreateOutcome = iota + 1
	CreateDuplicate
	CreateConflict
)

type CreateOutbound struct {
	IdempotencyKey string
	RequestDigest  [32]byte
	Message        OutboundMessage
	// CommandAudit is written in the same transaction as Message. It is set
	// only by authenticated broker adapters; tenant identity remains the
	// separately-authorized tenantID argument.
	CommandAudit *CommandAudit
}

type CommandAudit struct {
	Topic            string
	Partition        int32
	Offset           int64
	ProducerIdentity string
	CorrelationID    string
	PayloadDigest    [32]byte
}

type CreateResult struct {
	Outcome CreateOutcome
	Message OutboundMessage
}

type ListOptions struct {
	After domain.MessageID
	Limit int
}

type MessagePage struct {
	Messages   []OutboundMessage
	NextCursor domain.MessageID
}

type ListStore interface {
	ListMessages(context.Context, domain.TenantID, ListOptions) (MessagePage, error)
}

type Store interface {
	// CreateOutbound atomically stores the idempotency record, queued message,
	// initial immutable status, and corresponding outbox event.
	CreateOutbound(context.Context, CreateOutbound) (CreateResult, error)
	GetMessage(context.Context, domain.TenantID, domain.MessageID) (OutboundMessage, error)
}

type Config struct {
	Store Store
	NewID func() string
	Now   func() time.Time
}

type Service struct {
	store Store
	newID func() string
	now   func() time.Time
}

func NewService(config Config) (*Service, error) {
	if config.Store == nil || config.NewID == nil {
		return nil, ErrInvalidCommand
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	return &Service{store: config.Store, newID: config.NewID, now: config.Now}, nil
}

func (service *Service) Submit(ctx context.Context, tenantID domain.TenantID, idempotencyKey string, input SendInput) (OutboundMessage, error) {
	return service.submit(ctx, tenantID, idempotencyKey, input, nil)
}

// SubmitAuthenticatedCommand is the Kafka entry point for the same
// application command used by HTTP. The authenticated broker audit is passed
// through to Store.CreateOutbound so it commits before an offset is eligible
// for acknowledgement.
func (service *Service) SubmitAuthenticatedCommand(ctx context.Context, tenantID domain.TenantID, idempotencyKey string, input SendInput, audit CommandAudit) (OutboundMessage, error) {
	if !audit.valid() {
		return OutboundMessage{}, ErrInvalidCommand
	}
	return service.submit(ctx, tenantID, idempotencyKey, input, &audit)
}

func (service *Service) submit(ctx context.Context, tenantID domain.TenantID, idempotencyKey string, input SendInput, audit *CommandAudit) (OutboundMessage, error) {
	if tenantID == "" || !validIdempotencyKey(idempotencyKey) || input.ConnectionID == "" || !validContent(input) {
		return OutboundMessage{}, ErrInvalidCommand
	}
	if err := validateRoute(input); err != nil {
		return OutboundMessage{}, err
	}
	id := domain.MessageID(service.newID())
	if id == "" {
		return OutboundMessage{}, ErrInvalidCommand
	}
	message := OutboundMessage{
		ID: id, TenantID: tenantID, ConnectionID: input.ConnectionID,
		ConversationID: strings.TrimSpace(input.ConversationID), Recipient: strings.TrimSpace(input.Recipient),
		LineID: input.LineID, RouteMode: input.RouteMode, Text: input.Text,
		MediaIDs: append([]domain.MediaID(nil), input.MediaIDs...), Direction: "outbound",
		ProviderTmpID: ProviderTemporaryID(tenantID, id), State: domain.MessageStateQueued,
		CreatedAt: service.now().UTC(),
	}
	message.Attachments = make([]Attachment, len(message.MediaIDs))
	for index, mediaID := range message.MediaIDs {
		message.Attachments[index] = Attachment{MediaID: mediaID, Position: index}
	}
	result, err := service.store.CreateOutbound(ctx, CreateOutbound{
		IdempotencyKey: idempotencyKey,
		RequestDigest:  CanonicalRequestDigest(input),
		Message:        message,
		CommandAudit:   audit,
	})
	if err != nil {
		return OutboundMessage{}, err
	}
	switch result.Outcome {
	case CreateInserted, CreateDuplicate:
		return result.Message, nil
	case CreateConflict:
		return OutboundMessage{}, ErrIdempotencyConflict
	default:
		return OutboundMessage{}, errors.New("invalid message store result")
	}
}

func (audit CommandAudit) valid() bool {
	return audit.Topic != "" && len(audit.Topic) <= 249 && audit.Partition >= 0 && audit.Offset >= 0 &&
		audit.ProducerIdentity != "" && len(audit.ProducerIdentity) <= 512 && len(audit.CorrelationID) <= 512 &&
		audit.PayloadDigest != ([32]byte{})
}

func (service *Service) Get(ctx context.Context, tenantID domain.TenantID, messageID domain.MessageID) (OutboundMessage, error) {
	if tenantID == "" || messageID == "" {
		return OutboundMessage{}, ErrNotFound
	}
	message, err := service.store.GetMessage(ctx, tenantID, messageID)
	if err != nil {
		return OutboundMessage{}, err
	}
	if message.TenantID != tenantID || message.ID != messageID {
		return OutboundMessage{}, ErrNotFound
	}
	return message, nil
}

func (service *Service) List(ctx context.Context, tenantID domain.TenantID, options ListOptions) (MessagePage, error) {
	if tenantID == "" || options.Limit < 1 || options.Limit > 200 {
		return MessagePage{}, ErrInvalidCommand
	}
	store, ok := service.store.(ListStore)
	if !ok {
		return MessagePage{}, errors.New("message listing is unavailable")
	}
	page, err := store.ListMessages(ctx, tenantID, options)
	if err != nil {
		return MessagePage{}, err
	}
	for _, message := range page.Messages {
		if message.TenantID != tenantID || message.ID == "" {
			return MessagePage{}, ErrNotFound
		}
	}
	return page, nil
}

// ProviderTemporaryID derives the outbound TmpID deterministically from the
// tenant and message so dispatch retries reuse it. It must be a UUID: Google
// Messages only echoes TmpID on outgoing message updates in the native-app UUID
// format, and an empty echo breaks correlation of sent/delivered/read receipts.
func ProviderTemporaryID(tenantID domain.TenantID, messageID domain.MessageID) string {
	digest := sha256.Sum256([]byte(string(tenantID) + "\x00" + string(messageID)))
	var id uuid.UUID
	copy(id[:], digest[:16])
	id[6] = (id[6] & 0x0f) | 0x80 // RFC 9562 version 8 (custom, hash-derived)
	id[8] = (id[8] & 0x3f) | 0x80 // RFC 9562 variant
	return id.String()
}

func CanonicalRequestDigest(input SendInput) [32]byte {
	hash := sha256.New()
	for _, value := range []string{
		string(input.ConnectionID), strings.TrimSpace(input.ConversationID), strings.TrimSpace(input.Recipient),
		string(input.LineID), input.RouteMode, input.Text,
	} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	for _, mediaID := range input.MediaIDs {
		value := string(mediaID)
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func validIdempotencyKey(key string) bool {
	if key == "" || len(key) > maxIdempotencyBytes || strings.TrimSpace(key) != key {
		return false
	}
	for index := range len(key) {
		if key[index] < 0x21 || key[index] > 0x7e {
			return false
		}
	}
	return true
}

func validContent(input SendInput) bool {
	if !utf8.ValidString(input.Text) || len(input.Text) > maxTextBytes {
		return false
	}
	if strings.TrimSpace(input.Text) == "" && len(input.MediaIDs) == 0 {
		return false
	}
	if len(input.MediaIDs) > 16 {
		return false
	}
	seen := make(map[domain.MediaID]struct{}, len(input.MediaIDs))
	for _, mediaID := range input.MediaIDs {
		if mediaID == "" {
			return false
		}
		if _, exists := seen[mediaID]; exists {
			return false
		}
		seen[mediaID] = struct{}{}
	}
	return true
}

func validateRoute(input SendInput) error {
	conversationID := strings.TrimSpace(input.ConversationID)
	recipient := strings.TrimSpace(input.Recipient)
	if conversationID != "" {
		if !domain.ValidProviderConversationID(conversationID) || recipient != "" || input.RouteMode != "" {
			return ErrInvalidRoute
		}
		return nil
	}
	if input.RouteMode != RouteModePhoneDefault || input.LineID != "" || recipient == "" || strings.ContainsAny(recipient, ",;") {
		return ErrInvalidRoute
	}
	if _, err := domain.ParseE164(recipient); err != nil {
		return ErrInvalidRoute
	}
	return nil
}
