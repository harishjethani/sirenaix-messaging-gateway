package messaging_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/messaging"
)

type memoryCommands struct {
	byKey    map[string]messaging.OutboundMessage
	digests  map[string][32]byte
	byID     map[domain.MessageID]messaging.OutboundMessage
	statuses map[domain.MessageID][]domain.MessageState
	last     messaging.CreateOutbound
}

func newMemoryCommands() *memoryCommands {
	return &memoryCommands{
		byKey: make(map[string]messaging.OutboundMessage), digests: make(map[string][32]byte),
		byID: make(map[domain.MessageID]messaging.OutboundMessage), statuses: make(map[domain.MessageID][]domain.MessageState),
	}
}

func commandKey(tenant domain.TenantID, key string) string { return string(tenant) + "\x00" + key }

func (store *memoryCommands) CreateOutbound(_ context.Context, command messaging.CreateOutbound) (messaging.CreateResult, error) {
	store.last = command
	key := commandKey(command.Message.TenantID, command.IdempotencyKey)
	if existing, ok := store.byKey[key]; ok {
		if store.digests[key] != command.RequestDigest {
			return messaging.CreateResult{Outcome: messaging.CreateConflict}, nil
		}
		return messaging.CreateResult{Outcome: messaging.CreateDuplicate, Message: existing}, nil
	}
	store.byKey[key] = command.Message
	store.digests[key] = command.RequestDigest
	store.byID[command.Message.ID] = command.Message
	store.statuses[command.Message.ID] = []domain.MessageState{domain.MessageStateQueued}
	return messaging.CreateResult{Outcome: messaging.CreateInserted, Message: command.Message}, nil
}

func TestSubmitAuthenticatedCommandCarriesBrokerAuditIntoApplicationTransaction(t *testing.T) {
	store := newMemoryCommands()
	service, err := messaging.NewService(messaging.Config{Store: store, NewID: func() string { return "018f4ca7-52c4-7c5d-ae9b-5b7a358f9741" }})
	if err != nil {
		t.Fatal(err)
	}
	audit := messaging.CommandAudit{
		Topic: "sirenaix.messaging.commands.v1", Partition: 2, Offset: 8,
		ProducerIdentity: "producer-a", CorrelationID: "correlation-a", PayloadDigest: [32]byte{7},
	}
	message, err := service.SubmitAuthenticatedCommand(context.Background(), "tenant-a", "idem-a", messaging.SendInput{
		ConnectionID: "connection-a", ConversationID: "conversation-a", Text: "hello",
	}, audit)
	if err != nil {
		t.Fatal(err)
	}
	if message.ID == "" || store.last.CommandAudit == nil || *store.last.CommandAudit != audit {
		t.Fatalf("message=%+v application command audit=%+v", message, store.last.CommandAudit)
	}
}

func (store *memoryCommands) GetMessage(_ context.Context, tenant domain.TenantID, id domain.MessageID) (messaging.OutboundMessage, error) {
	message, ok := store.byID[id]
	if !ok || message.TenantID != tenant {
		return messaging.OutboundMessage{}, messaging.ErrNotFound
	}
	message.State = domain.DeriveMessageState(store.statuses[id])
	return message, nil
}

func TestSubmitRequiresTenantScopedIdempotencyAndConverges(t *testing.T) {
	store := newMemoryCommands()
	next := 0
	service, err := messaging.NewService(messaging.Config{Store: store, NewID: func() string {
		next++
		return []string{
			"018f4ca7-52c4-7c5d-ae9b-5b7a358f9741",
			"018f4ca7-52c4-7c5d-ae9b-5b7a358f9742",
			"018f4ca7-52c4-7c5d-ae9b-5b7a358f9743",
			"018f4ca7-52c4-7c5d-ae9b-5b7a358f9744",
		}[next-1]
	}, Now: func() time.Time { return time.Unix(1700000000, 0).UTC() }})
	if err != nil {
		t.Fatal(err)
	}
	input := messaging.SendInput{
		ConnectionID: "connection-a", ConversationID: "conversation-a", Text: "hello",
	}
	first, err := service.Submit(context.Background(), "tenant-a", "idem-a", input)
	if err != nil {
		t.Fatalf("first Submit() error = %v", err)
	}
	second, err := service.Submit(context.Background(), "tenant-a", "idem-a", input)
	if err != nil {
		t.Fatalf("duplicate Submit() error = %v", err)
	}
	if first.ID != second.ID || first.ProviderTmpID != second.ProviderTmpID || next != 2 {
		t.Fatalf("duplicate did not converge: first=%+v second=%+v generated=%d", first, second, next)
	}
	if _, err = service.Submit(context.Background(), "tenant-b", "idem-a", input); err != nil {
		t.Fatalf("same key in another tenant collided: %v", err)
	}
	changed := input
	changed.Text = "changed"
	if _, err = service.Submit(context.Background(), "tenant-a", "idem-a", changed); !errors.Is(err, messaging.ErrIdempotencyConflict) {
		t.Fatalf("changed body error = %v, want ErrIdempotencyConflict", err)
	}
	if _, err = service.Submit(context.Background(), "tenant-a", "", input); !errors.Is(err, messaging.ErrInvalidCommand) {
		t.Fatalf("empty key error = %v, want ErrInvalidCommand", err)
	}
}

func TestSubmitNewChatRequiresPhoneDefaultAndOneE164Recipient(t *testing.T) {
	service, err := messaging.NewService(messaging.Config{Store: newMemoryCommands(), NewID: func() string { return "018f4ca7-52c4-7c5d-ae9b-5b7a358f9741" }})
	if err != nil {
		t.Fatal(err)
	}
	valid := messaging.SendInput{
		ConnectionID: "connection-a", Recipient: "+12025550123", RouteMode: messaging.RouteModePhoneDefault, Text: "hello",
	}
	if _, err = service.Submit(context.Background(), "tenant-a", "one", valid); err != nil {
		t.Fatalf("valid new chat rejected: %v", err)
	}
	for name, mutate := range map[string]func(*messaging.SendInput){
		"missing explicit route": func(input *messaging.SendInput) { input.RouteMode = "" },
		"explicit line":          func(input *messaging.SendInput) { input.LineID = "secondary" },
		"group recipients":       func(input *messaging.SendInput) { input.Recipient = "+12025550123,+12025550124" },
		"local recipient":        func(input *messaging.SendInput) { input.Recipient = "2025550123" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := service.Submit(context.Background(), "tenant-a", "bad-route", candidate); !errors.Is(err, messaging.ErrInvalidRoute) {
				t.Fatalf("Submit() error = %v, want ErrInvalidRoute", err)
			}
		})
	}
}

func TestSubmitRejectsReservedProviderConversationBeforeStoreMutation(t *testing.T) {
	store := newMemoryCommands()
	service, err := messaging.NewService(messaging.Config{Store: store, NewID: func() string { return "018f4ca7-52c4-7c5d-ae9b-5b7a358f9741" }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Submit(context.Background(), "tenant-a", "reserved-route", messaging.SendInput{
		ConnectionID: "connection-a", ConversationID: domain.ProviderPageCursorID, Text: "hello",
	})
	if !errors.Is(err, messaging.ErrInvalidRoute) {
		t.Fatalf("reserved conversation Submit() error = %v, want ErrInvalidRoute", err)
	}
	if len(store.byID) != 0 || store.last.Message.ID != "" {
		t.Fatalf("reserved conversation reached store: last=%+v messages=%+v", store.last, store.byID)
	}
}

// Google Messages only echoes TmpID on outgoing message updates when it is a
// UUID (the native-app format); any other format comes back empty and breaks
// outbound receipt correlation.
func TestDeterministicProviderTemporaryIDIsStableOpaqueUUID(t *testing.T) {
	a := messaging.ProviderTemporaryID("tenant-a", "018f4ca7-52c4-7c5d-ae9b-5b7a358f9741")
	b := messaging.ProviderTemporaryID("tenant-a", "018f4ca7-52c4-7c5d-ae9b-5b7a358f9741")
	c := messaging.ProviderTemporaryID("tenant-b", "018f4ca7-52c4-7c5d-ae9b-5b7a358f9741")
	if a != b || a == c {
		t.Fatalf("temporary IDs a=%q b=%q c=%q", a, b, c)
	}
	parsed, err := uuid.Parse(a)
	if err != nil || parsed.String() != a || parsed.Variant() != uuid.RFC4122 || parsed.Version() != 8 {
		t.Fatalf("temporary ID %q is not a canonical RFC 9562 version 8 UUID: err=%v", a, err)
	}
}
