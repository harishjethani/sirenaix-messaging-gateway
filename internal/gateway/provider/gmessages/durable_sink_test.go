package gmessages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-gmessages/internal/gateway/connectionactor"
	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/ingress"
	"go.mau.fi/mautrix-gmessages/internal/gateway/session"
	"go.mau.fi/mautrix-gmessages/internal/gateway/store/postgres"
	"go.mau.fi/mautrix-gmessages/pkg/libgm"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
)

type sinkInbox struct {
	record  ingress.EnvelopeRecord
	commits int
	result  ingress.CommitResult
}

type cursorCycleInbox struct {
	sinkInbox
	responses map[string][32]byte
	edges     map[[32]byte][32]byte
}

func (store *cursorCycleInbox) CommitEnvelope(_ context.Context, record ingress.EnvelopeRecord) (ingress.CommitResult, error) {
	store.record = record
	store.commits++
	if prior, ok := store.responses[record.ProviderResponseID]; ok && prior == record.Digest {
		return ingress.CommitDuplicate, nil
	}
	store.responses[record.ProviderResponseID] = record.Digest
	if len(record.Projection.CursorCandidate) > 0 {
		next := sha256.Sum256(record.Projection.CursorCandidate)
		var base [32]byte
		if len(record.Projection.CursorBase) > 0 {
			base = sha256.Sum256(record.Projection.CursorBase)
			if _, exists := store.edges[base]; !exists {
				store.edges[base] = [32]byte{}
			}
		}
		if prior, exists := store.edges[next]; exists && prior != base {
			return ingress.CommitPoisoned, nil
		}
		store.edges[next] = base
	}
	return ingress.CommitInserted, nil
}

func (store *sinkInbox) CommitEnvelope(_ context.Context, record ingress.EnvelopeRecord) (ingress.CommitResult, error) {
	store.record = record
	store.commits++
	if store.result != 0 {
		return store.result, nil
	}
	return ingress.CommitInserted, nil
}

func TestDurableSinkCommitsAuthenticatedSettingsLinesBeforeACKEligibility(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	settings := &gmproto.Settings{SIMCards: []*gmproto.SIMCard{
		providerSIM("participant-a", "+12025550101", "Carrier A", 1),
		providerSIM("participant-b", "+12025550102", "Carrier B", 2),
	}}
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), durableTestOwnership(), settingsDurableEnvelope("settings-valid", settings))
	if err != nil || outcome != libgm.DurableOutcomeCommitted || store.commits != 1 || store.record.Poisoned {
		t.Fatalf("valid settings outcome = (%v, %v), commits=%d record=%+v", outcome, err, store.commits, store.record)
	}
	if !store.record.Projection.LineSnapshot || len(store.record.Projection.Lines) != 2 {
		t.Fatalf("durable line snapshot = %+v", store.record.Projection)
	}
	first := store.record.Projection.Lines[0]
	if first.ID == "" || first.TenantID != "tenant-a" || first.ConnectionID != "connection-a" ||
		first.ProviderParticipantID != "participant-a" || first.ProviderOutgoingID != "participant-a" ||
		first.Phone != "+12025550101" || first.CarrierName != "Carrier A" || first.ProviderSIMNumber != 1 ||
		first.DiscoverySource != ingress.LineDiscoveryAuthenticatedGoogleSettings {
		t.Fatalf("first durable line = %+v", first)
	}
}

func TestDurableSinkQuarantinesImpossibleSettingsSnapshotAndWithholdsACK(t *testing.T) {
	negativeSIM := providerSIM("participant-negative", "+12025550103", "Carrier C", -1)
	fixtures := map[string]*gmproto.Settings{
		"more than cap": {SIMCards: func() []*gmproto.SIMCard {
			cards := make([]*gmproto.SIMCard, ingress.MaxProjectedLines+1)
			for index := range cards {
				cards[index] = providerSIM(fmt.Sprintf("participant-%02d", index), fmt.Sprintf("+1202555%04d", index), "Carrier", int32(index+1))
			}
			return cards
		}()},
		"partially invalid": {SIMCards: []*gmproto.SIMCard{
			providerSIM("participant-a", "+12025550101", "Carrier A", 1),
			providerSIM("participant-b", "not-e164", "Carrier B", 2),
		}},
		"negative provider SIM number": {SIMCards: []*gmproto.SIMCard{negativeSIM}},
	}
	for name, settings := range fixtures {
		t.Run(name, func(t *testing.T) {
			store := &sinkInbox{}
			inbox, _ := ingress.NewService(store)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			outcome, err := sink.PersistEnvelopeOutcome(context.Background(), durableTestOwnership(), settingsDurableEnvelope("settings-"+strings.ReplaceAll(name, " ", "-"), settings))
			if outcome != libgm.DurableOutcomeUnknown || !errors.Is(err, ErrInvalidSettingsSnapshot) ||
				!errors.Is(err, libgm.ErrDurablePoisoned) || errors.Is(err, ErrDurableInfrastructure) {
				t.Fatalf("impossible settings outcome = (%v, %v)", outcome, err)
			}
			if store.commits != 1 || !store.record.Poisoned || !store.record.ACKPending || !store.record.ACKWithheld ||
				store.record.PoisonReason != ingress.PoisonReasonInvalidSettingsSnapshot ||
				store.record.Projection.LineSnapshot || len(store.record.Projection.Lines) != 0 {
				t.Fatalf("impossible settings durable poison = commits:%d record:%+v", store.commits, store.record)
			}
		})
	}
}

func TestDurableSinkPreservesRecoveredTerminalSettingsPoison(t *testing.T) {
	store := &sinkInbox{result: ingress.CommitDuplicateACKWithheld}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), durableTestOwnership(), settingsDurableEnvelope(
		"settings-terminal-recovered", &gmproto.Settings{SIMCards: []*gmproto.SIMCard{providerSIM("participant-a", "+12025550101", "Carrier A", 1)}},
	))
	if outcome != libgm.DurableOutcomeUnknown || !errors.Is(err, ErrInvalidSettingsSnapshot) ||
		!errors.Is(err, libgm.ErrDurablePoisoned) || errors.Is(err, ErrDurableFenceLost) {
		t.Fatalf("recovered terminal Settings outcome = (%v, %v)", outcome, err)
	}
	if store.commits != 1 || store.record.Poisoned || store.record.ACKWithheld {
		t.Fatalf("test did not exercise durable-state recovery: %+v", store.record)
	}
}

func TestDurableSinkAcceptsConservativeSettingsLineCapWithoutTruncation(t *testing.T) {
	cards := make([]*gmproto.SIMCard, ingress.MaxProjectedLines)
	for index := range cards {
		cards[index] = providerSIM(fmt.Sprintf("participant-%02d", index), fmt.Sprintf("+1202555%04d", index), "Carrier", int32(index+1))
	}
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), durableTestOwnership(), settingsDurableEnvelope("settings-cap", &gmproto.Settings{SIMCards: cards}))
	if err != nil || outcome != libgm.DurableOutcomeCommitted || !store.record.Projection.LineSnapshot || len(store.record.Projection.Lines) != ingress.MaxProjectedLines {
		t.Fatalf("line cap outcome = (%v, %v), projection=%+v", outcome, err, store.record.Projection)
	}
}

func TestDurableSinkAcceptsMaximumBoundedProviderLineIdentity(t *testing.T) {
	participantID := strings.Repeat("p", domain.MaxProviderConversationIDBytes)
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), durableTestOwnership(), settingsDurableEnvelope(
		"settings-max-participant", &gmproto.Settings{SIMCards: []*gmproto.SIMCard{providerSIM(participantID, "+12025550101", "Carrier", 1)}},
	))
	if err != nil || outcome != libgm.DurableOutcomeCommitted || store.record.Poisoned || len(store.record.Projection.Lines) != 1 {
		t.Fatalf("maximum provider line identity = (%v, %v), record=%+v", outcome, err, store.record)
	}
	lineID := string(store.record.Projection.Lines[0].ID)
	if !domain.ValidProviderIdentifier(lineID) || !strings.HasPrefix(lineID, "gmessages:") {
		t.Fatalf("bounded internal line ID = %q", lineID)
	}
}

func providerSIM(participantID, phone, carrier string, number int32) *gmproto.SIMCard {
	return &gmproto.SIMCard{
		SIMParticipant: &gmproto.SIMParticipant{ID: participantID},
		SIMData: &gmproto.SIMData{
			InternationalPhoneNumber: phone, CarrierName: carrier, ColorHex: "#123456",
			SIMPayload: &gmproto.SIMPayload{SIMNumber: number, Two: 7},
		},
		RCSChats: &gmproto.RCSChats{Enabled: true},
	}
}

func durableTestOwnership() connectionactor.ProviderOwnership {
	return connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}
}

func settingsDurableEnvelope(responseID string, settings *gmproto.Settings) libgm.DurableEnvelope {
	return libgm.DurableEnvelope{
		ResponseID: responseID, Raw: []byte("raw-" + responseID),
		Decoded: &libgm.IncomingRPCMessage{
			PayloadSource:      libgm.PayloadSourceEncryptedData,
			IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
			DecryptedMessage:   &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_SettingsEvent{SettingsEvent: settings}},
		},
	}
}

func TestDurableSinkDistinguishesNewAndDuplicatePoisonForRuntimeEscalation(t *testing.T) {
	for _, fixture := range []struct {
		name        string
		commit      ingress.CommitResult
		wantOutcome libgm.DurableOutcome
	}{
		{name: "new", commit: ingress.CommitPoisoned, wantOutcome: libgm.DurableOutcomePoisoned},
		{name: "duplicate", commit: ingress.CommitDuplicatePoisoned, wantOutcome: libgm.DurableOutcomeDuplicatePoisoned},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			store := &sinkInbox{result: fixture.commit}
			inbox, _ := ingress.NewService(store)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{ResponseID: "response-poison", Raw: []byte("raw"), DecodeError: errors.New("malformed")})
			if err != nil || outcome != fixture.wantOutcome {
				t.Fatalf("poison outcome = (%v, %v), want %v", outcome, err, fixture.wantOutcome)
			}
		})
	}
}

func TestDurableSinkPoisonsMalformedAndUnknownEventsBeforeACKEligibility(t *testing.T) {
	for name, decoded := range map[string]*libgm.IncomingRPCMessage{
		"malformed message": {PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{{
			ConversationID: "conversation-a",
		}}}}}},
		"unknown update": {PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: &gmproto.UpdateEvents{}},
	} {
		t.Run(name, func(t *testing.T) {
			store := &sinkInbox{}
			inbox, _ := ingress.NewService(store)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			err := sink.PersistEnvelope(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{ResponseID: "response-poison", Raw: []byte("raw-poison"), Decoded: decoded})
			if err != nil {
				t.Fatalf("PersistEnvelope() error = %v", err)
			}
			if store.commits != 1 || !store.record.Poisoned || !store.record.ACKPending || store.record.PoisonReason != "decode_failed" {
				t.Fatalf("poison record = %+v commits=%d", store.record, store.commits)
			}
		})
	}
}

func TestDurableSinkPersistsEveryKnownCorrelatedRPCResponseWithoutInventingProjection(t *testing.T) {
	tests := []struct {
		action   gmproto.ActionType
		response proto.Message
	}{
		{gmproto.ActionType_IS_BUGLE_DEFAULT, &gmproto.IsBugleDefaultResponse{}},
		{gmproto.ActionType_NOTIFY_DITTO_ACTIVITY, &gmproto.NotifyDittoActivityResponse{}},
		{gmproto.ActionType_GET_CONVERSATION_TYPE, &gmproto.GetConversationTypeResponse{}},
		{gmproto.ActionType_GET_CONVERSATION, &gmproto.GetConversationResponse{}},
		{gmproto.ActionType_SEND_MESSAGE, &gmproto.SendMessageResponse{}},
		{gmproto.ActionType_SEND_REACTION, &gmproto.SendReactionResponse{}},
		{gmproto.ActionType_DELETE_MESSAGE, &gmproto.DeleteMessageResponse{}},
		{gmproto.ActionType_MESSAGE_READ, nil},
		{gmproto.ActionType_GET_PARTICIPANTS_THUMBNAIL, &gmproto.GetThumbnailResponse{}},
		{gmproto.ActionType_GET_CONTACTS_THUMBNAIL, &gmproto.GetThumbnailResponse{}},
		{gmproto.ActionType_LIST_CONTACTS, &gmproto.ListContactsResponse{}},
		{gmproto.ActionType_LIST_TOP_CONTACTS, &gmproto.ListTopContactsResponse{}},
		{gmproto.ActionType_GET_OR_CREATE_CONVERSATION, &gmproto.GetOrCreateConversationResponse{}},
		{gmproto.ActionType_UPDATE_CONVERSATION, &gmproto.UpdateConversationResponse{}},
		{gmproto.ActionType_GET_FULL_SIZE_IMAGE, &gmproto.GetFullSizeImageResponse{}},
	}
	for _, fixture := range tests {
		t.Run(fixture.action.String(), func(t *testing.T) {
			store := &sinkInbox{}
			inbox, _ := ingress.NewService(store)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{
				ResponseID: "response-known", Raw: []byte("raw-known"), Request: libgm.DurableRequest{Action: fixture.action},
				Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, IncomingRPCMessage: &gmproto.IncomingRPCMessage{ResponseID: "response-known"},
					Message: &gmproto.RPCMessageData{Action: fixture.action}, DecryptedMessage: fixture.response},
			})
			if err != nil || outcome != libgm.DurableOutcomeCommitted || store.commits != 1 || store.record.Poisoned {
				t.Fatalf("known correlated response outcome = (%v, %v), record=%+v", outcome, err, store.record)
			}
			if !reflect.DeepEqual(store.record.Projection, ingress.Projection{}) || len(store.record.Media) != 0 {
				t.Fatalf("raw-only response invented provider projection: %+v", store.record)
			}
		})
	}
}

func TestDurableSinkPoisonsDecodedDataResponsesWithoutAuthenticatedPayload(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		action   gmproto.ActionType
		request  libgm.DurableRequest
		response proto.Message
	}{
		{name: "get conversation", action: gmproto.ActionType_GET_CONVERSATION, response: &gmproto.GetConversationResponse{}},
		{name: "get or create", action: gmproto.ActionType_GET_OR_CREATE_CONVERSATION, response: &gmproto.GetOrCreateConversationResponse{}},
		{name: "send", action: gmproto.ActionType_SEND_MESSAGE, response: &gmproto.SendMessageResponse{}},
		{name: "mark read", action: gmproto.ActionType_MESSAGE_READ},
		{name: "list conversations", action: gmproto.ActionType_LIST_CONVERSATIONS, response: &gmproto.ListConversationsResponse{}},
		{name: "list messages", action: gmproto.ActionType_LIST_MESSAGES,
			request: libgm.DurableRequest{ConversationID: "conversation-a"}, response: &gmproto.ListMessagesResponse{}},
		{name: "updates", action: gmproto.ActionType_GET_UPDATES, response: &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_ConversationEvent{
			ConversationEvent: &gmproto.ConversationEvent{Data: []*gmproto.Conversation{{ConversationID: "conversation-a"}}},
		}}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			store := &sinkInbox{}
			inbox, _ := ingress.NewService(store)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			fixture.request.Action = fixture.action
			outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{
				ResponseID: "response-unauth-" + strings.ReplaceAll(fixture.name, " ", "-"), Raw: []byte("raw"), Request: fixture.request,
				Decoded: &libgm.IncomingRPCMessage{
					IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
					Message:            &gmproto.RPCMessageData{Action: fixture.action}, DecryptedMessage: fixture.response,
				},
			})
			if err != nil || outcome != libgm.DurableOutcomePoisoned || !store.record.Poisoned || !reflect.DeepEqual(store.record.Projection, ingress.Projection{}) {
				t.Fatalf("unauthenticated %s outcome = (%v, %v), record=%+v", fixture.name, outcome, err, store.record)
			}
		})
	}
}

func TestDurableSinkNeverTreatsAuthenticatedSecondaryPayloadAsCorrelatedResponse(t *testing.T) {
	for _, fixture := range []struct {
		name     string
		action   gmproto.ActionType
		response proto.Message
	}{
		{name: "get conversation", action: gmproto.ActionType_GET_CONVERSATION, response: &gmproto.GetConversationResponse{}},
		{name: "get or create", action: gmproto.ActionType_GET_OR_CREATE_CONVERSATION, response: &gmproto.GetOrCreateConversationResponse{}},
		{name: "send", action: gmproto.ActionType_SEND_MESSAGE, response: &gmproto.SendMessageResponse{}},
		{name: "mark read", action: gmproto.ActionType_MESSAGE_READ},
		{name: "list conversations", action: gmproto.ActionType_LIST_CONVERSATIONS, response: &gmproto.ListConversationsResponse{}},
		{name: "list messages", action: gmproto.ActionType_LIST_MESSAGES, response: &gmproto.ListMessagesResponse{}},
		{name: "updates", action: gmproto.ActionType_GET_UPDATES, response: &gmproto.UpdateEvents{}},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			store := &sinkInbox{}
			inbox, _ := ingress.NewService(store)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{
				ResponseID: "response-secondary-" + strings.ReplaceAll(fixture.name, " ", "-"), Raw: []byte("raw-secondary"),
				Request: libgm.DurableRequest{Action: fixture.action},
				Decoded: &libgm.IncomingRPCMessage{
					IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
					Message:            &gmproto.RPCMessageData{Action: fixture.action}, PayloadSource: libgm.PayloadSourceEncryptedData2,
					SecondaryMessage: &gmproto.EncryptedData2Container{}, DecryptedMessage: fixture.response,
				},
			})
			if err != nil || outcome != libgm.DurableOutcomePoisoned || !store.record.Poisoned || !reflect.DeepEqual(store.record.Projection, ingress.Projection{}) {
				t.Fatalf("secondary %s outcome = (%v, %v), record=%+v", fixture.name, outcome, err, store.record)
			}
		})
	}
}

func TestDurableSinkCommitsAuthenticatedSecondaryAccountChangeAsRawOnly(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-secondary-account", Raw: []byte("raw-secondary-account"),
		Decoded: &libgm.IncomingRPCMessage{
			IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
			Message:            &gmproto.RPCMessageData{Action: gmproto.ActionType_GET_UPDATES}, PayloadSource: libgm.PayloadSourceEncryptedData2,
			SecondaryMessage: &gmproto.EncryptedData2Container{AccountChange: &gmproto.AccountChangeOrSomethingEvent{Account: "account@example.test"}},
		},
	})
	if err != nil || outcome != libgm.DurableOutcomeCommitted || store.commits != 1 || store.record.Poisoned || !reflect.DeepEqual(store.record.Projection, ingress.Projection{}) {
		t.Fatalf("secondary account change outcome = (%v, %v), record=%+v", outcome, err, store.record)
	}
}

func TestDurableSinkCommitsExactLegacyLogoutControlAsRawOnly(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-logout-control", Raw: []byte("raw-logout-control"),
		Decoded: &libgm.IncomingRPCMessage{
			IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
			Message:            &gmproto.RPCMessageData{Action: gmproto.ActionType_GET_UPDATES, UnencryptedData: []byte{0x72, 0x00}},
			PayloadSource:      libgm.PayloadSourceLogoutControl,
		},
	})
	if err != nil || outcome != libgm.DurableOutcomeCommitted || store.commits != 1 || store.record.Poisoned ||
		!reflect.DeepEqual(store.record.Projection, ingress.Projection{}) {
		t.Fatalf("logout control outcome = (%v, %v), record=%+v", outcome, err, store.record)
	}
}

func TestDurableSinkRejectsForgedLegacyLogoutControlSource(t *testing.T) {
	mutations := map[string]func(*gmproto.RPCMessageData){
		"marker":    func(message *gmproto.RPCMessageData) { message.UnencryptedData = []byte{0x72, 0x01} },
		"action":    func(message *gmproto.RPCMessageData) { message.Action = gmproto.ActionType_LIST_MESSAGES },
		"session":   func(message *gmproto.RPCMessageData) { message.SessionID = "request-collision" },
		"primary":   func(message *gmproto.RPCMessageData) { message.EncryptedData = []byte("ciphertext") },
		"secondary": func(message *gmproto.RPCMessageData) { message.EncryptedData2 = []byte("ciphertext") },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			message := &gmproto.RPCMessageData{Action: gmproto.ActionType_GET_UPDATES, UnencryptedData: []byte{0x72, 0x00}}
			mutate(message)
			store := &sinkInbox{}
			inbox, _ := ingress.NewService(store)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{
				ResponseID: "response-logout-forged-" + name, Raw: []byte("raw-forged"),
				Decoded: &libgm.IncomingRPCMessage{
					IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
					Message:            message, PayloadSource: libgm.PayloadSourceLogoutControl,
				},
			})
			if err != nil || outcome != libgm.DurableOutcomePoisoned || !store.record.Poisoned ||
				!reflect.DeepEqual(store.record.Projection, ingress.Projection{}) {
				t.Fatalf("forged logout %s outcome = (%v, %v), record=%+v", name, outcome, err, store.record)
			}
		})
	}
}

func TestDurableSinkPoisonsSecondaryAccountChangeWithResponseAction(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-secondary-wrong-action", Raw: []byte("raw-secondary-wrong-action"),
		Decoded: &libgm.IncomingRPCMessage{
			IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
			Message:            &gmproto.RPCMessageData{Action: gmproto.ActionType_SEND_MESSAGE}, PayloadSource: libgm.PayloadSourceEncryptedData2,
			SecondaryMessage: &gmproto.EncryptedData2Container{AccountChange: &gmproto.AccountChangeOrSomethingEvent{Account: "account@example.test"}},
		},
	})
	if err != nil || outcome != libgm.DurableOutcomePoisoned || !store.record.Poisoned {
		t.Fatalf("secondary response-action account change = (%v, %v), record=%+v", outcome, err, store.record)
	}
}

func TestDurableSinkPoisonsKnownResponseWithMismatchedAuthenticatedAction(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-mismatch", Raw: []byte("raw-mismatch"), Request: libgm.DurableRequest{Action: gmproto.ActionType_SEND_MESSAGE},
		Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, IncomingRPCMessage: &gmproto.IncomingRPCMessage{ResponseID: "response-mismatch"},
			Message: &gmproto.RPCMessageData{Action: gmproto.ActionType_SEND_MESSAGE}, DecryptedMessage: &gmproto.GetConversationResponse{}},
	})
	if err != nil || outcome != libgm.DurableOutcomePoisoned || !store.record.Poisoned {
		t.Fatalf("mismatched known response outcome = (%v, %v), record=%+v", outcome, err, store.record)
	}
}

func TestDurableSinkRejectsMessageReadReplyWithUnexpectedPayload(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-read-payload", Raw: []byte("raw"), Request: libgm.DurableRequest{Action: gmproto.ActionType_MESSAGE_READ},
		Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
			Message: &gmproto.RPCMessageData{Action: gmproto.ActionType_MESSAGE_READ}, DecryptedData: []byte("unexpected")},
	})
	if err != nil || outcome != libgm.DurableOutcomePoisoned || !store.record.Poisoned {
		t.Fatalf("message-read unexpected payload = (%v, %v), record=%+v", outcome, err, store.record)
	}
}

func TestDurableSinkRejectsInvalidPaginationResponseIDAsProviderLocalBeforeInbox(t *testing.T) {
	for _, responseID := range []string{strings.Repeat("r", 257), "response\x00id", "response\nid"} {
		store := &sinkInbox{}
		inbox, _ := ingress.NewService(store)
		sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
		outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
			Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
		}, libgm.DurableEnvelope{
			ResponseID: responseID, Raw: []byte("raw-pagination"),
			Request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS},
			Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, IncomingRPCMessage: &gmproto.IncomingRPCMessage{ResponseID: responseID}, DecryptedMessage: &gmproto.ListConversationsResponse{}},
		})
		if outcome != libgm.DurableOutcomeUnknown || !errors.Is(err, ingress.ErrInvalidProviderResponseID) || errors.Is(err, ErrDurableInfrastructure) {
			t.Fatalf("invalid response ID outcome = (%v, %v)", outcome, err)
		}
		if store.commits != 0 {
			t.Fatalf("invalid response ID reached inbox %d times", store.commits)
		}
	}
}

func TestResponseBackfillCursorCanonicalizesAlternateWireAndUnknownFields(t *testing.T) {
	cursor := &gmproto.Cursor{LastItemID: "conversation-a", LastItemTimestamp: 1700000000}
	want, err := proto.MarshalOptions{Deterministic: true}.Marshal(cursor)
	if err != nil {
		t.Fatal(err)
	}
	alternate := protowire.AppendTag(nil, 2, protowire.VarintType)
	alternate = protowire.AppendVarint(alternate, uint64(cursor.GetLastItemTimestamp()))
	alternate = protowire.AppendTag(alternate, 1, protowire.BytesType)
	alternate = protowire.AppendString(alternate, cursor.GetLastItemID())
	alternate = protowire.AppendTag(alternate, 77, protowire.VarintType)
	alternate = protowire.AppendVarint(alternate, 1)

	got, terminal, err := responseBackfillCursor(alternate, nil)
	if err != nil || terminal {
		t.Fatalf("responseBackfillCursor() = (%x, %v, %v)", got, terminal, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("canonical cursor = %x, want %x", got, want)
	}
}

type sinkACKs struct {
	ownership connectionactor.ProviderOwnership
	ids       []string
	owned     bool
	err       error
	postSend  time.Duration
}

func (store *sinkACKs) ListPendingProviderACKsFenced(_ context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, ownerID string, token uint64, _ int) ([]string, error) {
	store.ownership = connectionactor.ProviderOwnership{Key: connectionactor.Key{TenantID: tenantID, ConnectionID: connectionID}, OwnerID: ownerID, FencingToken: token}
	if store.err != nil {
		return nil, store.err
	}
	return append([]string(nil), store.ids...), nil
}

func (store *sinkACKs) MarkProviderACKedFenced(_ context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, ownerID string, token uint64, ids []string) (bool, error) {
	store.ownership = connectionactor.ProviderOwnership{Key: connectionactor.Key{TenantID: tenantID, ConnectionID: connectionID}, OwnerID: ownerID, FencingToken: token}
	if store.err != nil {
		return false, store.err
	}
	store.ids = append([]string(nil), ids...)
	return store.owned, nil
}

func (store *sinkACKs) CoordinateProviderACKsFenced(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, ownerID string, token uint64, _ time.Duration, ids []string, send func(context.Context, []string) error) (ingress.ACKCoordinationResult, error) {
	store.ownership = connectionactor.ProviderOwnership{Key: connectionactor.Key{TenantID: tenantID, ConnectionID: connectionID}, OwnerID: ownerID, FencingToken: token}
	if store.err != nil {
		return ingress.ACKCoordinationResult{}, store.err
	}
	if !store.owned {
		return ingress.ACKCoordinationResult{}, postgres.ErrConnectionLeaseLost
	}
	result := ingress.ACKCoordinationResult{AdmittedIDs: append([]string(nil), ids...)}
	if err := send(ctx, append([]string(nil), ids...)); err != nil {
		result.ProviderError = err
		return result, nil
	}
	if store.postSend > 0 {
		timer := time.NewTimer(store.postSend)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-timer.C:
		}
	}
	store.ids = append([]string(nil), ids...)
	return result, nil
}

func TestDurableACKProviderDeadlineLeavesPostWirePersistenceBudget(t *testing.T) {
	const ackTimeout = 120 * time.Millisecond
	inbox, _ := ingress.NewService(&sinkInbox{})
	store := &sinkACKs{owned: true, postSend: 40 * time.Millisecond}
	sink, err := NewDurableSink(DurableSinkConfig{
		Inbox: inbox, ACKs: store, Sealer: &recordingSealer{}, ACKTimeout: ackTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownership := connectionactor.ProviderOwnership{
		Key:     connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"},
		OwnerID: "owner-a", FencingToken: 7, LeaseTTL: 30 * time.Second,
	}
	providerCalls := 0
	result, coordinateErr := sink.CoordinateACKs(context.Background(), ownership, []string{"response-a"}, func(sendCtx context.Context, _ []string) error {
		providerCalls++
		deadline, bounded := sendCtx.Deadline()
		if !bounded {
			t.Fatal("provider ACK callback has no transport deadline")
		}
		remaining := time.Until(deadline) - 20*time.Millisecond
		if remaining <= 0 {
			t.Fatalf("provider ACK callback received exhausted deadline: %v", deadline)
		}
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		select {
		case <-sendCtx.Done():
			return sendCtx.Err()
		case <-timer.C:
			return nil
		}
	})
	if coordinateErr != nil || result.ProviderError != nil || providerCalls != 1 ||
		!reflect.DeepEqual(store.ids, []string{"response-a"}) {
		t.Fatalf("near-deadline provider success = (%+v, %v), provider calls=%d persisted=%v",
			result, coordinateErr, providerCalls, store.ids)
	}
	if errors.Is(coordinateErr, ErrDurableInfrastructure) {
		t.Fatalf("post-wire persistence budget became shared infrastructure failure: %v", coordinateErr)
	}
}

type concurrencyACKStore struct {
	active    atomic.Int32
	maxActive atomic.Int32
	started   chan struct{}
	release   <-chan struct{}
}

func (*concurrencyACKStore) ListPendingProviderACKsFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, int) ([]string, error) {
	return nil, nil
}
func (*concurrencyACKStore) MarkProviderACKedFenced(context.Context, domain.TenantID, domain.ConnectionID, string, uint64, []string) (bool, error) {
	return true, nil
}
func (store *concurrencyACKStore) CoordinateProviderACKsFenced(ctx context.Context, _ domain.TenantID, _ domain.ConnectionID, _ string, _ uint64, _ time.Duration, ids []string, send func(context.Context, []string) error) (ingress.ACKCoordinationResult, error) {
	active := store.active.Add(1)
	defer store.active.Add(-1)
	for {
		maximum := store.maxActive.Load()
		if active <= maximum || store.maxActive.CompareAndSwap(maximum, active) {
			break
		}
	}
	store.started <- struct{}{}
	select {
	case <-ctx.Done():
		return ingress.ACKCoordinationResult{AdmittedIDs: append([]string(nil), ids...)}, ctx.Err()
	case <-store.release:
	}
	if err := send(ctx, ids); err != nil {
		return ingress.ACKCoordinationResult{AdmittedIDs: append([]string(nil), ids...), ProviderError: err}, nil
	}
	return ingress.ACKCoordinationResult{AdmittedIDs: append([]string(nil), ids...)}, nil
}

func TestDurableACKLimiterReservesDatabaseCapacityAndCancellationRequeues(t *testing.T) {
	const limit = 8
	inbox, _ := ingress.NewService(&sinkInbox{})
	release := make(chan struct{})
	store := &concurrencyACKStore{started: make(chan struct{}, 64), release: release}
	sink, err := NewDurableSink(DurableSinkConfig{
		Inbox: inbox, ACKs: store, Sealer: &recordingSealer{}, ACKConcurrency: limit,
	})
	if err != nil {
		t.Fatal(err)
	}
	ownership := connectionactor.ProviderOwnership{
		Key:     connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"},
		OwnerID: "owner-a", FencingToken: 7, LeaseTTL: 30 * time.Second,
	}
	type result struct {
		coordination libgm.ACKCoordinationResult
		err          error
	}
	results := make(chan result, 64)
	for index := 0; index < 64; index++ {
		go func(index int) {
			coordination, coordinateErr := sink.CoordinateACKs(context.Background(), ownership,
				[]string{fmt.Sprintf("response-%02d", index)}, func(context.Context, []string) error { return nil })
			results <- result{coordination: coordination, err: coordinateErr}
		}(index)
	}
	for index := 0; index < limit; index++ {
		select {
		case <-store.started:
		case <-time.After(time.Second):
			t.Fatalf("only %d ACK transactions entered limiter", index)
		}
	}
	select {
	case <-store.started:
		t.Fatal("ACK limiter admitted more lock-holding DB transactions than configured")
	case <-time.After(25 * time.Millisecond):
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled, canceledErr := sink.CoordinateACKs(canceledCtx, ownership, []string{"response-canceled"}, func(context.Context, []string) error { return nil })
	if !errors.Is(canceledErr, context.Canceled) || !errors.Is(canceledErr, ErrACKAdmissionLimited) ||
		errors.Is(canceledErr, ErrDurableInfrastructure) ||
		!reflect.DeepEqual(canceled.RetryIDs, []string{"response-canceled"}) {
		t.Fatalf("canceled ACK limiter admission = (%+v, %v)", canceled, canceledErr)
	}
	deadlineCtx, cancelDeadline := context.WithTimeout(context.Background(), 10*time.Millisecond)
	deferred, deferredErr := sink.CoordinateACKs(deadlineCtx, ownership, []string{"response-deferred"}, func(context.Context, []string) error { return nil })
	cancelDeadline()
	if !errors.Is(deferredErr, context.DeadlineExceeded) || !errors.Is(deferredErr, ErrACKAdmissionLimited) ||
		errors.Is(deferredErr, ErrDurableInfrastructure) || !reflect.DeepEqual(deferred.RetryIDs, []string{"response-deferred"}) {
		t.Fatalf("congested ACK limiter admission = (%+v, %v)", deferred, deferredErr)
	}

	close(release)
	for index := 0; index < 64; index++ {
		select {
		case completed := <-results:
			if completed.err != nil || completed.coordination.ProviderError != nil {
				t.Fatalf("limited ACK completion = (%+v, %v)", completed.coordination, completed.err)
			}
		case <-time.After(time.Second):
			t.Fatalf("limited ACK %d did not complete", index)
		}
	}
	if maximum := store.maxActive.Load(); maximum != limit {
		t.Fatalf("maximum concurrent DB-holding ACKs = %d, want %d", maximum, limit)
	}
}

func TestDurableACKLimiterIsProcessWideAcrossIndependentSinks(t *testing.T) {
	inbox, _ := ingress.NewService(&sinkInbox{})
	release := make(chan struct{})
	store := &concurrencyACKStore{started: make(chan struct{}, 32), release: release}
	newSink := func() *DurableSink {
		sink, err := NewDurableSink(DurableSinkConfig{
			Inbox: inbox, ACKs: store, Sealer: &recordingSealer{}, ACKConcurrency: MaxACKConcurrency,
		})
		if err != nil {
			t.Fatal(err)
		}
		return sink
	}
	sinks := []*DurableSink{newSink(), newSink()}
	ownership := connectionactor.ProviderOwnership{
		Key:     connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"},
		OwnerID: "owner-a", FencingToken: 7, LeaseTTL: 30 * time.Second,
	}
	results := make(chan error, 32)
	for index := 0; index < 32; index++ {
		go func(index int) {
			_, coordinateErr := sinks[index%len(sinks)].CoordinateACKs(context.Background(), ownership,
				[]string{fmt.Sprintf("response-global-%02d", index)}, func(context.Context, []string) error { return nil })
			results <- coordinateErr
		}(index)
	}
	for index := 0; index < MaxACKConcurrency; index++ {
		select {
		case <-store.started:
		case <-time.After(time.Second):
			t.Fatalf("only %d ACK transactions entered the process limiter", index)
		}
	}
	select {
	case <-store.started:
		t.Fatal("independent sinks exceeded the process-wide ACK ceiling")
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	for index := 0; index < 32; index++ {
		select {
		case resultErr := <-results:
			if resultErr != nil {
				t.Fatalf("process-limited ACK %d: %v", index, resultErr)
			}
		case <-time.After(time.Second):
			t.Fatalf("process-limited ACK %d did not complete", index)
		}
	}
	if maximum := store.maxActive.Load(); maximum != MaxACKConcurrency {
		t.Fatalf("process-wide maximum = %d, want %d", maximum, MaxACKConcurrency)
	}
}

func TestDurableACKCoordinationTimeoutIsStrictlyBelowLeaseAndRetriesProviderFailure(t *testing.T) {
	inbox, _ := ingress.NewService(&sinkInbox{})
	if DefaultACKCoordinationTimeout != 4*time.Second || libgm.ProviderACKRequestTimeout != 5*time.Second ||
		DefaultACKCoordinationTimeout >= libgm.ProviderACKRequestTimeout {
		t.Fatalf("ACK timeout invariant = outer %v inner %v", DefaultACKCoordinationTimeout, libgm.ProviderACKRequestTimeout)
	}
	if _, err := NewDurableSink(DurableSinkConfig{
		Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}, ACKTimeout: libgm.ProviderACKRequestTimeout,
	}); err == nil {
		t.Fatal("gateway accepted an ACK coordination timeout equal to the provider request timeout")
	}
	t.Run("provider timeout rolls back to retry", func(t *testing.T) {
		sink, err := NewDurableSink(DurableSinkConfig{
			Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}, ACKTimeout: 100 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}
		ownership := connectionactor.ProviderOwnership{
			Key:     connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"},
			OwnerID: "owner-a", FencingToken: 7, LeaseTTL: 30 * time.Second,
		}
		started := time.Now()
		result, coordinateErr := sink.CoordinateACKs(context.Background(), ownership, []string{"response-a"}, func(ctx context.Context, _ []string) error {
			<-ctx.Done()
			return ctx.Err()
		})
		if coordinateErr != nil || !errors.Is(result.ProviderError, context.DeadlineExceeded) ||
			!reflect.DeepEqual(result.RetryIDs, []string{"response-a"}) {
			t.Fatalf("timed ACK coordination = (%+v, %v)", result, coordinateErr)
		}
		if elapsed := time.Since(started); elapsed >= ownership.LeaseTTL/3 {
			t.Fatalf("ACK timeout %v was not strictly below lease renewal budget %v", elapsed, ownership.LeaseTTL/3)
		}
	})

	t.Run("unsafe lease ratio fails before provider IO", func(t *testing.T) {
		sink, err := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
		if err != nil {
			t.Fatal(err)
		}
		providerCalls := 0
		_, coordinateErr := sink.CoordinateACKs(context.Background(), connectionactor.ProviderOwnership{
			Key:     connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"},
			OwnerID: "owner-a", FencingToken: 7, LeaseTTL: 9 * time.Second,
		}, []string{"response-a"}, func(context.Context, []string) error { providerCalls++; return nil })
		if coordinateErr == nil || providerCalls != 0 {
			t.Fatalf("unsafe lease ACK = error %v, provider calls %d", coordinateErr, providerCalls)
		}
	})
}

type recordingSealer struct{ plaintext [][]byte }

func (sealer *recordingSealer) Seal(_ context.Context, _ session.Scope, plaintext []byte) (session.Envelope, error) {
	sealer.plaintext = append(sealer.plaintext, append([]byte(nil), plaintext...))
	return session.Envelope{Version: 1, Provider: "gmessages-media", Ciphertext: bytes.Repeat([]byte{1}, 16), WrappedDEK: []byte("wrapped"), Nonce: make([]byte, 12), KeyID: "kms-key", KeyVersion: 1}, nil
}

type failingSealer struct{ err error }

func (sealer failingSealer) Seal(context.Context, session.Scope, []byte) (session.Envelope, error) {
	return session.Envelope{}, sealer.err
}

func TestDurableSinkWithholdsACKAndDoesNotPoisonOnMediaKeyKMSFailure(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	kmsFailure := errors.New("kms unavailable")
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: failingSealer{err: kmsFailure}})
	updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{{
		MessageID: "provider-message-a", ConversationID: "conversation-a", MessageInfo: []*gmproto.MessageInfo{{
			Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{MediaID: "media-a", DecryptionKey: []byte("secret")}},
		}},
	}}}}}
	_, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-a", Raw: []byte("raw"), Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: updates}})
	if !errors.Is(err, kmsFailure) || store.commits != 0 {
		t.Fatalf("PersistEnvelope() error=%v commits=%d", err, store.commits)
	}
}

func TestDurableSinkBoundsCardinalityBeforeSealingProviderKeys(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sealer := &recordingSealer{}
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: sealer})
	infos := make([]*gmproto.MessageInfo, 17)
	for index := range infos {
		infos[index] = &gmproto.MessageInfo{Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{
			MediaID: "media-a", MimeType: "image/png", Size: 1, DecryptionKey: []byte("must-not-seal"),
		}}}
	}
	updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{{
		MessageID: "provider-a", ConversationID: "conversation-a", MessageInfo: infos,
	}}}}}
	err := sink.PersistEnvelope(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-oversized", Raw: []byte("raw"), Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: updates}})
	if err != nil || store.commits != 1 || !store.record.Poisoned || len(sealer.plaintext) != 0 {
		t.Fatalf("PersistEnvelope() error=%v commits=%d poison=%v seals=%d", err, store.commits, store.record.Poisoned, len(sealer.plaintext))
	}
}

func TestDurableSinkTwoImageEnvelopeProjectsBothStablePositions(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	infos := []*gmproto.MessageInfo{
		{Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{MediaID: "media-first", MimeType: "image/png", Size: 1}}},
		{Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{MediaID: "media-second", MimeType: "image/jpeg", Size: 2}}},
	}
	updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{{
		MessageID: "provider-a", ConversationID: "conversation-a", MessageInfo: infos,
	}}}}}
	if err := sink.PersistEnvelope(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-two", Raw: []byte("raw"), Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: updates}}); err != nil {
		t.Fatal(err)
	}
	if len(store.record.Media) != 2 || store.record.Media[0].Position != 0 || store.record.Media[1].Position != 1 ||
		len(store.record.Events) != 3 || store.record.Events[1].ID == store.record.Events[2].ID {
		t.Fatalf("two-image projection = media=%+v events=%+v", store.record.Media, store.record.Events)
	}
}

// Incoming RCS images first arrive thumbnail-only (no MediaID). The message must
// still project, and the full-size update that follows must land at the same position.
func TestDurableSinkProjectsThumbnailOnlyImageWithoutPoisonOrMediaJob(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sealer := &recordingSealer{}
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: sealer})
	infos := []*gmproto.MessageInfo{
		{Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{
			ThumbnailMediaID: "thumbnail-first", ThumbnailDecryptionKey: []byte("thumbnail-secret"), MimeType: "image/jpeg", Size: 3,
		}}},
		{Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{MediaID: "media-second", MimeType: "image/png", Size: 2}}},
		{Data: &gmproto.MessageInfo_MessageContent{MessageContent: &gmproto.MessageContent{Content: "caption"}}},
	}
	updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{{
		MessageID: "provider-a", ConversationID: "conversation-a", MessageInfo: infos,
		MessageStatus: &gmproto.MessageStatus{Status: gmproto.MessageStatusType_INCOMING_COMPLETE},
	}}}}}
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), durableTestOwnership(), libgm.DurableEnvelope{
		ResponseID: "response-thumbnail", Raw: []byte("raw"),
		Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: updates},
	})
	if err != nil || outcome != libgm.DurableOutcomeCommitted || store.record.Poisoned {
		t.Fatalf("PersistEnvelopeOutcome() outcome=%v err=%v poisoned=%v", outcome, err, store.record.Poisoned)
	}
	if len(store.record.Projection.Messages) != 1 || store.record.Projection.Messages[0].Text != "caption" {
		t.Fatalf("projection = %+v", store.record.Projection)
	}
	if len(store.record.Media) != 1 || store.record.Media[0].Position != 1 || store.record.Media[0].Locator != "gmessages:bWVkaWEtc2Vjb25k" {
		t.Fatalf("media jobs = %+v", store.record.Media)
	}
	for _, sealed := range sealer.plaintext {
		if string(sealed) == "thumbnail-secret" {
			t.Fatal("thumbnail-only attachment key was sealed without a media job")
		}
	}
}

func TestDurableSinkProjectsCaptionlessThumbnailOnlyImageWithoutPoison(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{{
		MessageID: "provider-a", ConversationID: "conversation-a",
		MessageStatus: &gmproto.MessageStatus{Status: gmproto.MessageStatusType_INCOMING_COMPLETE},
		MessageInfo: []*gmproto.MessageInfo{
			{Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{ThumbnailMediaID: "thumbnail-a", MimeType: "image/jpeg", Size: 3}}},
		},
	}}}}}
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), durableTestOwnership(), libgm.DurableEnvelope{
		ResponseID: "response-captionless", Raw: []byte("raw"),
		Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: updates},
	})
	if err != nil || outcome != libgm.DurableOutcomeCommitted || store.record.Poisoned {
		t.Fatalf("PersistEnvelopeOutcome() outcome=%v err=%v poisoned=%v reason=%q", outcome, err, store.record.Poisoned, store.record.PoisonReason)
	}
	if len(store.record.Projection.Messages) != 1 || len(store.record.Media) != 0 {
		t.Fatalf("projection = %+v media = %+v", store.record.Projection, store.record.Media)
	}
}

func TestDurableSinkPoisonsOversizedThumbnailMediaID(t *testing.T) {
	store := &sinkInbox{}
	inbox, _ := ingress.NewService(store)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{{
		MessageID: "provider-a", ConversationID: "conversation-a", MessageInfo: []*gmproto.MessageInfo{
			{Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{ThumbnailMediaID: strings.Repeat("t", 4096), MimeType: "image/png"}}},
		},
	}}}}}
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), durableTestOwnership(), libgm.DurableEnvelope{
		ResponseID: "response-thumbnail-oversized", Raw: []byte("raw"),
		Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: updates},
	})
	if err != nil || outcome != libgm.DurableOutcomePoisoned || !store.record.Poisoned {
		t.Fatalf("PersistEnvelopeOutcome() outcome=%v err=%v poisoned=%v", outcome, err, store.record.Poisoned)
	}
}

func TestDurableSinkProjectsTextImageTransportAndExactReceiptSemantics(t *testing.T) {
	inboxStore := &sinkInbox{}
	inbox, _ := ingress.NewService(inboxStore)
	acks := &sinkACKs{owned: true}
	sealer := &recordingSealer{}
	sink, err := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: acks, Sealer: sealer})
	if err != nil {
		t.Fatal(err)
	}
	text := &gmproto.MessageInfo{Data: &gmproto.MessageInfo_MessageContent{MessageContent: &gmproto.MessageContent{Content: "hello"}}}
	mediaInfo := &gmproto.MessageInfo{Data: &gmproto.MessageInfo_MediaContent{MediaContent: &gmproto.MediaContent{
		MediaID: "media-a", MediaName: "photo.png", Size: 42, MimeType: "image/png", DecryptionKey: []byte("provider-secret"),
	}}}
	providerMessage := &gmproto.Message{
		MessageID: "provider-message-a", TmpID: "sx-temporary", ConversationID: "conversation-a", Type: 4,
		MessageStatus: &gmproto.MessageStatus{Status: gmproto.MessageStatusType_OUTGOING_DELIVERED},
		MessageInfo:   []*gmproto.MessageInfo{text, mediaInfo},
		SenderParticipant: &gmproto.Participant{
			FormattedNumber: "+12025550100",
			ID:              &gmproto.SmallInfo{Number: "+12025550999"},
		},
	}
	updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{providerMessage}}}}
	decoded := &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: updates}
	ownership := connectionactor.ProviderOwnership{Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9}
	if err = sink.PersistEnvelope(context.Background(), ownership, libgm.DurableEnvelope{ResponseID: "response-a", Raw: []byte("raw"), Decoded: decoded}); err != nil {
		t.Fatal(err)
	}
	record := inboxStore.record
	if len(record.Projection.Messages) != 1 {
		t.Fatalf("projection = %+v", record.Projection)
	}
	message := record.Projection.Messages[0]
	if message.Text != "hello" || message.State != domain.MessageStateDelivered || message.Transport != "rcs" || message.ProviderTmpID != "sx-temporary" || message.Sender != "+12025550100" ||
		message.Direction != "outbound" || message.Provenance != ingress.MessageProvenanceLive || message.ProviderStatus != "OUTGOING_DELIVERED" {
		t.Fatalf("projected message = %+v", message)
	}
	if len(record.Events) == 0 || record.Events[0].Type != "message.updated" {
		t.Fatalf("manual outgoing provider update became actionable: %+v", record.Events)
	}
	if len(record.Media) != 1 || record.Media[0].Locator != "gmessages:bWVkaWEtYQ" || record.Media[0].KeyEnvelope.Ciphertext == nil {
		t.Fatalf("media jobs = %+v", record.Media)
	}
	if len(sealer.plaintext) != 1 || string(sealer.plaintext[0]) != "provider-secret" {
		t.Fatalf("sealed plaintext calls = %q", sealer.plaintext)
	}
	if record.Media[0].Locator == "provider-secret" || string(record.Media[0].KeyEnvelope.Ciphertext) == "provider-secret" {
		t.Fatal("provider media key remained plaintext")
	}
}

func TestDurableSinkEmitsActionableEventOnlyForLiveCompleteInbound(t *testing.T) {
	providerTime := time.Date(2026, 8, 25, 12, 15, 0, 123000, time.UTC)
	for _, fixture := range []struct {
		name           string
		isOld          bool
		status         gmproto.MessageStatusType
		wantEvent      string
		wantProv       ingress.MessageProvenance
		wantActionable bool
	}{
		{name: "live inbound complete", status: gmproto.MessageStatusType_INCOMING_COMPLETE, wantEvent: "message.received", wantProv: ingress.MessageProvenanceLive, wantActionable: true},
		{name: "live inbound delivered without complete", status: gmproto.MessageStatusType_INCOMING_DELIVERED, wantEvent: "message.updated", wantProv: ingress.MessageProvenanceLive},
		{name: "live inbound displayed without complete", status: gmproto.MessageStatusType_INCOMING_DISPLAYED, wantEvent: "message.updated", wantProv: ingress.MessageProvenanceLive},
		{name: "restart replay", isOld: true, status: gmproto.MessageStatusType_INCOMING_COMPLETE, wantEvent: "message.imported", wantProv: ingress.MessageProvenanceReplay},
		{name: "live phone outgoing", status: gmproto.MessageStatusType_OUTGOING_COMPLETE, wantEvent: "message.updated", wantProv: ingress.MessageProvenanceLive},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			store := &sinkInbox{}
			inbox, _ := ingress.NewService(store)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_MessageEvent{MessageEvent: &gmproto.MessageEvent{Data: []*gmproto.Message{{
				MessageID: "provider-direction", ConversationID: "conversation-a", Timestamp: providerTime.UnixMicro(),
				MessageStatus: &gmproto.MessageStatus{Status: fixture.status},
				MessageInfo:   []*gmproto.MessageInfo{{Data: &gmproto.MessageInfo_MessageContent{MessageContent: &gmproto.MessageContent{Content: "hello"}}}},
			}}}}}
			err := sink.PersistEnvelope(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{ResponseID: "response-" + strings.ReplaceAll(fixture.name, " ", "-"), Raw: []byte("raw"), Decoded: &libgm.IncomingRPCMessage{
				PayloadSource: libgm.PayloadSourceEncryptedData, IsOld: fixture.isOld, DecryptedMessage: updates,
			}})
			if err != nil {
				t.Fatal(err)
			}
			message := store.record.Projection.Messages[0]
			if message.Provenance != fixture.wantProv || message.Actionable != fixture.wantActionable || !message.ProviderOccurredAt.Equal(providerTime) || len(store.record.Events) != 1 || store.record.Events[0].Type != fixture.wantEvent {
				t.Fatalf("message provenance/event = %+v / %+v", message, store.record.Events)
			}
			if fixture.wantEvent != "message.received" {
				for _, event := range store.record.Events {
					if event.Type == "message.received" {
						t.Fatalf("non-live-inbound emitted actionable event: %+v", store.record.Events)
					}
				}
			}
		})
	}
}

func TestTrustedProviderMessageTimeUsesProtocolMicroseconds(t *testing.T) {
	want := time.Date(2026, 8, 25, 12, 15, 0, 123000, time.UTC)
	if got := trustedProviderMessageTime(want.UnixMicro()); !got.Equal(want) {
		t.Fatalf("provider timestamp = %v, want %v", got, want)
	}
	for _, invalid := range []int64{0, time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC).UnixMicro(), time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC).UnixMicro()} {
		if got := trustedProviderMessageTime(invalid); !got.IsZero() {
			t.Fatalf("untrusted provider timestamp %d became %v", invalid, got)
		}
	}
}

func TestDurableSinkMapsOnlyCompleteDeliveredDisplayedAndDefinitiveFailure(t *testing.T) {
	statuses := map[gmproto.MessageStatusType]domain.MessageState{
		gmproto.MessageStatusType_OUTGOING_COMPLETE:       domain.MessageStateSent,
		gmproto.MessageStatusType_OUTGOING_DELIVERED:      domain.MessageStateDelivered,
		gmproto.MessageStatusType_OUTGOING_DISPLAYED:      domain.MessageStateRead,
		gmproto.MessageStatusType_OUTGOING_FAILED_GENERIC: domain.MessageStateFailed,
		gmproto.MessageStatusType_OUTGOING_SENDING:        "",
	}
	for providerStatus, want := range statuses {
		if got := MapProviderMessageState(providerStatus); got != want {
			t.Errorf("MapProviderMessageState(%s) = %q, want %q", providerStatus, got, want)
		}
	}
}

func TestDurableSinkProjectsExistingConversationDefaultRouteAndGroupFlag(t *testing.T) {
	inboxStore := &sinkInbox{}
	inbox, _ := ingress.NewService(inboxStore)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	updates := &gmproto.UpdateEvents{Event: &gmproto.UpdateEvents_ConversationEvent{ConversationEvent: &gmproto.ConversationEvent{Data: []*gmproto.Conversation{{
		ConversationID: "conversation-a", DefaultOutgoingID: "outgoing-primary", IsGroupChat: true,
	}}}}}
	err := sink.PersistEnvelope(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-conversation", Raw: []byte("raw"), Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: updates}})
	if err != nil {
		t.Fatal(err)
	}
	want := ingress.ProjectedConversation{ConversationID: "conversation-a", DefaultOutgoingID: "outgoing-primary", IsGroup: true}
	if len(inboxStore.record.Projection.Conversations) != 1 || inboxStore.record.Projection.Conversations[0] != want {
		t.Fatalf("conversation projection = %+v, want %+v", inboxStore.record.Projection.Conversations, want)
	}
}

func TestDurableSinkProjectsBackfillPageAndCursorInSameCommit(t *testing.T) {
	inboxStore := &sinkInbox{}
	inbox, _ := ingress.NewService(inboxStore)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	cursor := &gmproto.Cursor{LastItemID: "message-last", LastItemTimestamp: 1724400000023}
	page := &gmproto.ListMessagesResponse{Cursor: cursor, Messages: []*gmproto.Message{{
		MessageID: "message-backfill", ConversationID: "conversation-a", Timestamp: time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC).UnixMicro(),
		MessageStatus: &gmproto.MessageStatus{Status: gmproto.MessageStatusType_INCOMING_COMPLETE},
		MessageInfo:   []*gmproto.MessageInfo{{Data: &gmproto.MessageInfo_MessageContent{MessageContent: &gmproto.MessageContent{Content: "backfill"}}}},
	}}}
	err := sink.PersistEnvelope(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-page", Raw: []byte("exact-page"), Request: libgm.DurableRequest{
		Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-a",
	}, Decoded: &libgm.IncomingRPCMessage{
		PayloadSource: libgm.PayloadSourceEncryptedData, IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent}, DecryptedMessage: page,
	}})
	if err != nil {
		t.Fatal(err)
	}
	wantCursor, _ := proto.MarshalOptions{Deterministic: true}.Marshal(cursor)
	if len(inboxStore.record.Projection.Messages) != 1 || !bytes.Equal(inboxStore.record.Projection.Cursor, wantCursor) ||
		inboxStore.record.Projection.CursorSource != ingress.CursorSourceListMessages || inboxStore.record.Projection.CursorConversationID != "conversation-a" {
		t.Fatalf("committed backfill projection = %+v", inboxStore.record.Projection)
	}
	message := inboxStore.record.Projection.Messages[0]
	if message.Provenance != ingress.MessageProvenanceHistory || message.Direction != "inbound" || len(inboxStore.record.Events) == 0 || inboxStore.record.Events[0].Type != "message.imported" {
		t.Fatalf("backfill became actionable: message=%+v events=%+v", message, inboxStore.record.Events)
	}
}

func TestDurableSinkRoutesEmptyListMessagesCursorByRequestMetadata(t *testing.T) {
	inboxStore := &sinkInbox{}
	inbox, _ := ingress.NewService(inboxStore)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	cursor := &gmproto.Cursor{LastItemID: "empty-page-boundary", LastItemTimestamp: 1724400000024}
	err := sink.PersistEnvelope(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-empty-page", Raw: []byte("exact-empty-page"),
		Request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-empty"},
		Decoded: &libgm.IncomingRPCMessage{
			PayloadSource: libgm.PayloadSourceEncryptedData, IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
			DecryptedMessage: &gmproto.ListMessagesResponse{Cursor: cursor},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wantCursor, _ := proto.MarshalOptions{Deterministic: true}.Marshal(cursor)
	projection := inboxStore.record.Projection
	if len(projection.Messages) != 0 || !bytes.Equal(projection.Cursor, wantCursor) ||
		projection.CursorSource != ingress.CursorSourceListMessages || projection.CursorConversationID != "conversation-empty" {
		t.Fatalf("empty page projection = %+v", projection)
	}
}

func TestDurableSinkPoisonsZeroValueNonterminalCursor(t *testing.T) {
	inboxStore := &sinkInbox{}
	inbox, _ := ingress.NewService(inboxStore)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-zero-cursor", Raw: []byte("zero-cursor-page"),
		Request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-a"},
		Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: &gmproto.ListMessagesResponse{Cursor: &gmproto.Cursor{}}},
	})
	if err != nil || outcome != libgm.DurableOutcomePoisoned {
		t.Fatalf("zero cursor outcome = (%v, %v), want durable poison", outcome, err)
	}
	if !inboxStore.record.Poisoned || len(inboxStore.record.Projection.Cursor) != 0 || inboxStore.record.Projection.CursorConversationID != "" {
		t.Fatalf("zero cursor durable record = %+v", inboxStore.record)
	}
}

func TestDurableSinkPoisonsMissingRequiredOrMalformedCursorFieldsForBothRPCs(t *testing.T) {
	index := 0
	for name, fixture := range map[string]struct {
		response proto.Message
		request  libgm.DurableRequest
	}{
		"conversation structured missing timestamp": {
			response: &gmproto.ListConversationsResponse{Cursor: &gmproto.Cursor{LastItemID: "cursor-without-timestamp"}},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS},
		},
		"conversation malformed opaque": {
			response: &gmproto.ListConversationsResponse{CursorBytes: []byte{0xff, 0x80, 0x80}},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS},
		},
		"message structured missing timestamp": {
			response: &gmproto.ListMessagesResponse{Cursor: &gmproto.Cursor{LastItemID: "cursor-without-timestamp"}},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-a"},
		},
	} {
		index++
		t.Run(name, func(t *testing.T) {
			inboxStore := &sinkInbox{}
			inbox, _ := ingress.NewService(inboxStore)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{
				ResponseID: fmt.Sprintf("response-invalid-cursor-%d", index), Raw: []byte("invalid-cursor"), Request: fixture.request,
				Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: fixture.response},
			})
			if err != nil || outcome != libgm.DurableOutcomePoisoned || !inboxStore.record.Poisoned {
				t.Fatalf("invalid cursor = (%v, %v), record=%+v", outcome, err, inboxStore.record)
			}
		})
	}
}

func TestDurableSinkPoisonsWhitespaceAndControlCursorIDsInBothListRPCs(t *testing.T) {
	invalidIDs := []string{"   ", "cursor\x00id", "cursor\x01id"}
	for index, invalidID := range invalidIDs {
		opaque, err := proto.Marshal(&gmproto.Cursor{LastItemID: invalidID, LastItemTimestamp: 1724400000045})
		if err != nil {
			t.Fatal(err)
		}
		fixtures := []struct {
			name     string
			response proto.Message
			request  libgm.DurableRequest
		}{
			{
				name: "conversation structured", response: &gmproto.ListConversationsResponse{Cursor: &gmproto.Cursor{
					LastItemID: invalidID, LastItemTimestamp: 1724400000045,
				}}, request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS},
			},
			{
				name: "conversation opaque", response: &gmproto.ListConversationsResponse{CursorBytes: opaque},
				request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS},
			},
			{
				name: "message structured", response: &gmproto.ListMessagesResponse{Cursor: &gmproto.Cursor{
					LastItemID: invalidID, LastItemTimestamp: 1724400000045,
				}}, request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-a"},
			},
		}
		for _, fixture := range fixtures {
			t.Run(fmt.Sprintf("%d/%s", index, fixture.name), func(t *testing.T) {
				inboxStore := &sinkInbox{}
				inbox, _ := ingress.NewService(inboxStore)
				sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
				outcome, persistErr := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
					Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
				}, libgm.DurableEnvelope{
					ResponseID: fmt.Sprintf("response-invalid-control-cursor-%d-%d", index, len(fixture.name)),
					Raw:        []byte("invalid-control-cursor"), Request: fixture.request,
					Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: fixture.response},
				})
				if persistErr != nil || outcome != libgm.DurableOutcomePoisoned || !inboxStore.record.Poisoned || len(inboxStore.record.Projection.Cursor) != 0 {
					t.Fatalf("invalid cursor outcome = (%v, %v), record=%+v", outcome, persistErr, inboxStore.record)
				}
			})
		}
	}
}

func TestDurableSinkPoisonsAmbiguousAndNonAdvancingProviderCursors(t *testing.T) {
	cursor := &gmproto.Cursor{LastItemID: "cursor-a", LastItemTimestamp: 1724400000046}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(cursor)
	if err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, ingress.MaxCursorBytes+1)
	index := 0
	for name, fixture := range map[string]struct {
		response proto.Message
		request  libgm.DurableRequest
	}{
		"conversation dual matching": {
			response: &gmproto.ListConversationsResponse{Cursor: cursor, CursorBytes: encoded},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS},
		},
		"conversation dual oversized": {
			response: &gmproto.ListConversationsResponse{Cursor: cursor, CursorBytes: oversized},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS},
		},
		"conversation repeated request cursor": {
			response: &gmproto.ListConversationsResponse{Cursor: cursor},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS, Cursor: encoded},
		},
		"message repeated request cursor": {
			response: &gmproto.ListMessagesResponse{Cursor: cursor},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-a", Cursor: encoded},
		},
	} {
		index++
		t.Run(name, func(t *testing.T) {
			inboxStore := &sinkInbox{}
			inbox, _ := ingress.NewService(inboxStore)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			outcome, persistErr := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{
				ResponseID: fmt.Sprintf("response-invalid-cursor-kind-%d", index), Raw: []byte("invalid-cursor"), Request: fixture.request,
				Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: fixture.response},
			})
			if persistErr != nil || outcome != libgm.DurableOutcomePoisoned || !inboxStore.record.Poisoned || len(inboxStore.record.Projection.Cursor) != 0 {
				t.Fatalf("cursor outcome = (%v, %v), record=%+v", outcome, persistErr, inboxStore.record)
			}
		})
	}
}

func TestDurableSinkPoisonsBoundedCursorCycleButAllowsExactRedelivery(t *testing.T) {
	inboxStore := &cursorCycleInbox{responses: make(map[string][32]byte), edges: make(map[[32]byte][32]byte)}
	inbox, _ := ingress.NewService(inboxStore)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	ownership := connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}
	cursorA := &gmproto.Cursor{LastItemID: "cursor-a", LastItemTimestamp: 1724400000046}
	cursorB := &gmproto.Cursor{LastItemID: "cursor-b", LastItemTimestamp: 1724400000047}
	encodedA, _ := proto.MarshalOptions{Deterministic: true}.Marshal(cursorA)
	encodedB, _ := proto.MarshalOptions{Deterministic: true}.Marshal(cursorB)
	persist := func(responseID string, base []byte, next *gmproto.Cursor) libgm.DurableOutcome {
		outcome, err := sink.PersistEnvelopeOutcome(context.Background(), ownership, libgm.DurableEnvelope{
			ResponseID: responseID, Raw: []byte(responseID),
			Request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-a", Cursor: base},
			Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: &gmproto.ListMessagesResponse{Cursor: next}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return outcome
	}
	if got := persist("response-a-b", encodedA, cursorB); got != libgm.DurableOutcomeCommitted {
		t.Fatalf("first cursor outcome = %v", got)
	}
	if got := persist("response-a-b", encodedA, cursorB); got != libgm.DurableOutcomeCommitted {
		t.Fatalf("exact redelivery outcome = %v", got)
	}
	if got := persist("response-b-a", encodedB, cursorA); got != libgm.DurableOutcomePoisoned {
		t.Fatalf("cycle outcome = %v, want poison", got)
	}
}

func TestDurableSinkPoisonsReservedParentCursorConversationIDEverywhere(t *testing.T) {
	index := 0
	for name, fixture := range map[string]struct {
		response proto.Message
		request  libgm.DurableRequest
	}{
		"conversation list": {
			response: &gmproto.ListConversationsResponse{Conversations: []*gmproto.Conversation{{ConversationID: ingress.ProviderPageCursorID}}},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS},
		},
		"message page": {
			response: &gmproto.ListMessagesResponse{Messages: []*gmproto.Message{{MessageID: "message-a", ConversationID: ingress.ProviderPageCursorID}}},
			request:  libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: ingress.ProviderPageCursorID},
		},
	} {
		index++
		t.Run(name, func(t *testing.T) {
			inboxStore := &sinkInbox{}
			inbox, _ := ingress.NewService(inboxStore)
			sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
			outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
				Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
			}, libgm.DurableEnvelope{
				ResponseID: fmt.Sprintf("response-reserved-%d", index), Raw: []byte("reserved-provider-id"), Request: fixture.request,
				Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: fixture.response},
			})
			if err != nil || outcome != libgm.DurableOutcomePoisoned || !inboxStore.record.Poisoned {
				t.Fatalf("reserved provider ID = (%v, %v), record=%+v", outcome, err, inboxStore.record)
			}
		})
	}
}

func TestDurableSinkPoisonsConversationListWithMismatchedTrustedAction(t *testing.T) {
	inboxStore := &sinkInbox{}
	inbox, _ := ingress.NewService(inboxStore)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-list-action-mismatch", Raw: []byte("list-action-mismatch"),
		Request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-a"},
		Decoded: &libgm.IncomingRPCMessage{PayloadSource: libgm.PayloadSourceEncryptedData, DecryptedMessage: &gmproto.ListConversationsResponse{
			Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}},
		}},
	})
	if err != nil || outcome != libgm.DurableOutcomePoisoned || !inboxStore.record.Poisoned || len(inboxStore.record.Projection.Conversations) != 0 {
		t.Fatalf("mismatched conversation-list action = (%v, %v), record=%+v", outcome, err, inboxStore.record)
	}
}

func TestDurableSinkPoisonsCrossConversationListMessagesPageWithoutCursorWrite(t *testing.T) {
	inboxStore := &sinkInbox{}
	inbox, _ := ingress.NewService(inboxStore)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	outcome, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{
		ResponseID: "response-cross-conversation", Raw: []byte("cross-conversation-page"),
		Request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_MESSAGES, ConversationID: "conversation-requested"},
		Decoded: &libgm.IncomingRPCMessage{
			PayloadSource: libgm.PayloadSourceEncryptedData, IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent},
			DecryptedMessage: &gmproto.ListMessagesResponse{
				Messages: []*gmproto.Message{{MessageID: "message-wrong", ConversationID: "conversation-other"}},
				Cursor:   &gmproto.Cursor{LastItemID: "message-wrong", LastItemTimestamp: 1724400000024},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if outcome != libgm.DurableOutcomePoisoned {
		t.Fatalf("cross-conversation durable outcome = %v", outcome)
	}
	if !inboxStore.record.Poisoned || inboxStore.record.PoisonReason != "decode_failed" || len(inboxStore.record.Projection.Cursor) != 0 {
		t.Fatalf("cross-conversation durable result = %+v", inboxStore.record)
	}
}

func TestDurableSinkDoesNotCommitConversationListCursorBeforeChildren(t *testing.T) {
	inboxStore := &sinkInbox{}
	inbox, _ := ingress.NewService(inboxStore)
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{}})
	page := &gmproto.ListConversationsResponse{
		Conversations: []*gmproto.Conversation{{ConversationID: "conversation-a"}, {ConversationID: "conversation-b"}},
		Cursor:        &gmproto.Cursor{LastItemID: "conversation-b", LastItemTimestamp: 1724400000023},
	}
	err := sink.PersistEnvelope(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-conversation-page", Raw: []byte("exact-page"), Request: libgm.DurableRequest{Action: gmproto.ActionType_LIST_CONVERSATIONS}, Decoded: &libgm.IncomingRPCMessage{
		PayloadSource: libgm.PayloadSourceEncryptedData, IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_DataEvent}, DecryptedMessage: page,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(inboxStore.record.Projection.Conversations) != 2 {
		t.Fatalf("projected conversations = %d, want 2", len(inboxStore.record.Projection.Conversations))
	}
	if len(inboxStore.record.Projection.Cursor) != 0 {
		t.Fatalf("conversation-list cursor committed before child pages: %x", inboxStore.record.Projection.Cursor)
	}
}

func TestBackfillCursorPrefersStructuredReplayableCursor(t *testing.T) {
	cursor := &gmproto.Cursor{LastItemID: "conversation-last", LastItemTimestamp: 1724400000023}
	got, err := backfillCursor([]byte("provider-opaque-fallback"), cursor)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := proto.MarshalOptions{Deterministic: true}.Marshal(cursor)
	if !bytes.Equal(got, want) {
		t.Fatalf("stored cursor = %x, want replayable structured cursor %x", got, want)
	}
}

func TestDurableSinkACKMarkFailsClosedOnStaleFence(t *testing.T) {
	inbox, _ := ingress.NewService(&sinkInbox{})
	sink, _ := NewDurableSink(DurableSinkConfig{Inbox: inbox, ACKs: &sinkACKs{owned: false}, Sealer: &recordingSealer{}})
	err := sink.MarkACKed(context.Background(), connectionactor.ProviderOwnership{Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 1}, []string{"response-a"})
	if !errors.Is(err, ErrDurableFenceLost) {
		t.Fatalf("MarkACKed() error = %v, want ErrDurableFenceLost", err)
	}
}

type failingInboxProcessor struct{ err error }

func (processor failingInboxProcessor) Process(context.Context, ingress.Envelope) (ingress.ProcessResult, error) {
	return ingress.ProcessResult{}, processor.err
}

func TestDurableSinkMapsRepositoryLeaseLossToStaleFence(t *testing.T) {
	sink, _ := NewDurableSink(DurableSinkConfig{
		Inbox: failingInboxProcessor{err: postgres.ErrConnectionLeaseLost}, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{},
	})
	_, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-stale", Raw: []byte("raw-stale"), Decoded: &libgm.IncomingRPCMessage{
		IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_PairEvent},
	}})
	if !errors.Is(err, ErrDurableFenceLost) || !errors.Is(err, postgres.ErrConnectionLeaseLost) {
		t.Fatalf("repository fence error = %v", err)
	}
	acks := &sinkACKs{owned: true, err: postgres.ErrConnectionLeaseLost}
	sink.acks = acks
	if _, err = sink.PendingACKs(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, 256); !errors.Is(err, ErrDurableFenceLost) || !errors.Is(err, postgres.ErrConnectionLeaseLost) {
		t.Fatalf("pending ACK fence error = %v", err)
	}
}

func TestDurableSinkClassifiesOnlyOperationalPersistenceAsInfrastructure(t *testing.T) {
	databaseFailure := errors.New("repository unavailable")
	sink, _ := NewDurableSink(DurableSinkConfig{
		Inbox: failingInboxProcessor{err: databaseFailure}, ACKs: &sinkACKs{owned: true}, Sealer: &recordingSealer{},
	})
	_, err := sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-db", Raw: []byte("raw-db"), Decoded: &libgm.IncomingRPCMessage{
		IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_PairEvent},
	}})
	if !errors.Is(err, ErrDurableInfrastructure) || !errors.Is(err, databaseFailure) {
		t.Fatalf("repository infrastructure error = %v", err)
	}
	sink.inbox = failingInboxProcessor{err: ingress.ErrConflictingEnvelope}
	_, err = sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-conflict", Raw: []byte("raw-conflict"), Decoded: &libgm.IncomingRPCMessage{
		IncomingRPCMessage: &gmproto.IncomingRPCMessage{BugleRoute: gmproto.BugleRoute_PairEvent},
	}})
	if !errors.Is(err, ingress.ErrConflictingEnvelope) || errors.Is(err, ErrDurableInfrastructure) {
		t.Fatalf("provider envelope conflict classification = %v", err)
	}
	sink.inbox = failingInboxProcessor{err: ingress.ErrProviderResponseCapacity}
	_, err = sink.PersistEnvelopeOutcome(context.Background(), connectionactor.ProviderOwnership{
		Key: connectionactor.Key{TenantID: "tenant-a", ConnectionID: "connection-a"}, OwnerID: "owner-a", FencingToken: 9,
	}, libgm.DurableEnvelope{ResponseID: "response-capacity", Raw: []byte("raw-capacity"), DecodeError: errors.New("poison")})
	if !errors.Is(err, ingress.ErrProviderResponseCapacity) || errors.Is(err, ErrDurableInfrastructure) {
		t.Fatalf("provider response capacity classification = %v", err)
	}
}
