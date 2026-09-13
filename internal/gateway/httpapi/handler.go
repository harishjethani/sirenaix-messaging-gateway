package httpapi

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"

	"go.mau.fi/mautrix-gmessages/internal/gateway/auth"
	servercontacts "go.mau.fi/mautrix-gmessages/internal/gateway/contacts"
	"go.mau.fi/mautrix-gmessages/internal/gateway/contactsync"
	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/media"
	"go.mau.fi/mautrix-gmessages/internal/gateway/messaging"
	"go.mau.fi/mautrix-gmessages/internal/gateway/pairing"
	"go.mau.fi/mautrix-gmessages/internal/gateway/store/postgres"
	"go.mau.fi/mautrix-gmessages/internal/gateway/webhook"
)

const (
	maxJSONBodyBytes  = 8 * 1024
	maxRequestIDBytes = 64
	defaultPageLimit  = 50
	maxPageLimit      = 200
)

type Store interface {
	servercontacts.Store
	SaveConnection(ctx context.Context, tenantID domain.TenantID, record postgres.ConnectionRecord) error
	GetConnection(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID) (domain.Connection, error)
	ListConnectionsPage(ctx context.Context, tenantID domain.TenantID, after domain.ConnectionID, limit int) (postgres.ConnectionPage, error)
	ListLines(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID) ([]postgres.LineRecord, error)
	ListContacts(ctx context.Context, tenantID domain.TenantID, options postgres.ContactListOptions) (postgres.ContactPage, error)
	SetContactAlias(ctx context.Context, tenantID domain.TenantID, contactID domain.ContactID, alias string) error
	ClearContactAlias(ctx context.Context, tenantID domain.TenantID, contactID domain.ContactID) error
	ListLabels(ctx context.Context, tenantID domain.TenantID) ([]domain.Label, error)
	CreateLabel(ctx context.Context, tenantID domain.TenantID, label domain.Label) error
	AttachLabel(ctx context.Context, tenantID domain.TenantID, contactID domain.ContactID, labelID domain.LabelID) error
	DetachLabel(ctx context.Context, tenantID domain.TenantID, contactID domain.ContactID, labelID domain.LabelID) error
}

type ConnectionPairer interface {
	Start(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, credentials pairing.Credentials) (pairing.Attempt, error)
	SelectDevice(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, pairingID, deviceID string) (pairing.Attempt, error)
	Complete(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, pairingID string) (pairing.Attempt, error)
	Cancel(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID, pairingID string) error
}

type ContactSyncer interface {
	Sync(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID) (contactsync.SyncResult, error)
}

type HealthReader interface {
	GetConnectionHealth(ctx context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID) (postgres.ConnectionActorHealth, error)
}

type MessageService interface {
	Submit(context.Context, domain.TenantID, string, messaging.SendInput) (messaging.OutboundMessage, error)
	Get(context.Context, domain.TenantID, domain.MessageID) (messaging.OutboundMessage, error)
	List(context.Context, domain.TenantID, messaging.ListOptions) (messaging.MessagePage, error)
}

type MediaService interface {
	Upload(context.Context, domain.TenantID, media.Upload) (media.Record, error)
	GetMetadata(context.Context, domain.TenantID, domain.MediaID) (media.Record, error)
	Open(context.Context, domain.TenantID, domain.MediaID) (io.ReadCloser, media.Record, error)
}

type WebhookService interface {
	Create(context.Context, domain.TenantID, string) (webhook.CreatedEndpoint, error)
	Rotate(context.Context, domain.TenantID, string) (string, error)
	List(context.Context, domain.TenantID, webhook.EndpointListOptions) (webhook.EndpointPage, error)
	Delete(context.Context, domain.TenantID, string) (webhook.DeleteResult, error)
	Replay(context.Context, domain.TenantID, string) error
}

var _ Store = (*postgres.Repository)(nil)
var _ ContactSyncer = (*contactsync.Service)(nil)

type Dependencies struct {
	Store    Store
	Syncer   ContactSyncer
	Pairing  ConnectionPairer
	Health   HealthReader
	Verifier auth.Verifier
	NewID    func() string
	Messages MessageService
	Media    MediaService
	Webhooks WebhookService
}

type handler struct {
	store    Store
	syncer   ContactSyncer
	pairing  ConnectionPairer
	health   HealthReader
	verifier auth.Verifier
	newID    func() string
	messages MessageService
	media    MediaService
	webhooks WebhookService
	contacts *servercontacts.Service
}

func NewHandler(dependencies Dependencies) (http.Handler, error) {
	if isNil(dependencies.Store) {
		return nil, errors.New("http API store is required")
	}
	if isNil(dependencies.Syncer) {
		return nil, errors.New("http API contact syncer is required")
	}
	if isNil(dependencies.Pairing) {
		return nil, errors.New("http API pairing service is required")
	}
	if isNil(dependencies.Verifier) {
		return nil, errors.New("http API token verifier is required")
	}
	if dependencies.NewID == nil {
		return nil, errors.New("http API ID generator is required")
	}
	health := dependencies.Health
	if isNil(health) {
		health, _ = dependencies.Store.(HealthReader)
	}
	contacts, err := servercontacts.NewService(dependencies.Store, dependencies.NewID)
	if err != nil {
		return nil, errors.New("http API contact service is required")
	}
	return &handler{
		store: dependencies.Store, syncer: dependencies.Syncer, pairing: dependencies.Pairing,
		health: health, verifier: dependencies.Verifier, newID: dependencies.NewID,
		messages: dependencies.Messages, media: dependencies.Media, webhooks: dependencies.Webhooks,
		contacts: contacts,
	}, nil
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

type route struct {
	method string
	allow  string
	scope  string
	action func(http.ResponseWriter, *http.Request, auth.Principal, []string)
}

func (api *handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	requestID := acceptedRequestID(request.Header.Get("X-Request-ID"))
	if requestID == "" {
		requestID = newRequestID()
	}
	response.Header().Set("X-Request-ID", requestID)
	response.Header().Set("Cache-Control", "no-store")

	if !strings.HasPrefix(request.URL.Path, "/v1") {
		writeError(response, http.StatusNotFound, "not_found", "resource not found", requestID)
		return
	}
	principal, ok := api.authenticate(response, request, requestID)
	if !ok {
		return
	}
	if hasTenantInput(request) {
		writeError(response, http.StatusBadRequest, "invalid_request", "tenant identity must come from the access token", requestID)
		return
	}
	matched, arguments := api.match(request.URL.Path, request.Method)
	if matched == nil {
		writeError(response, http.StatusNotFound, "not_found", "resource not found", requestID)
		return
	}
	if request.Method != matched.method {
		response.Header().Set("Allow", matched.allow)
		writeError(response, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestID)
		return
	}
	if !principal.HasScope(matched.scope) {
		writeError(response, http.StatusForbidden, "forbidden", "required scope is missing", requestID)
		return
	}
	matched.action(response, request, principal, arguments)
}

func (api *handler) authenticate(response http.ResponseWriter, request *http.Request, requestID string) (auth.Principal, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		response.Header().Set("WWW-Authenticate", "Bearer")
		writeError(response, http.StatusUnauthorized, "unauthorized", "valid bearer token required", requestID)
		return auth.Principal{}, false
	}
	value := values[0]
	if len(value) < len("Bearer ")+1 || !strings.EqualFold(value[:len("Bearer")], "Bearer") || value[len("Bearer")] != ' ' {
		response.Header().Set("WWW-Authenticate", "Bearer")
		writeError(response, http.StatusUnauthorized, "unauthorized", "valid bearer token required", requestID)
		return auth.Principal{}, false
	}
	rawToken := value[len("Bearer "):]
	for index := 0; index < len(rawToken); index++ {
		if rawToken[index] < 0x21 || rawToken[index] > 0x7e || rawToken[index] == ',' {
			response.Header().Set("WWW-Authenticate", "Bearer")
			writeError(response, http.StatusUnauthorized, "unauthorized", "valid bearer token required", requestID)
			return auth.Principal{}, false
		}
	}
	principal, err := api.verifier.Verify(request.Context(), rawToken)
	if err != nil || strings.TrimSpace(principal.Subject) == "" || strings.TrimSpace(string(principal.TenantID)) == "" {
		response.Header().Set("WWW-Authenticate", "Bearer")
		writeError(response, http.StatusUnauthorized, "unauthorized", "valid bearer token required", requestID)
		return auth.Principal{}, false
	}
	return principal, true
}

func (api *handler) match(path, requestMethod string) (*route, []string) {
	if path == "" || strings.HasSuffix(path, "/") {
		return nil, nil
	}
	segments := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(segments) < 2 || segments[0] != "v1" {
		return nil, nil
	}
	read := "messaging:read"
	write := "messaging:write"
	switch {
	case len(segments) == 2 && segments[1] == "connections":
		if requestMethod == http.MethodPost {
			return &route{method: http.MethodPost, allow: http.MethodGet + ", " + http.MethodPost, scope: write, action: api.createConnection}, nil
		}
		return &route{method: http.MethodGet, allow: http.MethodGet + ", " + http.MethodPost, scope: read, action: api.listConnections}, nil
	case len(segments) == 4 && segments[1] == "connections" && segments[2] != "" && segments[3] == "health":
		return &route{method: http.MethodGet, allow: http.MethodGet, scope: read, action: api.connectionHealth}, []string{segments[2]}
	case len(segments) == 4 && segments[1] == "connections" && segments[2] != "" && segments[3] == "lines":
		return &route{method: http.MethodGet, allow: http.MethodGet, scope: read, action: api.listLines}, []string{segments[2]}
	case len(segments) == 4 && segments[1] == "connections" && segments[2] != "" && segments[3] == "messages":
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.submitMessage}, []string{segments[2]}
	case len(segments) == 2 && segments[1] == "messages":
		return &route{method: http.MethodGet, allow: http.MethodGet, scope: read, action: api.listMessages}, nil
	case len(segments) == 3 && segments[1] == "messages" && segments[2] != "":
		return &route{method: http.MethodGet, allow: http.MethodGet, scope: read, action: api.getMessage}, []string{segments[2]}
	case len(segments) == 2 && segments[1] == "media":
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.uploadMedia}, nil
	case len(segments) == 3 && segments[1] == "media" && segments[2] != "":
		return &route{method: http.MethodGet, allow: http.MethodGet, scope: read, action: api.getMedia}, []string{segments[2]}
	case len(segments) == 4 && segments[1] == "media" && segments[2] != "" && segments[3] == "content":
		return &route{method: http.MethodGet, allow: http.MethodGet, scope: read, action: api.getMediaContent}, []string{segments[2]}
	case len(segments) == 2 && segments[1] == "webhooks":
		if requestMethod == http.MethodPost {
			return &route{method: http.MethodPost, allow: http.MethodGet + ", " + http.MethodPost, scope: write, action: api.createWebhook}, nil
		}
		return &route{method: http.MethodGet, allow: http.MethodGet + ", " + http.MethodPost, scope: read, action: api.listWebhooks}, nil
	case len(segments) == 3 && segments[1] == "webhooks" && strings.HasSuffix(segments[2], ":rotate"):
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.rotateWebhook}, []string{strings.TrimSuffix(segments[2], ":rotate")}
	case len(segments) == 3 && segments[1] == "webhooks" && segments[2] != "":
		return &route{method: http.MethodDelete, allow: http.MethodDelete, scope: write, action: api.deleteWebhook}, []string{segments[2]}
	case len(segments) == 4 && segments[1] == "webhooks" && segments[2] == "dlq" && strings.HasSuffix(segments[3], ":replay"):
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.replayWebhookDLQ}, []string{strings.TrimSuffix(segments[3], ":replay")}
	case len(segments) == 4 && segments[1] == "connections" && segments[2] != "" && segments[3] == "contacts:sync":
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.syncContacts}, []string{segments[2]}
	case len(segments) == 5 && segments[1] == "connections" && segments[2] != "" && segments[3] == "pairing" && segments[4] == "start":
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.startPairing}, []string{segments[2]}
	case len(segments) == 5 && segments[1] == "connections" && segments[2] != "" && segments[3] == "pairing" && segments[4] == "complete":
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.completePairing}, []string{segments[2]}
	case len(segments) == 5 && segments[1] == "connections" && segments[2] != "" && segments[3] == "pairing" && segments[4] == "cancel":
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.cancelPairing}, []string{segments[2]}
	case len(segments) == 4 && segments[1] == "connections" && segments[2] != "" && segments[3] == "reauthorize":
		return &route{method: http.MethodPost, allow: http.MethodPost, scope: write, action: api.reauthorize}, []string{segments[2]}
	case len(segments) == 2 && segments[1] == "contacts":
		if requestMethod == http.MethodPut {
			return &route{method: http.MethodPut, allow: http.MethodGet + ", " + http.MethodPut, scope: write, action: api.putContact}, nil
		}
		return &route{method: http.MethodGet, allow: http.MethodGet + ", " + http.MethodPut, scope: read, action: api.listContacts}, nil
	case len(segments) == 3 && segments[1] == "contacts" && segments[2] != "":
		return &route{method: http.MethodPatch, allow: http.MethodPatch, scope: write, action: api.patchContact}, []string{segments[2]}
	case len(segments) == 2 && segments[1] == "labels":
		if requestMethod == http.MethodPost {
			return &route{method: http.MethodPost, allow: http.MethodGet + ", " + http.MethodPost, scope: write, action: api.createLabel}, nil
		}
		return &route{method: http.MethodGet, allow: http.MethodGet + ", " + http.MethodPost, scope: read, action: api.listLabels}, nil
	case len(segments) == 5 && segments[1] == "contacts" && segments[2] != "" && segments[3] == "labels" && segments[4] != "":
		if requestMethod == http.MethodDelete {
			return &route{method: http.MethodDelete, allow: http.MethodPut + ", " + http.MethodDelete, scope: write, action: api.detachLabel}, []string{segments[2], segments[4]}
		}
		return &route{method: http.MethodPut, allow: http.MethodPut + ", " + http.MethodDelete, scope: write, action: api.attachLabel}, []string{segments[2], segments[4]}
	default:
		return nil, nil
	}
}
