package httpapi

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"go.mau.fi/mautrix-gmessages/internal/gateway/auth"
	servercontacts "go.mau.fi/mautrix-gmessages/internal/gateway/contacts"
	"go.mau.fi/mautrix-gmessages/internal/gateway/contactsync"
	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/pairing"
	"go.mau.fi/mautrix-gmessages/internal/gateway/store/postgres"
)

type connectionResponse struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	State string `json:"state"`
}

type labelResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type contactResponse struct {
	ID                   string          `json:"id"`
	Phone                string          `json:"phone"`
	ProviderName         string          `json:"provider_name"`
	ServerAlias          string          `json:"server_alias"`
	EffectiveDisplayName string          `json:"effective_display_name"`
	Labels               []labelResponse `json:"labels"`
}

func (api *handler) createConnection(response http.ResponseWriter, request *http.Request, principal auth.Principal, _ []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	var body struct {
		DisplayLabel string `json:"display_label"`
	}
	if !decodeStrictJSON(response, request, &body) {
		return
	}
	label := strings.TrimSpace(body.DisplayLabel)
	id := api.newID()
	if label == "" || len(label) > 128 || !utf8.ValidString(label) || !validStableID(id) {
		writeInvalidRequest(response)
		return
	}
	record := postgres.ConnectionRecord{Connection: domain.Connection{
		ID: domain.ConnectionID(id), TenantID: principal.TenantID, Name: label, State: domain.ConnectionStateUnpaired,
	}}
	if err := api.store.SaveConnection(request.Context(), principal.TenantID, record); err != nil {
		if errors.Is(err, postgres.ErrConnectionQuotaExceeded) {
			writeError(response, http.StatusConflict, "resource_limit", "tenant connection quota reached", response.Header().Get("X-Request-ID"))
			return
		}
		writeInternalError(response)
		return
	}
	writeJSON(response, http.StatusCreated, connectionResponse{ID: id, Name: label, State: string(domain.ConnectionStateUnpaired)})
}

func (api *handler) startPairing(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	var body struct {
		Cookies          map[string]string `json:"cookies,omitempty"`
		GoogleAuthUser   *int              `json:"google_authuser,omitempty"`
		PairingID        string            `json:"pairing_id,omitempty"`
		SelectedDeviceID string            `json:"selected_device_id,omitempty"`
	}
	if !decodeStrictJSON(response, request, &body) {
		return
	}
	connectionID := domain.ConnectionID(arguments[0])
	var attempt pairing.Attempt
	var err error
	if body.Cookies != nil && body.PairingID == "" && body.SelectedDeviceID == "" {
		credentials := pairing.Credentials{Cookies: body.Cookies}
		if body.GoogleAuthUser != nil {
			if !pairing.ValidGoogleAuthUser(*body.GoogleAuthUser) {
				writeInvalidRequest(response)
				return
			}
			credentials.GoogleAuthUser = *body.GoogleAuthUser
		}
		attempt, err = api.pairing.Start(request.Context(), principal.TenantID, connectionID, credentials)
	} else if body.Cookies == nil && body.GoogleAuthUser == nil && body.PairingID != "" && body.SelectedDeviceID != "" {
		if !pairing.ValidPairingID(body.PairingID) || !pairing.ValidDeviceID(body.SelectedDeviceID) {
			writeInvalidRequest(response)
			return
		}
		attempt, err = api.pairing.SelectDevice(request.Context(), principal.TenantID, connectionID, body.PairingID, body.SelectedDeviceID)
	} else {
		writeInvalidRequest(response)
		return
	}
	if err != nil {
		writePairingError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, attempt)
}

func (api *handler) completePairing(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	pairingID, ok := decodePairingID(response, request)
	if !ok {
		return
	}
	attempt, err := api.pairing.Complete(request.Context(), principal.TenantID, domain.ConnectionID(arguments[0]), pairingID)
	if err != nil {
		writePairingError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, attempt)
}

func (api *handler) cancelPairing(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	pairingID, ok := decodePairingID(response, request)
	if !ok {
		return
	}
	if err := api.pairing.Cancel(request.Context(), principal.TenantID, domain.ConnectionID(arguments[0]), pairingID); err != nil {
		writePairingError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (api *handler) reauthorize(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	var body struct{}
	if !decodeStrictJSON(response, request, &body) {
		return
	}
	if _, ok := api.ownedConnection(response, request, principal.TenantID, domain.ConnectionID(arguments[0])); !ok {
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{
		"next_action": "post_pairing_start",
		"path":        "/v1/connections/" + arguments[0] + "/pairing/start",
	})
}

func decodePairingID(response http.ResponseWriter, request *http.Request) (string, bool) {
	var body struct {
		PairingID string `json:"pairing_id"`
	}
	if !decodeStrictJSON(response, request, &body) {
		return "", false
	}
	if !pairing.ValidPairingID(body.PairingID) {
		writeInvalidRequest(response)
		return "", false
	}
	return body.PairingID, true
}

func writePairingError(response http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, pairing.ErrAttemptNotFound):
		writeNotFound(response)
	case errors.Is(err, pairing.ErrAttemptActive), errors.Is(err, pairing.ErrAttemptBusy), errors.Is(err, pairing.ErrInvalidConnectionState):
		writeError(response, http.StatusConflict, "pairing_conflict", "connection cannot begin pairing", response.Header().Get("X-Request-ID"))
	case errors.Is(err, pairing.ErrAttemptExpired):
		writeError(response, http.StatusGone, "pairing_expired", "pairing attempt expired", response.Header().Get("X-Request-ID"))
	case errors.Is(err, pairing.ErrUnknownDevice):
		writeError(response, http.StatusBadRequest, "invalid_device", "selected device is not eligible", response.Header().Get("X-Request-ID"))
	case errors.Is(err, pairing.ErrInvalidCookieBundle):
		writeError(response, http.StatusBadRequest, "invalid_cookie_bundle", "Google cookie bundle is invalid", response.Header().Get("X-Request-ID"))
	default:
		writeInternalError(response)
	}
}

func validStableID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, char := range value {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.') {
			return false
		}
	}
	return true
}

func (api *handler) listConnections(response http.ResponseWriter, request *http.Request, principal auth.Principal, _ []string) {
	if !queryIsExactly(request, map[string]bool{"after": true, "limit": true}) {
		writeInvalidRequest(response)
		return
	}
	if !ensureEmptyBody(response, request) {
		return
	}
	query := request.URL.Query()
	if values, exists := query["after"]; exists && (values[0] == "" || len(values[0]) > 256 || strings.ContainsAny(values[0], "\x00\r\n")) {
		writeInvalidRequest(response)
		return
	}
	limit := defaultPageLimit
	if values, exists := query["limit"]; exists {
		parsed, err := strconv.Atoi(values[0])
		if values[0] == "" || err != nil || parsed < 1 || parsed > maxPageLimit {
			writeInvalidRequest(response)
			return
		}
		limit = parsed
	}
	page, err := api.store.ListConnectionsPage(request.Context(), principal.TenantID, domain.ConnectionID(query.Get("after")), limit)
	if err != nil {
		writeInternalError(response)
		return
	}
	connections := make([]connectionResponse, 0, len(page.Records))
	for _, record := range page.Records {
		connection := record.Connection
		if connection.TenantID != principal.TenantID || connection.ID == "" || connection.State.Validate() != nil {
			writeNotFound(response)
			return
		}
		connections = append(connections, connectionResponse{ID: string(connection.ID), Name: connection.Name, State: string(connection.State)})
	}
	payload := map[string]any{"connections": connections}
	if page.NextCursor != "" {
		payload["next_cursor"] = page.NextCursor
	}
	writeJSON(response, http.StatusOK, payload)
}

func (api *handler) connectionHealth(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	if !ensureEmptyBody(response, request) {
		return
	}
	connection, ok := api.ownedConnection(response, request, principal.TenantID, domain.ConnectionID(arguments[0]))
	if !ok {
		return
	}
	payload := map[string]any{
		"connection_id":            string(connection.ID),
		"state":                    string(connection.State),
		"requires_reauthorization": connection.State == domain.ConnectionStateReauthorizationRequired,
	}
	if api.health != nil {
		health, err := api.health.GetConnectionHealth(request.Context(), principal.TenantID, connection.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeInternalError(response)
			return
		}
		if err == nil {
			payload["lease_state"] = health.LeaseState
			if health.ActorState != "" {
				payload["actor_state"] = health.ActorState
				payload["reconnect_count"] = health.ReconnectCount
				payload["current_backoff_ms"] = health.CurrentBackoff.Milliseconds()
				payload["last_safe_reason"] = health.LastSafeReason
			}
			if health.ConnectedAt != nil {
				payload["connected_at"] = health.ConnectedAt.UTC()
			}
			if health.LastFrameAt != nil {
				payload["last_frame_at"] = health.LastFrameAt.UTC()
			}
			if health.LastPhoneResponseAt != nil {
				payload["last_phone_response_at"] = health.LastPhoneResponseAt.UTC()
			}
		}
	}
	writeJSON(response, http.StatusOK, payload)
}

func (api *handler) listLines(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	if !ensureEmptyBody(response, request) {
		return
	}
	connectionID := domain.ConnectionID(arguments[0])
	connection, ok := api.ownedConnection(response, request, principal.TenantID, connectionID)
	if !ok {
		return
	}
	records, err := api.store.ListLines(request.Context(), principal.TenantID, connectionID)
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	lines := make([]map[string]any, 0, len(records))
	for _, record := range records {
		if record.Line.ID == "" || record.Phone.String() == "" || record.Line.ValidateFor(connection) != nil ||
			(record.DiscoverySource != postgres.LineDiscoveryAuthenticatedGoogleSettings && record.DiscoverySource != postgres.LineDiscoveryLegacyUnknown) {
			writeNotFound(response)
			return
		}
		line := map[string]any{
			"id": string(record.Line.ID), "connection_id": string(record.Line.ConnectionID),
			"phone": record.Phone.String(), "display_name": record.Line.DisplayName,
			"rcs_enabled": record.RCSEnabled, "provider_sim_number": record.ProviderSIMNumber,
			"provider_sim_payload_type": record.ProviderSIMPayloadType, "discovery_source": record.DiscoverySource,
		}
		if record.CarrierName != "" {
			line["carrier_name"] = record.CarrierName
		}
		if record.ColorHex != "" {
			line["color_hex"] = record.ColorHex
		}
		lines = append(lines, line)
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"lines": lines,
		"routing_capabilities": map[string]any{
			"explicit_line_send":              "existing_conversation_match_only",
			"new_conversation_line_selection": false,
			"new_conversation_route":          "phone_default",
		},
	})
}

func (api *handler) syncContacts(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	if !ensureEmptyBody(response, request) {
		return
	}
	result, err := api.syncer.Sync(request.Context(), principal.TenantID, domain.ConnectionID(arguments[0]))
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	reasons := make(map[string]int)
	for _, rejected := range result.Rejected {
		reasons[string(rejected.Reason)]++
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"accepted": len(result.Contacts), "quarantined": len(result.Rejected), "reasons": reasons,
	})
}

func (api *handler) listContacts(response http.ResponseWriter, request *http.Request, principal auth.Principal, _ []string) {
	if !ensureEmptyBody(response, request) {
		return
	}
	options, ok := contactPageOptions(response, request)
	if !ok {
		return
	}
	page, err := api.store.ListContacts(request.Context(), principal.TenantID, options)
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	labels, err := api.ownedLabels(request, principal.TenantID)
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	labelByID := make(map[domain.LabelID]domain.Label, len(labels))
	for _, label := range labels {
		labelByID[label.ID] = label
	}
	contacts := make([]contactResponse, 0, len(page.Contacts))
	for _, contact := range page.Contacts {
		if contact.TenantID != principal.TenantID || contact.ID == "" || contact.Phone.String() == "" {
			writeNotFound(response)
			return
		}
		view, err := makeContactResponse(contact, labelByID)
		if err != nil {
			writeInternalError(response)
			return
		}
		contacts = append(contacts, view)
	}
	next := ""
	if page.NextCursor != "" {
		next = encodeCursor(page.NextCursor)
	}
	writeJSON(response, http.StatusOK, map[string]any{"contacts": contacts, "next_cursor": next})
}

func (api *handler) putContact(response http.ResponseWriter, request *http.Request, principal auth.Principal, _ []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	var body struct {
		Phone       string          `json:"phone"`
		ServerAlias json.RawMessage `json:"server_alias,omitempty"`
	}
	if !decodeStrictJSON(response, request, &body) {
		return
	}
	var alias *string
	if body.ServerAlias != nil {
		value := ""
		if !bytes.Equal(bytes.TrimSpace(body.ServerAlias), []byte("null")) && json.Unmarshal(body.ServerAlias, &value) != nil {
			writeInvalidRequest(response)
			return
		}
		alias = &value
	}
	contact, err := api.contacts.Upsert(request.Context(), principal.TenantID, servercontacts.UpsertInput{Phone: body.Phone, ServerAlias: alias})
	if err != nil {
		if errors.Is(err, servercontacts.ErrInvalidContact) {
			writeInvalidRequest(response)
		} else {
			writeDependencyError(response, err)
		}
		return
	}
	labels, err := api.ownedLabels(request, principal.TenantID)
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	labelByID := make(map[domain.LabelID]domain.Label, len(labels))
	for _, label := range labels {
		labelByID[label.ID] = label
	}
	view, err := makeContactResponse(contact, labelByID)
	if err != nil {
		writeInternalError(response)
		return
	}
	writeJSON(response, http.StatusOK, view)
}

func makeContactResponse(contact domain.Contact, labels map[domain.LabelID]domain.Label) (contactResponse, error) {
	view := contactResponse{
		ID: string(contact.ID), Phone: contact.Phone.String(), ProviderName: contact.ProviderDisplayName,
		ServerAlias: contact.Alias, EffectiveDisplayName: contact.EffectiveDisplayName(),
		Labels: make([]labelResponse, 0, len(contact.LabelIDs)),
	}
	for _, labelID := range contact.LabelIDs {
		label, exists := labels[labelID]
		if !exists {
			return contactResponse{}, fmt.Errorf("contact references missing label")
		}
		view.Labels = append(view.Labels, makeLabelResponse(label))
	}
	return view, nil
}

func (api *handler) patchContact(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	var body struct {
		ServerAlias json.RawMessage `json:"server_alias"`
	}
	if !decodeStrictJSON(response, request, &body) {
		return
	}
	if body.ServerAlias == nil {
		writeInvalidRequest(response)
		return
	}
	contactID := domain.ContactID(arguments[0])
	var err error
	if bytes.Equal(bytes.TrimSpace(body.ServerAlias), []byte("null")) {
		err = api.store.ClearContactAlias(request.Context(), principal.TenantID, contactID)
	} else {
		var alias string
		if json.Unmarshal(body.ServerAlias, &alias) != nil {
			writeInvalidRequest(response)
			return
		}
		alias = strings.TrimSpace(alias)
		if alias == "" {
			err = api.store.ClearContactAlias(request.Context(), principal.TenantID, contactID)
		} else {
			err = api.store.SetContactAlias(request.Context(), principal.TenantID, contactID, alias)
		}
	}
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (api *handler) listLabels(response http.ResponseWriter, request *http.Request, principal auth.Principal, _ []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	if !ensureEmptyBody(response, request) {
		return
	}
	labels, err := api.ownedLabels(request, principal.TenantID)
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	views := make([]labelResponse, 0, len(labels))
	for _, label := range labels {
		views = append(views, makeLabelResponse(label))
	}
	writeJSON(response, http.StatusOK, map[string]any{"labels": views})
}

func (api *handler) createLabel(response http.ResponseWriter, request *http.Request, principal auth.Principal, _ []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	var body struct {
		Name string `json:"name"`
	}
	if !decodeStrictJSON(response, request, &body) {
		return
	}
	desired, err := domain.NewLabel(domain.LabelID(api.newID()), principal.TenantID, body.Name)
	if err != nil {
		writeInvalidRequest(response)
		return
	}
	labels, err := api.ownedLabels(request, principal.TenantID)
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	if existing, found := labelBySlug(labels, desired.Slug); found {
		writeJSON(response, http.StatusOK, makeLabelResponse(existing))
		return
	}
	if err := api.store.CreateLabel(request.Context(), principal.TenantID, desired); err != nil {
		// A concurrent request may have won the tenant+slug unique race. Re-read
		// before deciding this is an internal failure so callers converge.
		labels, listErr := api.ownedLabels(request, principal.TenantID)
		if listErr == nil {
			if existing, found := labelBySlug(labels, desired.Slug); found {
				writeJSON(response, http.StatusOK, makeLabelResponse(existing))
				return
			}
		}
		writeInternalError(response)
		return
	}
	writeJSON(response, http.StatusCreated, makeLabelResponse(desired))
}

func (api *handler) attachLabel(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	if !ensureEmptyBody(response, request) {
		return
	}
	err := api.store.AttachLabel(request.Context(), principal.TenantID, domain.ContactID(arguments[0]), domain.LabelID(arguments[1]))
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (api *handler) detachLabel(response http.ResponseWriter, request *http.Request, principal auth.Principal, arguments []string) {
	if !queryIsExactly(request, nil) {
		writeInvalidRequest(response)
		return
	}
	if !ensureEmptyBody(response, request) {
		return
	}
	contactID := domain.ContactID(arguments[0])
	labelID := domain.LabelID(arguments[1])
	err := api.store.DetachLabel(request.Context(), principal.TenantID, contactID, labelID)
	if err != nil {
		writeDependencyError(response, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (api *handler) ownedConnection(response http.ResponseWriter, request *http.Request, tenantID domain.TenantID, connectionID domain.ConnectionID) (domain.Connection, bool) {
	connection, err := api.store.GetConnection(request.Context(), tenantID, connectionID)
	if err != nil {
		writeDependencyError(response, err)
		return domain.Connection{}, false
	}
	if connection.ID != connectionID || connection.TenantID != tenantID || connection.State.Validate() != nil {
		writeNotFound(response)
		return domain.Connection{}, false
	}
	return connection, true
}

func (api *handler) ownedLabels(request *http.Request, tenantID domain.TenantID) ([]domain.Label, error) {
	labels, err := api.store.ListLabels(request.Context(), tenantID)
	if err != nil {
		return nil, err
	}
	for _, label := range labels {
		canonical, canonicalErr := domain.NewLabel(label.ID, tenantID, label.Name)
		if canonicalErr != nil || label.TenantID != tenantID || canonical.Slug != label.Slug {
			return nil, domain.ErrTenantBoundary
		}
	}
	return labels, nil
}

func makeLabelResponse(label domain.Label) labelResponse {
	return labelResponse{ID: string(label.ID), Name: label.Name, Slug: label.Slug}
}

func labelBySlug(labels []domain.Label, slug string) (domain.Label, bool) {
	for _, label := range labels {
		if label.Slug == slug {
			return label, true
		}
	}
	return domain.Label{}, false
}

func contactPageOptions(response http.ResponseWriter, request *http.Request) (postgres.ContactListOptions, bool) {
	if !queryIsExactly(request, map[string]bool{"limit": true, "cursor": true}) {
		writeInvalidRequest(response)
		return postgres.ContactListOptions{}, false
	}
	options := postgres.ContactListOptions{Limit: defaultPageLimit}
	if values, exists := request.URL.Query()["limit"]; exists {
		if len(values) != 1 || values[0] == "" {
			writeInvalidRequest(response)
			return postgres.ContactListOptions{}, false
		}
		limit, err := strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > maxPageLimit {
			writeInvalidRequest(response)
			return postgres.ContactListOptions{}, false
		}
		options.Limit = limit
	}
	if values, exists := request.URL.Query()["cursor"]; exists {
		if len(values) != 1 || values[0] == "" {
			writeInvalidRequest(response)
			return postgres.ContactListOptions{}, false
		}
		after, err := decodeCursor(values[0])
		if err != nil {
			writeInvalidRequest(response)
			return postgres.ContactListOptions{}, false
		}
		options.After = after
	}
	return options, true
}

func encodeCursor(after domain.ContactID) string {
	return base64.RawURLEncoding.EncodeToString([]byte("sirenaix-contact-v1\x00" + string(after)))
}

func decodeCursor(value string) (domain.ContactID, error) {
	const maxDecodedCursorBytes = 512
	const maxEncodedCursorBytes = 683
	if len(value) > maxEncodedCursorBytes {
		return "", postgres.ErrInvalidCursor
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > maxDecodedCursorBytes || !utf8.Valid(decoded) {
		return "", postgres.ErrInvalidCursor
	}
	const prefix = "sirenaix-contact-v1\x00"
	if !bytes.HasPrefix(decoded, []byte(prefix)) {
		return "", postgres.ErrInvalidCursor
	}
	after := string(decoded[len(prefix):])
	if after == "" || strings.ContainsAny(after, "\x00\r\n") {
		return "", postgres.ErrInvalidCursor
	}
	return domain.ContactID(after), nil
}

func queryIsExactly(request *http.Request, allowed map[string]bool) bool {
	for name, values := range request.URL.Query() {
		if !allowed[name] || len(values) != 1 {
			return false
		}
	}
	return true
}

func singleHeaderValue(request *http.Request, name string) (string, bool) {
	values := request.Header.Values(name)
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func decodeStrictJSON(response http.ResponseWriter, request *http.Request, target any) bool {
	contentType, ok := singleHeaderValue(request, "Content-Type")
	if !ok {
		writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", response.Header().Get("X-Request-ID"))
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		writeError(response, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json", response.Header().Get("X-Request-ID"))
		return false
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeJSONDecodeError(response, err)
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSONDecodeError(response, err)
		return false
	}
	return true
}

func ensureEmptyBody(response http.ResponseWriter, request *http.Request) bool {
	if request.Body == nil || request.Body == http.NoBody {
		return true
	}
	limited := http.MaxBytesReader(response, request.Body, maxJSONBodyBytes)
	contents, err := io.ReadAll(limited)
	if err != nil {
		writeJSONDecodeError(response, err)
		return false
	}
	if len(bytes.TrimSpace(contents)) != 0 {
		writeInvalidRequest(response)
		return false
	}
	return true
}

func writeJSONDecodeError(response http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(response, http.StatusRequestEntityTooLarge, "request_too_large", "request body is too large", response.Header().Get("X-Request-ID"))
		return
	}
	writeInvalidRequest(response)
}

func writeDependencyError(response http.ResponseWriter, err error) {
	if isNotFound(err) {
		writeNotFound(response)
		return
	}
	writeInternalError(response)
}

func isNotFound(err error) bool {
	return errors.Is(err, contactsync.ErrConnectionNotFound) ||
		errors.Is(err, contactsync.ErrConnectionAccessDenied) ||
		errors.Is(err, contactsync.ErrContactAccessDenied) ||
		errors.Is(err, postgres.ErrContactNotFound) ||
		errors.Is(err, postgres.ErrLabelNotFound) ||
		errors.Is(err, postgres.ErrContactLabelLinkNotFound) ||
		errors.Is(err, domain.ErrTenantBoundary) ||
		errors.Is(err, domain.ErrConnectionBoundary)
}

func writeInvalidRequest(response http.ResponseWriter) {
	writeError(response, http.StatusBadRequest, "invalid_request", "request is invalid", response.Header().Get("X-Request-ID"))
}

func writeNotFound(response http.ResponseWriter) {
	writeError(response, http.StatusNotFound, "not_found", "resource not found", response.Header().Get("X-Request-ID"))
}

func writeInternalError(response http.ResponseWriter) {
	writeError(response, http.StatusInternalServerError, "internal_error", "request could not be completed", response.Header().Get("X-Request-ID"))
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	encoded, err := json.Marshal(value)
	if err != nil {
		writeInternalError(response)
		return
	}
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_, _ = response.Write(append(encoded, '\n'))
}

func writeError(response http.ResponseWriter, status int, code, message, requestID string) {
	writeJSON(response, status, map[string]any{"error": map[string]string{
		"code": code, "message": message, "request_id": requestID,
	}})
}

func hasTenantInput(request *http.Request) bool {
	if _, exists := request.Header[http.CanonicalHeaderKey("X-Tenant-ID")]; exists {
		return true
	}
	for name := range request.URL.Query() {
		normalized := strings.ToLower(strings.ReplaceAll(name, "-", "_"))
		if normalized == "tenant" || normalized == "tenant_id" || normalized == "tenantid" {
			return true
		}
	}
	return false
}

func acceptedRequestID(candidate string) string {
	if candidate == "" || len(candidate) > maxRequestIDBytes {
		return ""
	}
	for _, char := range candidate {
		if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.') {
			return ""
		}
	}
	return candidate
}

func newRequestID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "request-unavailable"
	}
	return hex.EncodeToString(buffer)
}
