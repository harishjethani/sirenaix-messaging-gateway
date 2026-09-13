package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.mau.fi/mautrix-gmessages/internal/gateway/auth"
	"go.mau.fi/mautrix-gmessages/internal/gateway/contactsync"
	"go.mau.fi/mautrix-gmessages/internal/gateway/domain"
	"go.mau.fi/mautrix-gmessages/internal/gateway/pairing"
	"go.mau.fi/mautrix-gmessages/internal/gateway/store/postgres"
)

func TestAuthenticationFailsClosedWithStableSafeErrors(t *testing.T) {
	store := newFakeStore(t)
	handler := newTestHandler(t, store, &fakeSyncer{}, tokenVerifier{})
	tests := []struct {
		name          string
		authorization string
	}{
		{name: "missing"},
		{name: "wrong scheme", authorization: "Basic abc"},
		{name: "empty bearer", authorization: "Bearer "},
		{name: "extra value", authorization: "Bearer valid extra"},
		{name: "invalid token", authorization: "Bearer invalid"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/connections", nil)
			request.Header.Set("Authorization", test.authorization)
			request.Header.Set("X-Request-ID", "request-example-123")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertError(t, response, http.StatusUnauthorized, "unauthorized", "request-example-123")
			if strings.Contains(response.Body.String(), "signature fixture detail") {
				t.Fatalf("response leaked verifier detail: %s", response.Body.String())
			}
			if got := response.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Fatalf("WWW-Authenticate = %q", got)
			}
		})
	}

	if _, err := NewHandler(Dependencies{Store: store, Syncer: &fakeSyncer{}, NewID: func() string { return "id" }}); err == nil {
		t.Fatal("nil verifier unexpectedly accepted")
	}
}

func TestReadAndWriteScopesAreEnforced(t *testing.T) {
	store := newFakeStore(t)
	syncer := &fakeSyncer{}
	verifier := tokenVerifier{principals: map[string]auth.Principal{
		"read":  {Subject: "reader", TenantID: "tenant-example", Scopes: []string{"messaging:read"}},
		"write": {Subject: "writer", TenantID: "tenant-example", Scopes: []string{"messaging:write"}},
	}}
	handler := newTestHandler(t, store, syncer, verifier)

	assertStatus(t, serve(handler, http.MethodGet, "/v1/connections", nil, "read"), http.StatusOK)
	assertError(t, serve(handler, http.MethodGet, "/v1/connections", nil, "write"), http.StatusForbidden, "forbidden", "")
	assertStatus(t, serve(handler, http.MethodPost, "/v1/connections/connection-example/contacts:sync", nil, "write"), http.StatusOK)
	assertError(t, serve(handler, http.MethodPost, "/v1/connections/connection-example/contacts:sync", nil, "read"), http.StatusForbidden, "forbidden", "")
}

func TestPrincipalTenantIsTheOnlyTenantPassedToDependencies(t *testing.T) {
	store := newFakeStore(t)
	syncer := &fakeSyncer{}
	handler := newTestHandler(t, store, syncer, validVerifier())

	assertStatus(t, serve(handler, http.MethodGet, "/v1/connections", nil, "valid"), http.StatusOK)
	if store.lastTenant != "tenant-example" {
		t.Fatalf("repository tenant = %q", store.lastTenant)
	}

	for name, request := range map[string]*http.Request{
		"query":  authenticatedRequest(http.MethodGet, "/v1/connections?tenant_id=tenant-attacker", nil, "valid"),
		"header": authenticatedRequest(http.MethodGet, "/v1/connections", nil, "valid"),
		"body":   authenticatedJSONRequest(http.MethodPost, "/v1/connections/connection-example/contacts:sync", `{"tenant_id":"tenant-attacker"}`, "valid"),
	} {
		t.Run(name, func(t *testing.T) {
			if name == "header" {
				request.Header.Set("X-Tenant-ID", "tenant-attacker")
			}
			beforeStore, beforeSync := store.calls, syncer.calls
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertError(t, response, http.StatusBadRequest, "invalid_request", "")
			if store.calls != beforeStore || syncer.calls != beforeSync {
				t.Fatal("tenant injection reached a dependency")
			}
		})
	}
}

func TestConnectionsHealthAndMultiSIMLines(t *testing.T) {
	store := newFakeStore(t)
	store.connections = []postgres.ConnectionRecord{{Connection: domain.Connection{
		ID: "connection-example", TenantID: "tenant-example", Name: "Front desk phone",
		State: domain.ConnectionStateReauthorizationRequired,
	}}}
	phoneA := mustPhone(t, "+1 202 555 0101")
	phoneB := mustPhone(t, "+1 202 555 0102")
	store.lines = []postgres.LineRecord{
		{Line: domain.Line{ID: "line-a", TenantID: "tenant-example", ConnectionID: "connection-example", DisplayName: "Line A"}, Phone: phoneA,
			CarrierName: "Carrier A", ColorHex: "#123456", RCSEnabled: true, ProviderSIMNumber: 1, ProviderSIMPayloadType: 2,
			DiscoverySource: postgres.LineDiscoveryAuthenticatedGoogleSettings},
		{Line: domain.Line{ID: "line-b", TenantID: "tenant-example", ConnectionID: "connection-example", DisplayName: "Line B"}, Phone: phoneB,
			DiscoverySource: postgres.LineDiscoveryAuthenticatedGoogleSettings},
	}
	handler := newTestHandler(t, store, &fakeSyncer{}, validVerifier())

	connections := serve(handler, http.MethodGet, "/v1/connections", nil, "valid")
	assertStatus(t, connections, http.StatusOK)
	assertJSONContains(t, connections.Body.Bytes(), `"name":"Front desk phone"`, `"state":"reauthorization-required"`)

	health := serve(handler, http.MethodGet, "/v1/connections/connection-example/health", nil, "valid")
	assertStatus(t, health, http.StatusOK)
	assertJSONContains(t, health.Body.Bytes(), `"requires_reauthorization":true`, `"state":"reauthorization-required"`)

	lines := serve(handler, http.MethodGet, "/v1/connections/connection-example/lines", nil, "valid")
	assertStatus(t, lines, http.StatusOK)
	assertJSONContains(t, lines.Body.Bytes(),
		`"phone":"+12025550101"`, `"phone":"+12025550102"`, `"carrier_name":"Carrier A"`, `"color_hex":"#123456"`,
		`"rcs_enabled":true`, `"provider_sim_number":1`, `"provider_sim_payload_type":2`,
		`"discovery_source":"authenticated_google_settings"`, `"explicit_line_send":"existing_conversation_match_only"`,
		`"new_conversation_line_selection":false`, `"new_conversation_route":"phone_default"`)
}

func TestConnectionsListUsesStrictBoundedPagination(t *testing.T) {
	store := newFakeStore(t)
	store.connectionNext = "connection-next"
	handler := newTestHandler(t, store, &fakeSyncer{}, validVerifier())
	response := serve(handler, http.MethodGet, "/v1/connections?after=connection-before&limit=1", nil, "valid")
	assertStatus(t, response, http.StatusOK)
	assertJSONContains(t, response.Body.Bytes(), `"next_cursor":"connection-next"`)
	if store.lastConnectionAfter != "connection-before" || store.lastConnectionLimit != 1 {
		t.Fatalf("connection page = after:%q limit:%d", store.lastConnectionAfter, store.lastConnectionLimit)
	}
	for _, target := range []string{
		"/v1/connections?after=first&after=second", "/v1/connections?limit=1&limit=2",
		"/v1/connections?after=", "/v1/connections?limit=0", "/v1/connections?limit=201",
	} {
		assertStatus(t, serve(handler, http.MethodGet, target, nil, "valid"), http.StatusBadRequest)
	}
}

func TestCreateConnectionMapsTenantQuotaWithoutLeakingCounts(t *testing.T) {
	store := newFakeStore(t)
	store.saveConnectionErr = postgres.ErrConnectionQuotaExceeded
	handler := newTestHandler(t, store, &fakeSyncer{}, validVerifier())
	response := serveJSON(handler, http.MethodPost, "/v1/connections", `{"display_label":"Front phone"}`, "valid")
	assertError(t, response, http.StatusConflict, "resource_limit", "")
}

func TestConnectionHealthExposesOnlySafeActorLivenessFields(t *testing.T) {
	store := newFakeStore(t)
	connectedAt := time.Date(2026, 8, 23, 15, 0, 0, 0, time.UTC)
	frameAt := connectedAt.Add(time.Minute)
	health := &fakeHealthReader{health: postgres.ConnectionActorHealth{
		ActorState: "ready", LeaseState: "owned", ConnectionState: domain.ConnectionStateConnected,
		ConnectedAt: &connectedAt, LastFrameAt: &frameAt, ReconnectCount: 3,
		CurrentBackoff: 250 * time.Millisecond, LastSafeReason: "transient-network", FencingToken: 17,
	}}
	handler, err := NewHandler(Dependencies{
		Store: store, Health: health, Syncer: &fakeSyncer{}, Pairing: &fakePairer{}, Verifier: validVerifier(),
		NewID: func() string { return "generated-label" },
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	response := serve(handler, http.MethodGet, "/v1/connections/connection-example/health", nil, "valid")
	assertStatus(t, response, http.StatusOK)
	body := response.Body.String()
	assertJSONContains(t, response.Body.Bytes(),
		`"actor_state":"ready"`, `"lease_state":"owned"`, `"connected_at":"2026-08-23T15:00:00Z"`,
		`"last_frame_at":"2026-08-23T15:01:00Z"`, `"reconnect_count":3`, `"current_backoff_ms":250`,
		`"last_safe_reason":"transient-network"`)
	for _, secret := range []string{"tenant-example", "owner-a", "phone", "fencing_token", `"17"`} {
		if strings.Contains(body, secret) {
			t.Fatalf("health response exposed %q: %s", secret, body)
		}
	}
}

func TestConnectionHealthKeepsAuthoritativeReauthorizationStateOverStaleActorHealth(t *testing.T) {
	store := newFakeStore(t)
	store.connections[0].Connection.State = domain.ConnectionStateReauthorizationRequired
	health := &fakeHealthReader{health: postgres.ConnectionActorHealth{
		ActorState: "ready", LeaseState: "inactive", ConnectionState: domain.ConnectionStateConnected,
		LastSafeReason: "none", RequiresReauthorization: false, FencingToken: 16,
	}}
	handler, err := NewHandler(Dependencies{
		Store: store, Health: health, Syncer: &fakeSyncer{}, Pairing: &fakePairer{}, Verifier: validVerifier(),
		NewID: func() string { return "generated-label" },
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	response := serve(handler, http.MethodGet, "/v1/connections/connection-example/health", nil, "valid")
	assertStatus(t, response, http.StatusOK)
	assertJSONContains(t, response.Body.Bytes(), `"state":"reauthorization-required"`, `"requires_reauthorization":true`, `"actor_state":"ready"`)
}

type fakeHealthReader struct {
	health postgres.ConnectionActorHealth
	err    error
}

func (reader *fakeHealthReader) GetConnectionHealth(context.Context, domain.TenantID, domain.ConnectionID) (postgres.ConnectionActorHealth, error) {
	return reader.health, reader.err
}

func TestPairingEndpointsCreateAndAdvanceTenantScopedConnectionWithoutEchoingSecrets(t *testing.T) {
	store := newFakeStore(t)
	pairer := &fakePairer{start: pairing.Attempt{
		ID: "pairing-safe", State: pairing.StateAwaitingDeviceSelection,
		Devices: []pairing.Device{{ID: "phone-a", Label: "Phone A"}, {ID: "phone-b", Label: "Phone B"}},
	}}
	handler, err := NewHandler(Dependencies{Store: store, Syncer: &fakeSyncer{}, Pairing: pairer, Verifier: validVerifier(), NewID: func() string { return "connection-new" }})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	created := serveJSON(handler, http.MethodPost, "/v1/connections", `{"display_label":" Front phone "}`, "valid")
	assertStatus(t, created, http.StatusCreated)
	assertJSONContains(t, created.Body.Bytes(), `"id":"connection-new"`, `"state":"unpaired"`, `"name":"Front phone"`)
	if store.savedConnection.Connection.TenantID != "tenant-example" || len(store.savedConnection.ProviderDeviceFingerprint) != 0 {
		t.Fatalf("created connection = %#v", store.savedConnection)
	}

	secret := "private-cookie-marker"
	started := serveJSON(handler, http.MethodPost, "/v1/connections/connection-new/pairing/start",
		`{"cookies":{"SID":"`+secret+`","HSID":"2","OSID":"3","SSID":"4","APISID":"5","SAPISID":"6"}}`, "valid")
	assertStatus(t, started, http.StatusOK)
	assertJSONContains(t, started.Body.Bytes(), `"pairing_id":"pairing-safe"`, `"state":"awaiting_device_selection"`, `"id":"phone-a"`)
	if strings.Contains(started.Body.String(), secret) || pairer.lastTenant != "tenant-example" || pairer.lastConnection != "connection-new" {
		t.Fatalf("unsafe/incorrect pairing start: body=%s pairer=%#v", started.Body.String(), pairer)
	}

	pairer.selected = pairing.Attempt{ID: "pairing-safe", State: pairing.StateAwaitingPhoneApproval, Emoji: "🦊"}
	selected := serveJSON(handler, http.MethodPost, "/v1/connections/connection-new/pairing/start",
		`{"pairing_id":"pairing-safe","selected_device_id":"phone-b"}`, "valid")
	assertStatus(t, selected, http.StatusOK)
	assertJSONContains(t, selected.Body.Bytes(), `"state":"awaiting_phone_approval"`, `"emoji":"🦊"`)

	pairer.completed = pairing.Attempt{ID: "pairing-safe", State: pairing.StateComplete}
	completed := serveJSON(handler, http.MethodPost, "/v1/connections/connection-new/pairing/complete", `{"pairing_id":"pairing-safe"}`, "valid")
	assertStatus(t, completed, http.StatusOK)
	assertJSONContains(t, completed.Body.Bytes(), `"state":"complete"`)
	assertStatus(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-new/pairing/cancel", `{"pairing_id":"pairing-safe"}`, "valid"), http.StatusNoContent)
}

func TestPairingEndpointsEnforceWriteScopeTenantAndSafeErrors(t *testing.T) {
	store := newFakeStore(t)
	pairer := &fakePairer{err: pairing.ErrInvalidCookieBundle}
	verifier := tokenVerifier{principals: map[string]auth.Principal{
		"read":  {Subject: "reader", TenantID: "tenant-example", Scopes: []string{"messaging:read"}},
		"write": {Subject: "writer", TenantID: "tenant-example", Scopes: []string{"messaging:write"}},
	}}
	handler, err := NewHandler(Dependencies{Store: store, Syncer: &fakeSyncer{}, Pairing: pairer, Verifier: verifier, NewID: func() string { return "connection-new" }})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	body := `{"cookies":{"SID":"private-cookie-marker"}}`
	assertError(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/start", body, "read"), http.StatusForbidden, "forbidden", "")
	failure := serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/start", body, "write")
	assertError(t, failure, http.StatusBadRequest, "invalid_cookie_bundle", "")
	if strings.Contains(failure.Body.String(), "private-cookie-marker") {
		t.Fatalf("provider detail leaked: %s", failure.Body.String())
	}
	pairer.err = errors.New("provider failed around private-cookie-marker")
	failure = serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/start", body, "write")
	assertError(t, failure, http.StatusInternalServerError, "internal_error", "")
	if strings.Contains(failure.Body.String(), "private-cookie-marker") {
		t.Fatalf("provider detail leaked: %s", failure.Body.String())
	}
	assertError(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/reauthorize", `{"cookies":{"SID":"secret"}}`, "write"), http.StatusBadRequest, "invalid_request", "")
	reauthorize := serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/reauthorize", `{}`, "write")
	assertStatus(t, reauthorize, http.StatusOK)
	assertJSONContains(t, reauthorize.Body.Bytes(), `"next_action":"post_pairing_start"`)
}

func TestPairingStartForwardsBoundedGoogleAccountIndex(t *testing.T) {
	store := newFakeStore(t)
	pairer := &fakePairer{start: pairing.Attempt{ID: "pairing-safe", State: pairing.StateAwaitingDeviceSelection}}
	handler, err := NewHandler(Dependencies{Store: store, Syncer: &fakeSyncer{}, Pairing: pairer, Verifier: validVerifier(), NewID: func() string { return "connection-new" }})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	cookies := `{"SID":"1","HSID":"2","OSID":"3","SSID":"4","APISID":"5","SAPISID":"6","__Secure-1PSIDTS":"7"}`
	started := serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/start", `{"cookies":`+cookies+`,"google_authuser":1}`, "valid")
	assertStatus(t, started, http.StatusOK)
	if pairer.lastCredentials.GoogleAuthUser != 1 || pairer.lastCredentials.Cookies["__Secure-1PSIDTS"] != "7" {
		t.Fatalf("forwarded credentials = %+v", pairer.lastCredentials)
	}
	pairer.lastTenant, pairer.lastConnection = "", ""
	for _, body := range []string{
		`{"cookies":` + cookies + `,"google_authuser":10}`,
		`{"cookies":` + cookies + `,"google_authuser":-1}`,
		`{"cookies":` + cookies + `,"google_authuser":"1"}`,
		`{"pairing_id":"pairing-safe","selected_device_id":"phone-a","google_authuser":1}`,
	} {
		assertError(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/start", body, "valid"), http.StatusBadRequest, "invalid_request", "")
	}
	if pairer.lastTenant != "" || pairer.lastConnection != "" {
		t.Fatal("invalid google account index reached the pairing service")
	}
}

func TestPairingEndpointsShareStrictPairingAndDeviceIDValidation(t *testing.T) {
	store := newFakeStore(t)
	pairer := &fakePairer{}
	handler, err := NewHandler(Dependencies{Store: store, Syncer: &fakeSyncer{}, Pairing: pairer, Verifier: validVerifier(), NewID: func() string { return "connection-new" }})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	invalidPairingIDs := []string{"short", "invalid.dot", strings.Repeat("a", 129), "valid-id\ncontrol"}
	for _, pairingID := range invalidPairingIDs {
		body := `{"pairing_id":` + strconv.Quote(pairingID) + `}`
		assertError(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/complete", body, "valid"), http.StatusBadRequest, "invalid_request", "")
		assertError(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/cancel", body, "valid"), http.StatusBadRequest, "invalid_request", "")
		selection := `{"pairing_id":` + strconv.Quote(pairingID) + `,"selected_device_id":"phone-a"}`
		assertError(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/start", selection, "valid"), http.StatusBadRequest, "invalid_request", "")
	}
	for _, deviceID := range []string{"", "phone id", "phone\ncontrol", strings.Repeat("d", 257)} {
		selection := `{"pairing_id":"pairing-safe","selected_device_id":` + strconv.Quote(deviceID) + `}`
		assertError(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/pairing/start", selection, "valid"), http.StatusBadRequest, "invalid_request", "")
	}
	if pairer.lastTenant != "" || pairer.lastConnection != "" {
		t.Fatal("invalid pairing identifiers reached the pairing service")
	}
}

func TestCrossTenantAndMissingObjectsFailClosed(t *testing.T) {
	store := newFakeStore(t)
	store.connectionErr = contactsync.ErrConnectionNotFound
	handler := newTestHandler(t, store, &fakeSyncer{err: contactsync.ErrConnectionAccessDenied}, validVerifier())
	for _, test := range []struct{ method, path, body string }{
		{http.MethodGet, "/v1/connections/connection-other/health", ""},
		{http.MethodGet, "/v1/connections/connection-other/lines", ""},
		{http.MethodPost, "/v1/connections/connection-other/contacts:sync", ""},
	} {
		var response *httptest.ResponseRecorder
		if test.body == "" {
			response = serve(handler, test.method, test.path, nil, "valid")
		} else {
			response = serveJSON(handler, test.method, test.path, test.body, "valid")
		}
		assertError(t, response, http.StatusNotFound, "not_found", "")
	}

	store.connectionErr = nil
	store.aliasErr = postgres.ErrContactNotFound
	assertError(t, serveJSON(handler, http.MethodPatch, "/v1/contacts/contact-other", `{"server_alias":"Prospect"}`, "valid"), http.StatusNotFound, "not_found", "")
	store.attachErr = postgres.ErrContactLabelLinkNotFound
	assertError(t, serve(handler, http.MethodPut, "/v1/contacts/contact-other/labels/label-other", nil, "valid"), http.StatusNotFound, "not_found", "")
}

func TestContactPaginationAndAIReadyContactShape(t *testing.T) {
	store := newFakeStore(t)
	store.labels = []domain.Label{{ID: "label-potential", TenantID: "tenant-example", Name: "Potential Client", Slug: "potential-client"}}
	store.contacts = []domain.Contact{{
		ID: "contact-example", TenantID: "tenant-example", Phone: mustPhone(t, "+1 202 555 0140"),
		ProviderDisplayName: "Provider Name", Alias: "Server Alias", LabelIDs: []domain.LabelID{"label-potential"},
	}}
	store.nextCursor = "contact-next"
	handler := newTestHandler(t, store, &fakeSyncer{}, validVerifier())

	first := serve(handler, http.MethodGet, "/v1/contacts", nil, "valid")
	assertStatus(t, first, http.StatusOK)
	if store.lastContactOptions.Limit != 50 || store.lastContactOptions.After != "" {
		t.Fatalf("default options = %#v", store.lastContactOptions)
	}
	assertJSONContains(t, first.Body.Bytes(),
		`"id":"contact-example"`, `"phone":"+12025550140"`, `"provider_name":"Provider Name"`,
		`"server_alias":"Server Alias"`, `"effective_display_name":"Server Alias"`, `"slug":"potential-client"`)
	var firstPage struct {
		NextCursor string `json:"next_cursor"`
	}
	decodeJSON(t, first.Body.Bytes(), &firstPage)
	if firstPage.NextCursor == "" || strings.Contains(firstPage.NextCursor, "contact-next") {
		t.Fatalf("cursor is not opaque: %q", firstPage.NextCursor)
	}

	second := serve(handler, http.MethodGet, "/v1/contacts?limit=200&cursor="+firstPage.NextCursor, nil, "valid")
	assertStatus(t, second, http.StatusOK)
	if store.lastContactOptions.Limit != 200 || store.lastContactOptions.After != "contact-next" {
		t.Fatalf("decoded options = %#v", store.lastContactOptions)
	}

	for _, query := range []string{"?limit=0", "?limit=201", "?limit=abc", "?cursor=not-base64!", "?cursor=" + firstPage.NextCursor + "&cursor=" + firstPage.NextCursor} {
		assertError(t, serve(handler, http.MethodGet, "/v1/contacts"+query, nil, "valid"), http.StatusBadRequest, "invalid_request", "")
	}
}

func TestPutContactCreatesServerLeadBeforeProviderImportAndIsTenantIdempotent(t *testing.T) {
	store := newFakeStore(t)
	handler := newTestHandler(t, store, &fakeSyncer{}, validVerifier())

	first := serveJSON(handler, http.MethodPut, "/v1/contacts", `{"phone":"+12025550199","server_alias":"  Potential Client  "}`, "valid")
	assertStatus(t, first, http.StatusOK)
	assertJSONContains(t, first.Body.Bytes(), `"id":"generated-label"`, `"phone":"+12025550199"`, `"server_alias":"Potential Client"`)
	if store.upsertContactPhone.String() != "+12025550199" || store.upsertContactAlias == nil || *store.upsertContactAlias != "Potential Client" || store.lastTenant != "tenant-example" {
		t.Fatalf("server contact upsert = phone:%q alias:%v tenant:%q", store.upsertContactPhone.String(), store.upsertContactAlias, store.lastTenant)
	}

	second := serveJSON(handler, http.MethodPut, "/v1/contacts", `{"phone":"+12025550199"}`, "valid")
	assertStatus(t, second, http.StatusOK)
	assertJSONContains(t, second.Body.Bytes(), `"id":"generated-label"`, `"server_alias":"Potential Client"`)
	if store.upsertContactAlias != nil {
		t.Fatalf("omitted alias became an overwrite: %v", store.upsertContactAlias)
	}
	if store.upsertContactCalls != 2 {
		t.Fatalf("upsert calls = %d", store.upsertContactCalls)
	}
}

func TestPutContactRejectsLocalNumbersUnknownFieldsAndOversizedAliases(t *testing.T) {
	handler := newTestHandler(t, newFakeStore(t), &fakeSyncer{}, validVerifier())
	for _, body := range []string{
		`{"phone":"202-555-0199"}`,
		`{"phone":"+1 (202) 555-0199"}`,
		`{"phone":"+12025550199","unknown":true}`,
		`{"phone":"+12025550199","server_alias":"` + strings.Repeat("x", 257) + `"}`,
	} {
		assertError(t, serveJSON(handler, http.MethodPut, "/v1/contacts", body, "valid"), http.StatusBadRequest, "invalid_request", "")
	}
}

func TestAliasSetClearAndStrictJSON(t *testing.T) {
	store := newFakeStore(t)
	handler := newTestHandler(t, store, &fakeSyncer{}, validVerifier())

	assertStatus(t, serveJSON(handler, http.MethodPatch, "/v1/contacts/contact-example", `{"server_alias":"  Priority Lead  "}`, "valid"), http.StatusNoContent)
	if store.aliasSet != "Priority Lead" || store.aliasContact != "contact-example" {
		t.Fatalf("alias set = %q for %q", store.aliasSet, store.aliasContact)
	}
	assertStatus(t, serveJSON(handler, http.MethodPatch, "/v1/contacts/contact-example", `{"server_alias":null}`, "valid"), http.StatusNoContent)
	if !store.aliasCleared {
		t.Fatal("alias was not cleared")
	}

	for name, body := range map[string]string{
		"unknown":        `{"nickname":"Lead"}`,
		"provider field": `{"provider_name":"Overwrite"}`,
		"tenant":         `{"tenant_id":"tenant-attacker","server_alias":"Lead"}`,
		"missing":        `{}`,
		"trailing":       `{"server_alias":"Lead"} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			assertError(t, serveJSON(handler, http.MethodPatch, "/v1/contacts/contact-example", body, "valid"), http.StatusBadRequest, "invalid_request", "")
		})
	}
	tooLarge := `{"server_alias":"` + strings.Repeat("a", maxJSONBodyBytes+1) + `"}`
	assertError(t, serveJSON(handler, http.MethodPatch, "/v1/contacts/contact-example", tooLarge, "valid"), http.StatusRequestEntityTooLarge, "request_too_large", "")
}

func TestPotentialClientLabelCreateListAttachAndIdempotentDetach(t *testing.T) {
	store := newFakeStore(t)
	store.contacts = []domain.Contact{{ID: "contact-example", TenantID: "tenant-example", Phone: mustPhone(t, "+12025550155")}}
	handler := newTestHandler(t, store, &fakeSyncer{}, validVerifier())

	created := serveJSON(handler, http.MethodPost, "/v1/labels", `{"name":" Potential Client "}`, "valid")
	assertStatus(t, created, http.StatusCreated)
	assertJSONContains(t, created.Body.Bytes(), `"id":"generated-label"`, `"slug":"potential-client"`)
	if len(store.labels) != 1 || store.labels[0].TenantID != "tenant-example" {
		t.Fatalf("created labels = %#v", store.labels)
	}

	converged := serveJSON(handler, http.MethodPost, "/v1/labels", `{"name":"potential client"}`, "valid")
	assertStatus(t, converged, http.StatusOK)
	if len(store.labels) != 1 {
		t.Fatalf("duplicate label was created: %#v", store.labels)
	}
	listed := serve(handler, http.MethodGet, "/v1/labels", nil, "valid")
	assertStatus(t, listed, http.StatusOK)
	assertJSONContains(t, listed.Body.Bytes(), `"slug":"potential-client"`)

	assertStatus(t, serve(handler, http.MethodPut, "/v1/contacts/contact-example/labels/generated-label", nil, "valid"), http.StatusNoContent)
	if store.attachedContact != "contact-example" || store.attachedLabel != "generated-label" {
		t.Fatalf("attach = %q/%q", store.attachedContact, store.attachedLabel)
	}
	beforeContacts, beforeLabels := store.listContactsCalls, store.listLabelsCalls
	assertStatus(t, serve(handler, http.MethodDelete, "/v1/contacts/contact-example/labels/generated-label", nil, "valid"), http.StatusNoContent)
	if store.listContactsCalls != beforeContacts || store.listLabelsCalls != beforeLabels || store.detachCalls != 1 {
		t.Fatal("DELETE did not delegate directly to the atomic detach operation")
	}
	assertStatus(t, serve(handler, http.MethodDelete, "/v1/contacts/contact-example/labels/generated-label", nil, "valid"), http.StatusNoContent)

	store.detachErr = postgres.ErrContactNotFound
	assertError(t, serve(handler, http.MethodDelete, "/v1/contacts/contact-other/labels/generated-label", nil, "valid"), http.StatusNotFound, "not_found", "")
	store.detachErr = postgres.ErrLabelNotFound
	assertError(t, serve(handler, http.MethodDelete, "/v1/contacts/contact-example/labels/label-other", nil, "valid"), http.StatusNotFound, "not_found", "")
}

func TestManualContactSyncReturnsOnlySafeSummary(t *testing.T) {
	store := newFakeStore(t)
	syncer := &fakeSyncer{result: contactsync.SyncResult{
		Contacts: []domain.Contact{{ID: "contact-example"}, {ID: "contact-other"}},
		Rejected: []contactsync.RejectedContact{
			{ProviderContactID: "raw-provider-id", PhoneNumber: "+12025559999", Reason: contactsync.RejectionInvalidPhoneNumber},
			{ProviderContactID: "raw-provider-id-2", PhoneNumber: "secret", Reason: contactsync.RejectionInvalidProviderContactID},
		},
	}}
	handler := newTestHandler(t, store, syncer, validVerifier())
	response := serve(handler, http.MethodPost, "/v1/connections/connection-example/contacts:sync", nil, "valid")
	assertStatus(t, response, http.StatusOK)
	assertJSONContains(t, response.Body.Bytes(), `"accepted":2`, `"quarantined":2`, `"invalid_phone_number":1`, `"invalid_provider_contact_id":1`)
	if strings.Contains(response.Body.String(), "raw-provider-id") || strings.Contains(response.Body.String(), "+12025559999") || strings.Contains(response.Body.String(), "secret") {
		t.Fatalf("sync response leaked provider data: %s", response.Body.String())
	}
	if syncer.lastTenant != "tenant-example" || syncer.lastConnection != "connection-example" {
		t.Fatalf("sync scope = %q/%q", syncer.lastTenant, syncer.lastConnection)
	}
}

func TestBodylessRoutesRejectUnexpectedAndOversizedBodiesBeforeDependencies(t *testing.T) {
	store := newFakeStore(t)
	syncer := &fakeSyncer{}
	handler := newTestHandler(t, store, syncer, validVerifier())

	for name, body := range map[string]string{
		"tenant field":  `{"tenant_id":"tenant-attacker"}`,
		"unknown field": `{"unexpected":true}`,
	} {
		t.Run("GET "+name, func(t *testing.T) {
			before := store.calls
			response := serveJSON(handler, http.MethodGet, "/v1/connections", body, "valid")
			assertError(t, response, http.StatusBadRequest, "invalid_request", "")
			if store.calls != before {
				t.Fatal("unexpected GET body reached repository")
			}
		})
	}

	beforeSync := syncer.calls
	assertError(t, serveJSON(handler, http.MethodPost, "/v1/connections/connection-example/contacts:sync", `{}`, "valid"), http.StatusBadRequest, "invalid_request", "")
	if syncer.calls != beforeSync {
		t.Fatal("unexpected manual sync body reached syncer")
	}

	oversized := authenticatedRequest(http.MethodGet, "/v1/contacts", strings.NewReader(strings.Repeat("x", maxJSONBodyBytes+1)), "valid")
	oversized.ContentLength = -1
	oversized.TransferEncoding = []string{"chunked"}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, oversized)
	assertError(t, response, http.StatusRequestEntityTooLarge, "request_too_large", "")
	if store.listContactsCalls != 0 {
		t.Fatal("oversized chunked body reached repository")
	}
}

func TestBodylessRoutesRejectUnsupportedQueriesWithStableJSONError(t *testing.T) {
	store := newFakeStore(t)
	syncer := &fakeSyncer{}
	handler := newTestHandler(t, store, syncer, validVerifier())
	tests := []struct {
		name   string
		method string
		path   string
	}{
		{name: "connections", method: http.MethodGet, path: "/v1/connections"},
		{name: "health", method: http.MethodGet, path: "/v1/connections/connection-example/health"},
		{name: "lines", method: http.MethodGet, path: "/v1/connections/connection-example/lines"},
		{name: "manual sync", method: http.MethodPost, path: "/v1/connections/connection-example/contacts:sync"},
		{name: "labels", method: http.MethodGet, path: "/v1/labels"},
		{name: "attach label", method: http.MethodPut, path: "/v1/contacts/contact-example/labels/label-example"},
		{name: "detach label", method: http.MethodDelete, path: "/v1/contacts/contact-example/labels/label-example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			beforeStore, beforeSync := store.calls, syncer.calls
			request := authenticatedRequest(test.method, test.path+"?unexpected=example", nil, "valid")
			request.Header.Set("X-Request-ID", "query-error-example")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)

			assertError(t, response, http.StatusBadRequest, "invalid_request", "query-error-example")
			if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
				t.Fatalf("Content-Type = %q", got)
			}
			if store.calls != beforeStore || syncer.calls != beforeSync {
				t.Fatal("invalid query reached a dependency")
			}
		})
	}
}

func TestBearerHeaderGrammarRejectsAmbiguousValues(t *testing.T) {
	principals := map[string]auth.Principal{}
	for _, token := range []string{"valid", "valid,", "valid\x7f", "válid"} {
		principals[token] = auth.Principal{Subject: "subject-example", TenantID: "tenant-example", Scopes: []string{"messaging:read"}}
	}
	handler := newTestHandler(t, newFakeStore(t), &fakeSyncer{}, tokenVerifier{principals: principals})
	for name, values := range map[string][]string{
		"two spaces":       {"Bearer  valid"},
		"tab separator":    {"Bearer\tvalid"},
		"comma ambiguity":  {"Bearer valid,"},
		"control byte":     {"Bearer valid\x7f"},
		"non ASCII":        {"Bearer válid"},
		"duplicate fields": {"Bearer valid", "Bearer valid"},
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/connections", nil)
			request.Header["Authorization"] = values
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			assertError(t, response, http.StatusUnauthorized, "unauthorized", "")
		})
	}
	assertStatus(t, serve(handler, http.MethodGet, "/v1/connections", nil, "valid"), http.StatusOK)
	request := httptest.NewRequest(http.MethodGet, "/v1/connections", nil)
	request.Header.Set("Authorization", "bearer valid")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertStatus(t, response, http.StatusOK)
}

func TestCursorBoundsRejectOversizeBeforeDecodeAllocation(t *testing.T) {
	const prefix = "sirenaix-contact-v1\x00"
	boundaryDecoded := prefix + strings.Repeat("a", 512-len(prefix))
	boundary := base64.RawURLEncoding.EncodeToString([]byte(boundaryDecoded))
	if _, err := decodeCursor(boundary); err != nil {
		t.Fatalf("maximum cursor was rejected: %v", err)
	}

	oversized := strings.Repeat("A", 684)
	allocations := testing.AllocsPerRun(100, func() {
		if _, err := decodeCursor(oversized); !errors.Is(err, postgres.ErrInvalidCursor) {
			t.Fatalf("oversized cursor error = %v", err)
		}
	})
	if allocations != 0 {
		t.Fatalf("oversized cursor allocated before rejection: %.1f allocations", allocations)
	}
}

func TestMethodAllowSensitiveHeadersAndRequestIDBounds(t *testing.T) {
	handler := newTestHandler(t, newFakeStore(t), &fakeSyncer{}, validVerifier())
	wrongMethod := serve(handler, http.MethodPatch, "/v1/connections", nil, "valid")
	assertError(t, wrongMethod, http.StatusMethodNotAllowed, "method_not_allowed", "")
	if got := wrongMethod.Header().Get("Allow"); got != http.MethodGet+", "+http.MethodPost {
		t.Fatalf("Allow = %q", got)
	}
	if got := wrongMethod.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q", got)
	}
	if got := wrongMethod.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q", got)
	}

	request := authenticatedRequest(http.MethodGet, "/v1/connections", nil, "valid")
	request.Header.Set("X-Request-ID", strings.Repeat("x", 129))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if got := response.Header().Get("X-Request-ID"); got == "" || len(got) > maxRequestIDBytes || got == request.Header.Get("X-Request-ID") {
		t.Fatalf("generated request ID = %q", got)
	}
}

type tokenVerifier struct{ principals map[string]auth.Principal }

func validVerifier() tokenVerifier {
	return tokenVerifier{principals: map[string]auth.Principal{"valid": {
		Subject: "subject-example", TenantID: "tenant-example", Scopes: []string{"messaging:read", "messaging:write"},
	}}}
}

func (v tokenVerifier) Verify(_ context.Context, token string) (auth.Principal, error) {
	if principal, ok := v.principals[token]; ok {
		return principal, nil
	}
	return auth.Principal{}, errors.New("signature fixture detail")
}

type fakeSyncer struct {
	result         contactsync.SyncResult
	err            error
	calls          int
	lastTenant     domain.TenantID
	lastConnection domain.ConnectionID
}

func (s *fakeSyncer) Sync(_ context.Context, tenantID domain.TenantID, connectionID domain.ConnectionID) (contactsync.SyncResult, error) {
	s.calls++
	s.lastTenant, s.lastConnection = tenantID, connectionID
	return s.result, s.err
}

type fakeStore struct {
	connections         []postgres.ConnectionRecord
	connectionErr       error
	connectionNext      domain.ConnectionID
	lastConnectionAfter domain.ConnectionID
	lastConnectionLimit int
	saveConnectionErr   error
	lines               []postgres.LineRecord
	contacts            []domain.Contact
	nextCursor          domain.ContactID
	labels              []domain.Label
	aliasErr            error
	attachErr           error
	detachErr           error
	calls               int
	lastTenant          domain.TenantID
	lastContactOptions  postgres.ContactListOptions
	aliasSet            string
	aliasContact        domain.ContactID
	aliasCleared        bool
	attachedContact     domain.ContactID
	attachedLabel       domain.LabelID
	listContactsCalls   int
	listLabelsCalls     int
	detachCalls         int
	savedConnection     postgres.ConnectionRecord
	upsertContactPhone  domain.E164Phone
	upsertContactAlias  *string
	upsertContactCalls  int
}

func newFakeStore(t *testing.T) *fakeStore {
	t.Helper()
	return &fakeStore{connections: []postgres.ConnectionRecord{{Connection: domain.Connection{
		ID: "connection-example", TenantID: "tenant-example", Name: "Example phone", State: domain.ConnectionStateConnected,
	}}}}
}

func (s *fakeStore) record(tenantID domain.TenantID) { s.calls++; s.lastTenant = tenantID }

func (s *fakeStore) GetConnection(_ context.Context, tenantID domain.TenantID, id domain.ConnectionID) (domain.Connection, error) {
	s.record(tenantID)
	if s.connectionErr != nil {
		return domain.Connection{}, s.connectionErr
	}
	for _, record := range s.connections {
		if record.Connection.ID == id && record.Connection.TenantID == tenantID {
			return record.Connection, nil
		}
	}
	return domain.Connection{}, contactsync.ErrConnectionNotFound
}

func (s *fakeStore) SaveConnection(_ context.Context, tenantID domain.TenantID, record postgres.ConnectionRecord) error {
	s.record(tenantID)
	if s.saveConnectionErr != nil {
		return s.saveConnectionErr
	}
	s.savedConnection = record
	s.connections = append(s.connections, record)
	return nil
}

func (s *fakeStore) ListConnectionsPage(_ context.Context, tenantID domain.TenantID, after domain.ConnectionID, limit int) (postgres.ConnectionPage, error) {
	s.record(tenantID)
	s.lastConnectionAfter, s.lastConnectionLimit = after, limit
	return postgres.ConnectionPage{Records: append([]postgres.ConnectionRecord(nil), s.connections...), NextCursor: s.connectionNext}, nil
}

func (s *fakeStore) ListLines(_ context.Context, tenantID domain.TenantID, _ domain.ConnectionID) ([]postgres.LineRecord, error) {
	s.record(tenantID)
	return append([]postgres.LineRecord(nil), s.lines...), nil
}

func (s *fakeStore) ListContacts(_ context.Context, tenantID domain.TenantID, options postgres.ContactListOptions) (postgres.ContactPage, error) {
	s.record(tenantID)
	s.listContactsCalls++
	s.lastContactOptions = options
	return postgres.ContactPage{Contacts: append([]domain.Contact(nil), s.contacts...), NextCursor: s.nextCursor}, nil
}

func (s *fakeStore) UpsertServerContact(_ context.Context, tenantID domain.TenantID, createdID domain.ContactID, phone domain.E164Phone, alias *string) (domain.Contact, error) {
	s.record(tenantID)
	s.upsertContactCalls++
	s.upsertContactPhone, s.upsertContactAlias = phone, alias
	for index := range s.contacts {
		if s.contacts[index].TenantID == tenantID && s.contacts[index].Phone == phone {
			if alias != nil {
				s.contacts[index].Alias = *alias
			}
			return s.contacts[index], nil
		}
	}
	contact := domain.Contact{ID: createdID, TenantID: tenantID, Phone: phone}
	if alias != nil {
		contact.Alias = *alias
	}
	s.contacts = append(s.contacts, contact)
	return contact, nil
}

func (s *fakeStore) SetContactAlias(_ context.Context, tenantID domain.TenantID, contactID domain.ContactID, alias string) error {
	s.record(tenantID)
	s.aliasContact, s.aliasSet = contactID, strings.TrimSpace(alias)
	return s.aliasErr
}

func (s *fakeStore) ClearContactAlias(_ context.Context, tenantID domain.TenantID, contactID domain.ContactID) error {
	s.record(tenantID)
	s.aliasContact, s.aliasCleared = contactID, true
	return s.aliasErr
}

func (s *fakeStore) ListLabels(_ context.Context, tenantID domain.TenantID) ([]domain.Label, error) {
	s.record(tenantID)
	s.listLabelsCalls++
	return append([]domain.Label(nil), s.labels...), nil
}

func (s *fakeStore) CreateLabel(_ context.Context, tenantID domain.TenantID, label domain.Label) error {
	s.record(tenantID)
	s.labels = append(s.labels, label)
	return nil
}

func (s *fakeStore) AttachLabel(_ context.Context, tenantID domain.TenantID, contactID domain.ContactID, labelID domain.LabelID) error {
	s.record(tenantID)
	s.attachedContact, s.attachedLabel = contactID, labelID
	return s.attachErr
}

func (s *fakeStore) DetachLabel(_ context.Context, tenantID domain.TenantID, contactID domain.ContactID, labelID domain.LabelID) error {
	s.record(tenantID)
	s.detachCalls++
	return s.detachErr
}

type fakePairer struct {
	start, selected, completed pairing.Attempt
	err                        error
	lastTenant                 domain.TenantID
	lastConnection             domain.ConnectionID
	lastCredentials            pairing.Credentials
}

func (pairer *fakePairer) Start(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID, credentials pairing.Credentials) (pairing.Attempt, error) {
	pairer.lastTenant, pairer.lastConnection, pairer.lastCredentials = tenant, connection, credentials
	return pairer.start, pairer.err
}
func (pairer *fakePairer) SelectDevice(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID, _, _ string) (pairing.Attempt, error) {
	pairer.lastTenant, pairer.lastConnection = tenant, connection
	return pairer.selected, pairer.err
}
func (pairer *fakePairer) Complete(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID, _ string) (pairing.Attempt, error) {
	pairer.lastTenant, pairer.lastConnection = tenant, connection
	return pairer.completed, pairer.err
}
func (pairer *fakePairer) Cancel(_ context.Context, tenant domain.TenantID, connection domain.ConnectionID, _ string) error {
	pairer.lastTenant, pairer.lastConnection = tenant, connection
	return pairer.err
}

func newTestHandler(t *testing.T, store Store, syncer ContactSyncer, verifier auth.Verifier) http.Handler {
	t.Helper()
	handler, err := NewHandler(Dependencies{Store: store, Syncer: syncer, Pairing: &fakePairer{}, Verifier: verifier, NewID: func() string { return "generated-label" }})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return handler
}

func serve(handler http.Handler, method, path string, body io.Reader, token string) *httptest.ResponseRecorder {
	request := authenticatedRequest(method, path, body, token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func serveJSON(handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	request := authenticatedJSONRequest(method, path, body, token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func authenticatedRequest(method, path string, body io.Reader, token string) *http.Request {
	request := httptest.NewRequest(method, path, body)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	return request
}

func authenticatedJSONRequest(method, path, body, token string) *http.Request {
	request := authenticatedRequest(method, path, bytes.NewBufferString(body), token)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func assertStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status = %d, want %d; body=%s", response.Code, want, response.Body.String())
	}
}

func assertError(t *testing.T, response *httptest.ResponseRecorder, status int, code, requestID string) {
	t.Helper()
	assertStatus(t, response, status)
	var envelope struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}
	decodeJSON(t, response.Body.Bytes(), &envelope)
	if envelope.Error.Code != code || envelope.Error.Message == "" || envelope.Error.RequestID == "" {
		t.Fatalf("unexpected error envelope: %#v", envelope)
	}
	if requestID != "" && envelope.Error.RequestID != requestID {
		t.Fatalf("request ID = %q, want %q", envelope.Error.RequestID, requestID)
	}
	if response.Header().Get("X-Request-ID") != envelope.Error.RequestID {
		t.Fatal("response and envelope request IDs differ")
	}
}

func assertJSONContains(t *testing.T, body []byte, fragments ...string) {
	t.Helper()
	compact := new(bytes.Buffer)
	if err := json.Compact(compact, body); err != nil {
		t.Fatalf("invalid JSON %q: %v", body, err)
	}
	for _, fragment := range fragments {
		if !strings.Contains(compact.String(), fragment) {
			t.Fatalf("JSON %s does not contain %s", compact.String(), fragment)
		}
	}
}

func decodeJSON(t *testing.T, body []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode JSON %q: %v", body, err)
	}
}

func mustPhone(t *testing.T, value string) domain.E164Phone {
	t.Helper()
	phone, err := domain.ParseE164(value)
	if err != nil {
		t.Fatalf("ParseE164: %v", err)
	}
	return phone
}
