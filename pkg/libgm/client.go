package libgm

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/mautrix-gmessages/pkg/libgm/crypto"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/events"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/gmproto"
	"go.mau.fi/mautrix-gmessages/pkg/libgm/util"
)

type AuthData struct {
	// Keys used to encrypt communication with the phone
	RequestCrypto *crypto.AESCTRHelper `json:"request_crypto,omitempty"`
	// Key used to sign requests to refresh the tachyon auth token from the server
	RefreshKey *crypto.JWK `json:"refresh_key,omitempty"`
	// Identity of the paired phone and browser
	Browser *gmproto.Device `json:"browser,omitempty"`
	Mobile  *gmproto.Device `json:"mobile,omitempty"`
	// Key used to authenticate with the server
	TachyonAuthToken []byte    `json:"tachyon_token,omitempty"`
	TachyonExpiry    time.Time `json:"tachyon_expiry,omitempty"`
	TachyonTTL       int64     `json:"tachyon_ttl,omitempty"`
	// Unknown encryption key, not used for anything
	WebEncryptionKey []byte `json:"web_encryption_key,omitempty"`

	SessionID uuid.UUID `json:"session_id,omitempty"`
	DestRegID uuid.UUID `json:"dest_reg_id,omitempty"`
	PairingID uuid.UUID `json:"pairing_id,omitempty"`

	Cookies map[string]string `json:"cookies,omitempty"`
	// GoogleAuthUser is the browser account index (/u/N) of the Google account the
	// cookies should authenticate as when the cookie jar holds several accounts.
	// Zero is the default account and sends no X-Goog-AuthUser header.
	GoogleAuthUser int `json:"google_authuser,omitempty"`

	// sessionLock is the single synchronization boundary for every durable
	// authentication field and, through Client methods, push keys. It must
	// never be copied; snapshots deliberately create a fresh AuthData.
	sessionLock sync.RWMutex `json:"-"`
}

func (*AuthData) String() string   { return "libgm.AuthData{redacted}" }
func (*AuthData) GoString() string { return "libgm.AuthData{redacted}" }

func (ad *AuthData) SetCookies(cookies map[string]string) {
	ad.sessionLock.Lock()
	ad.Cookies = cloneStringMap(cookies)
	ad.sessionLock.Unlock()
}

// SetGoogleAuthUser selects which signed-in Google account (the N in /u/N) the
// cookies authenticate as.
func (ad *AuthData) SetGoogleAuthUser(index int) {
	ad.sessionLock.Lock()
	ad.GoogleAuthUser = index
	ad.sessionLock.Unlock()
}

// CookieSnapshot returns an independent copy taken under the same lock used
// by HTTP cookie rotation.
func (ad *AuthData) CookieSnapshot() map[string]string {
	if ad == nil {
		return nil
	}
	ad.sessionLock.RLock()
	defer ad.sessionLock.RUnlock()
	return cloneStringMap(ad.Cookies)
}

func (ad *AuthData) SetDevices(browser, mobile *gmproto.Device) {
	ad.sessionLock.Lock()
	ad.Browser = cloneDevice(browser)
	ad.Mobile = cloneDevice(mobile)
	ad.sessionLock.Unlock()
}

func (ad *AuthData) SetTachyonAuth(token []byte, expiry time.Time, ttl int64) {
	ad.sessionLock.Lock()
	zeroBytes(ad.TachyonAuthToken)
	ad.TachyonAuthToken = append([]byte(nil), token...)
	ad.TachyonExpiry, ad.TachyonTTL = expiry, ttl
	ad.sessionLock.Unlock()
}

func (ad *AuthData) SetRequestCryptoKeys(aesKey, hmacKey []byte) {
	ad.sessionLock.Lock()
	if ad.RequestCrypto == nil {
		ad.RequestCrypto = &crypto.AESCTRHelper{}
	}
	zeroBytes(ad.RequestCrypto.AESKey)
	zeroBytes(ad.RequestCrypto.HMACKey)
	ad.RequestCrypto.AESKey = append([]byte(nil), aesKey...)
	ad.RequestCrypto.HMACKey = append([]byte(nil), hmacKey...)
	ad.sessionLock.Unlock()
}

func (ad *AuthData) SetRefreshKey(key *crypto.JWK) {
	ad.sessionLock.Lock()
	if ad.RefreshKey != nil {
		zeroBytes(ad.RefreshKey.D)
		zeroBytes(ad.RefreshKey.X)
		zeroBytes(ad.RefreshKey.Y)
	}
	ad.RefreshKey = cloneJWK(key)
	ad.sessionLock.Unlock()
}

func (ad *AuthData) SetSessionIdentifiers(sessionID, destinationRegistrationID, pairingID uuid.UUID) {
	ad.sessionLock.Lock()
	ad.SessionID, ad.DestRegID, ad.PairingID = sessionID, destinationRegistrationID, pairingID
	ad.sessionLock.Unlock()
}

func (ad *AuthData) SetSessionID(sessionID uuid.UUID) {
	ad.sessionLock.Lock()
	ad.SessionID = sessionID
	ad.sessionLock.Unlock()
}

func (ad *AuthData) SetDestinationRegistrationID(id uuid.UUID) {
	ad.sessionLock.Lock()
	ad.DestRegID = id
	ad.sessionLock.Unlock()
}

func (ad *AuthData) SetPairingID(id uuid.UUID) {
	ad.sessionLock.Lock()
	ad.PairingID = id
	ad.sessionLock.Unlock()
}

func (ad *AuthData) SetWebEncryptionKey(key []byte) {
	ad.sessionLock.Lock()
	zeroBytes(ad.WebEncryptionKey)
	ad.WebEncryptionKey = append([]byte(nil), key...)
	ad.sessionLock.Unlock()
}

// Snapshot returns an independent, serialization-safe copy of all durable
// authentication material. The mutex itself is deliberately not copied.
func (ad *AuthData) Snapshot() *AuthData {
	if ad == nil {
		return nil
	}
	ad.sessionLock.RLock()
	defer ad.sessionLock.RUnlock()
	return ad.snapshotLocked()
}

func (ad *AuthData) snapshotLocked() *AuthData {
	snapshot := &AuthData{
		TachyonAuthToken: append([]byte(nil), ad.TachyonAuthToken...),
		TachyonExpiry:    ad.TachyonExpiry, TachyonTTL: ad.TachyonTTL,
		WebEncryptionKey: append([]byte(nil), ad.WebEncryptionKey...),
		SessionID:        ad.SessionID, DestRegID: ad.DestRegID, PairingID: ad.PairingID,
		Cookies: cloneStringMap(ad.Cookies), GoogleAuthUser: ad.GoogleAuthUser,
	}
	if ad.RequestCrypto != nil {
		snapshot.RequestCrypto = &crypto.AESCTRHelper{
			AESKey:  append([]byte(nil), ad.RequestCrypto.AESKey...),
			HMACKey: append([]byte(nil), ad.RequestCrypto.HMACKey...),
		}
	}
	if ad.RefreshKey != nil {
		snapshot.RefreshKey = cloneJWK(ad.RefreshKey)
	}
	if ad.Browser != nil {
		snapshot.Browser = proto.Clone(ad.Browser).(*gmproto.Device)
	}
	if ad.Mobile != nil {
		snapshot.Mobile = proto.Clone(ad.Mobile).(*gmproto.Device)
	}
	return snapshot
}

// ClearSecrets drops and overwrites mutable secret buffers where practical.
func (ad *AuthData) ClearSecrets() {
	if ad == nil {
		return
	}
	ad.sessionLock.Lock()
	defer ad.sessionLock.Unlock()
	ad.clearSecretsLocked()
}

func (ad *AuthData) clearSecretsLocked() {
	zeroBytes(ad.TachyonAuthToken)
	zeroBytes(ad.WebEncryptionKey)
	if ad.RequestCrypto != nil {
		zeroBytes(ad.RequestCrypto.AESKey)
		zeroBytes(ad.RequestCrypto.HMACKey)
	}
	if ad.RefreshKey != nil {
		zeroBytes(ad.RefreshKey.D)
		zeroBytes(ad.RefreshKey.X)
		zeroBytes(ad.RefreshKey.Y)
	}
	clear(ad.Cookies)
	ad.Cookies, ad.GoogleAuthUser = nil, 0
	ad.RequestCrypto, ad.RefreshKey, ad.Browser, ad.Mobile = nil, nil, nil, nil
	ad.TachyonAuthToken, ad.WebEncryptionKey = nil, nil
	ad.TachyonExpiry, ad.TachyonTTL = time.Time{}, 0
	ad.SessionID, ad.DestRegID, ad.PairingID = uuid.Nil, uuid.Nil, uuid.Nil
}

func cloneDevice(device *gmproto.Device) *gmproto.Device {
	if device == nil {
		return nil
	}
	return proto.Clone(device).(*gmproto.Device)
}

func cloneJWK(key *crypto.JWK) *crypto.JWK {
	if key == nil {
		return nil
	}
	return &crypto.JWK{
		KeyType: key.KeyType, Curve: key.Curve,
		D: append(crypto.RawURLBytes(nil), key.D...),
		X: append(crypto.RawURLBytes(nil), key.X...),
		Y: append(crypto.RawURLBytes(nil), key.Y...),
	}
}

func cloneStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (ad *AuthData) AddCookiesToRequest(req *http.Request) {
	ad.sessionLock.RLock()
	defer ad.sessionLock.RUnlock()
	if ad.Cookies == nil {
		return
	}
	for name, value := range ad.Cookies {
		req.AddCookie(&http.Cookie{Name: name, Value: value})
	}
	sapisid, ok := ad.Cookies["SAPISID"]
	if ok {
		req.Header.Set("Authorization", SAPISIDHash(util.MessagesBaseURL, sapisid))
	}
	if ad.GoogleAuthUser > 0 {
		// Without this, Google authenticates the cookies as the browser's default
		// account and rejects requests for any other signed-in account with 401.
		req.Header.Set("X-Goog-AuthUser", strconv.Itoa(ad.GoogleAuthUser))
	}
}

func (ad *AuthData) UpdateCookiesFromResponse(resp *http.Response) {
	ad.sessionLock.Lock()
	defer ad.sessionLock.Unlock()
	if ad.Cookies == nil {
		return
	}
	for _, cookie := range resp.Cookies() {
		ad.Cookies[cookie.Name] = cookie.Value
	}
}

func (ad *AuthData) HasCookies() bool {
	if ad == nil {
		return false
	}
	ad.sessionLock.RLock()
	defer ad.sessionLock.RUnlock()
	if ad.DestRegID == uuid.Nil {
		return true
	}
	return ad.Cookies != nil
}

func (ad *AuthData) IsGoogleAccount() bool {
	if ad == nil {
		return false
	}
	ad.sessionLock.RLock()
	defer ad.sessionLock.RUnlock()
	return ad.DestRegID != uuid.Nil
}

func (ad *AuthData) AuthNetwork() string {
	if ad == nil {
		return ""
	}
	ad.sessionLock.RLock()
	defer ad.sessionLock.RUnlock()
	if ad.DestRegID != uuid.Nil {
		return util.GoogleNetwork
	}
	return ""
}

const RefreshTachyonBuffer = 1 * time.Hour

type Proxy func(*http.Request) (*url.URL, error)
type EventHandler func(evt any)

type updateDedupItem struct {
	id   string
	hash [32]byte
}

type Client struct {
	Logger         zerolog.Logger
	evHandler      EventHandler
	sessionHandler *SessionHandler

	longPollingConn io.Closer
	listenID        int
	skipCount       int
	disconnecting   bool
	pollingMu       sync.Mutex
	protocolMu      sync.Mutex

	pingInterval             time.Duration
	alertTimeoutCount        int
	pingShortCircuit         chan struct{}
	dataReceiveCheckInterval time.Duration
	nextDataReceiveCheck     time.Time
	nextDataReceiveCheckLock sync.Mutex

	recentUpdates    [8]updateDedupItem
	recentUpdatesPtr int

	conversationsFetchedOnce bool

	GaiaHackyDeviceSwitcher int

	PairCallback atomic.Pointer[func(data *gmproto.PairedData)]

	AuthData *AuthData
	PushKeys *PushKeys
	Config   *gmproto.Config

	httpTransport *http.Transport
	http          *http.Client
	lphttp        *http.Client

	// Lock order: lifecycleMu, pollingMu, lifecycleHooksMu. No lifecycle lock
	// is held across network calls or user callbacks.
	lifecycleMu      sync.Mutex
	lifecycle        *clientLifecycle
	credentialReset  chan struct{}
	lifecycleDeps    lifecycleDependencies
	lifecycleHooksMu sync.RWMutex
	lifecycleHooks   LifecycleHooks
	retryPolicyMu    sync.RWMutex
	longPollRetry    LongPollRetryPolicy
	durableMu        sync.RWMutex
	durableEnvelope  DurableEnvelopeHandler
	ackCoordinator   ACKCoordinator
	ackObserver      ACKObserver
	durableFailure   DurableFailureObserver
	invalidIDLogMu   sync.Mutex
	invalidIDLogAt   time.Time
	invalidIDLogHits uint8
	auxiliaryMu      sync.Mutex
	auxiliary        *auxiliaryLifecycle
	mediaPolicyMu    sync.RWMutex
	mediaPolicy      MediaRequestPolicy
}

func NewAuthData() *AuthData {
	return &AuthData{
		RequestCrypto: crypto.NewAESCTRHelper(),
		RefreshKey:    crypto.GenerateECDSAKey(),
	}
}

func NewClient(authData *AuthData, pk *PushKeys, logger zerolog.Logger) *Client {
	sessionHandler := &SessionHandler{
		responseWaiters: make(map[string]responseWaiter),
	}
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
	}
	cli := &Client{
		AuthData:       authData,
		PushKeys:       clonePushKeys(pk),
		Logger:         logger,
		sessionHandler: sessionHandler,

		httpTransport: transport,
		http:          &http.Client{Transport: transport, Timeout: 2 * time.Minute},
		lphttp:        &http.Client{Transport: transport, Timeout: 30 * time.Minute},

		pingShortCircuit:         make(chan struct{}),
		pingInterval:             1 * time.Minute,
		alertTimeoutCount:        4,
		dataReceiveCheckInterval: DefaultBugleDefaultCheckInterval,
	}
	sessionHandler.client = cli
	cli.initLifecycle()
	return cli
}

func (c *Client) SnapshotSession() (*AuthData, *PushKeys) {
	if c == nil || c.AuthData == nil {
		return nil, nil
	}
	c.AuthData.sessionLock.RLock()
	defer c.AuthData.sessionLock.RUnlock()
	return c.AuthData.snapshotLocked(), clonePushKeys(c.PushKeys)
}

func (c *Client) ClearSessionSecrets() {
	if c == nil {
		return
	}
	resetDone := c.beginCredentialReset()
	defer c.finishCredentialReset(resetDone)
	_ = c.DisconnectContext(context.Background())
	if c.AuthData == nil {
		if c.PushKeys != nil {
			zeroBytes(c.PushKeys.P256DH)
			zeroBytes(c.PushKeys.Auth)
		}
		c.PushKeys = nil
		return
	}
	c.AuthData.sessionLock.Lock()
	defer c.AuthData.sessionLock.Unlock()
	c.AuthData.clearSecretsLocked()
	if c.PushKeys != nil {
		zeroBytes(c.PushKeys.P256DH)
		zeroBytes(c.PushKeys.Auth)
	}
	c.PushKeys = nil
}

func (c *Client) SetPushKeys(keys *PushKeys) {
	if c == nil || c.AuthData == nil {
		return
	}
	c.AuthData.sessionLock.Lock()
	if c.PushKeys != nil {
		zeroBytes(c.PushKeys.P256DH)
		zeroBytes(c.PushKeys.Auth)
	}
	c.PushKeys = clonePushKeys(keys)
	c.AuthData.sessionLock.Unlock()
}

func clonePushKeys(keys *PushKeys) *PushKeys {
	if keys == nil {
		return nil
	}
	return &PushKeys{URL: keys.URL, P256DH: append([]byte(nil), keys.P256DH...), Auth: append([]byte(nil), keys.Auth...)}
}

func (c *Client) CurrentSessionID() string {
	return c.sessionHandler.sessionID
}

func (c *Client) SetEventHandler(eventHandler EventHandler) {
	c.evHandler = eventHandler
}

func (c *Client) SetPingInterval(interval time.Duration) {
	if interval >= 1*time.Minute && interval < 4*time.Hour {
		c.pingInterval = interval
	}
}

func (c *Client) SetAlertTimeoutCount(count int) {
	if count > 0 {
		c.alertTimeoutCount = count
	}
}

// SetDataReceiveCheckInterval sets how often to send an extra GET_UPDATES call
// (and emit a NoDataReceived event) when no data has been received recently.
// Intervals shorter than 5 minutes are ignored to avoid draining the phone's battery.
func (c *Client) SetDataReceiveCheckInterval(interval time.Duration) {
	if interval >= 5*time.Minute {
		c.dataReceiveCheckInterval = interval
	}
}

func (c *Client) SetProxy(proxy string) error {
	proxyParsed, err := url.Parse(proxy)
	if err != nil {
		logSafeError(c.Logger.Fatal(), err).Msg("Failed to set proxy")
	}
	c.httpTransport.Proxy = http.ProxyURL(proxyParsed)
	c.Logger.Debug().Bool("proxy_configured", true).Msg("SetProxy")
	return nil
}

func (c *Client) Connect() error {
	return c.ConnectContext(context.Background())
}

func (c *Client) ConnectBackground() error {
	auth := c.AuthData.Snapshot()
	defer auth.ClearSecrets()
	if auth.TachyonAuthToken == nil {
		return fmt.Errorf("no auth token")
	} else if auth.Browser == nil {
		return fmt.Errorf("not logged in")
	}
	cleanExit := c.doLongPoll(true, true, nil)
	c.sessionHandler.sendAckRequest()
	if !cleanExit {
		return fmt.Errorf("polling exited uncleanly")
	}
	return nil
}

func (c *Client) postConnectContext(ctx context.Context) {
	if !waitForContext(ctx, 2*time.Second) {
		return
	}
	if c.getSkipCount() > 0 {
		c.Logger.Warn().Int("skip_count", c.getSkipCount()).Msg("Skip count is non-zero in postConnect, waiting longer")
		for i := 0; i < 3 && c.getSkipCount() > 0; i++ {
			if !waitForContext(ctx, time.Second) {
				return
			}
		}
		if c.getSkipCount() > 0 {
			c.Logger.Warn().Int("skip_count", c.getSkipCount()).Msg("Skip count is still non-zero")
		}
		c.triggerEvent(&events.HackySetActiveMayFail{})
	}
	ctx = c.Logger.WithContext(ctx)
	c.Logger.Debug().Msg("Sending acks before get updates request")
	c.sessionHandler.sendAckRequestContext(ctx)
	if !waitForContext(ctx, time.Second) {
		return
	}
	c.Logger.Debug().Msg("Sending get updates request")
	err := c.SetActiveSession(ctx)
	if err != nil {
		logSafeError(c.Logger.Error(), err).Msg("Failed to set active session")
		c.triggerEvent(&events.PingFailed{
			Error: fmt.Errorf("failed to set active session: %w", err),
		})
		return
	}
	c.Logger.Debug().Msg("Sent set active session/get updates request")

	bugleRes, err := c.IsBugleDefault(ctx)
	if err != nil {
		logSafeError(c.Logger.Error(), err).Msg("Failed to check bugle default")
		return
	}
	c.Logger.Debug().Bool("bugle_default", bugleRes.Success).Msg("Got is bugle default response on connect")
}

func (c *Client) Disconnect() {
	_ = c.DisconnectContext(context.Background())
}

func (c *Client) IsConnected() bool {
	c.pollingMu.Lock()
	defer c.pollingMu.Unlock()
	return c.longPollingConn != nil
}

func waitForContext(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (c *Client) getSkipCount() int {
	c.protocolMu.Lock()
	defer c.protocolMu.Unlock()
	return c.skipCount
}

func (c *Client) setSkipCount(value int) {
	c.protocolMu.Lock()
	c.skipCount = value
	c.protocolMu.Unlock()
}

func (c *Client) decrementSkipCount() bool {
	c.protocolMu.Lock()
	defer c.protocolMu.Unlock()
	if c.skipCount <= 0 {
		return false
	}
	c.skipCount--
	return true
}

func (c *Client) IsLoggedIn() bool {
	if c == nil || c.AuthData == nil {
		return false
	}
	auth := c.AuthData.Snapshot()
	defer auth.ClearSecrets()
	return auth.Browser != nil && auth.HasCookies()
}

func (c *Client) Reconnect() error {
	c.closeLongPolling()
	err := c.Connect()
	if err != nil {
		logSafeError(c.Logger.Error(), err).Msg("Failed to reconnect")
		return err
	}
	c.Logger.Debug().Msg("Successfully reconnected to server")
	return nil
}

func (c *Client) triggerEvent(evt interface{}) {
	if c.evHandler != nil {
		c.evHandler(evt)
	}
}

func (c *Client) FetchConfig(ctx context.Context) error {
	config, err := c.fetchConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch config: %w", err)
	}
	if deviceID := config.GetDeviceInfo().GetDeviceID(); deviceID != "" && c.AuthData != nil {
		sessionID, parseErr := uuid.Parse(deviceID)
		err = parseErr
		if err != nil {
			event := logSafeError(c.Logger.Error(), err)
			logSafeProviderID(event, "device_id", deviceID)
			event.Msg("Failed to parse device ID")
		} else {
			c.AuthData.SetSessionID(sessionID)
		}
	}
	c.Config = config
	return nil
}

func (c *Client) fetchConfig(ctx context.Context) (*gmproto.Config, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, util.ConfigURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}
	util.BuildRelayHeaders(req, "", "*/*")
	req.Header.Set("sec-fetch-site", "same-origin")
	req.Header.Del("x-user-agent")
	req.Header.Del("origin")
	c.AuthData.AddCookiesToRequest(req)

	resp, err := c.http.Do(req)
	if resp != nil {
		c.AuthData.UpdateCookiesFromResponse(resp)
	}
	config, err := typedHTTPResponse[*gmproto.Config](resp, err)
	if err != nil {
		return nil, err
	}

	version, parseErr := config.ParsedClientVersion()
	if parseErr != nil {
		return nil, fmt.Errorf("failed to parse client version: %w", err)
	}

	currVersion := util.ConfigMessage
	if version.Year != currVersion.Year || version.Month != currVersion.Month || version.Day != currVersion.Day {
		toLog := c.diffVersionFormat(currVersion, version)
		c.Logger.Trace().Any("version", toLog).Msg("Messages for web version is not latest")
	} else {
		c.Logger.Debug().Any("version", currVersion).Msg("Using latest messages for web version")
	}

	return config, nil
}

func (c *Client) diffVersionFormat(curr *gmproto.ConfigVersion, latest *gmproto.ConfigVersion) string {
	return fmt.Sprintf("%d.%d.%d -> %d.%d.%d", curr.Year, curr.Month, curr.Day, latest.Year, latest.Month, latest.Day)
}

func (c *Client) updateTachyonAuthToken(data *gmproto.TokenData) {
	validForDuration := time.Duration(data.GetTTL()) * time.Microsecond
	if validForDuration == 0 {
		validForDuration = 24 * time.Hour
	}
	expiry := time.Now().UTC().Add(validForDuration)
	c.AuthData.SetTachyonAuth(data.GetTachyonAuthToken(), expiry, validForDuration.Microseconds())
	c.emitLifecycleActivity(lifecycleActivitySessionChange)
	c.Logger.Debug().
		Time("tachyon_expiry", expiry).
		Int64("valid_for", data.GetTTL()).
		Msg("Updated tachyon token")
}

type PushKeys struct {
	URL    string
	P256DH []byte
	Auth   []byte
}

func (c *Client) RegisterPush(ctx context.Context, keys *PushKeys) error {
	currentAuth, currentPush := c.SnapshotSession()
	if currentAuth != nil {
		currentAuth.ClearSecrets()
	}
	needsRefresh := currentPush == nil || currentPush.URL != keys.URL
	if currentPush != nil {
		zeroBytes(currentPush.P256DH)
		zeroBytes(currentPush.Auth)
	}
	if needsRefresh {
		err := c.refreshAuthToken(keys)
		if err != nil {
			return fmt.Errorf("failed to refresh auth token: %w", err)
		}
	}
	err := c.UpdateSettings(ctx, &gmproto.SettingsUpdateRequest{
		PushSettings: &gmproto.SettingsUpdateRequest_PushSettings{
			Enabled: true,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to update settings to enable push: %w", err)
	}
	c.SetPushKeys(keys)
	return nil
}

func (c *Client) refreshAuthToken(pushKeyOverride *PushKeys) error {
	return c.refreshAuthTokenContext(context.Background(), pushKeyOverride)
}

func (c *Client) refreshAuthTokenContext(ctx context.Context, pushKeyOverride *PushKeys) error {
	auth, currentPush := c.SnapshotSession()
	if auth == nil {
		return nil
	}
	defer auth.ClearSecrets()
	defer func() {
		if currentPush != nil {
			zeroBytes(currentPush.P256DH)
			zeroBytes(currentPush.Auth)
		}
	}()
	if auth.Browser == nil || (time.Until(auth.TachyonExpiry) > RefreshTachyonBuffer && pushKeyOverride == nil) {
		return nil
	}
	jwk := auth.RefreshKey
	if jwk == nil {
		return fmt.Errorf("missing refresh key")
	}
	requestID := uuid.NewString()
	timestamp := time.Now().UnixMilli() * 1000

	signBytes := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", requestID, timestamp)))
	sig, err := ecdsa.SignASN1(rand.Reader, jwk.GetPrivateKey(), signBytes[:])
	if err != nil {
		return err
	}

	var moreParams *gmproto.RegisterRefreshRequest_MoreParameters
	keys := currentPush
	if pushKeyOverride != nil {
		keys = clonePushKeys(pushKeyOverride)
		defer func() {
			zeroBytes(keys.P256DH)
			zeroBytes(keys.Auth)
		}()
	}
	if keys != nil {
		moreParams = &gmproto.RegisterRefreshRequest_MoreParameters{
			Three: 3,
		}
		moreParams.PushReg = &gmproto.RegisterRefreshRequest_PushRegistration{
			Type:   "messages_web",
			Url:    keys.URL,
			P256Dh: base64.RawURLEncoding.EncodeToString(keys.P256DH),
			Auth:   base64.RawURLEncoding.EncodeToString(keys.Auth),
		}
	}
	c.Logger.Debug().
		Time("tachyon_expiry", auth.TachyonExpiry).
		Bool("force_refresh", pushKeyOverride != nil).
		Bool("include_push_keys", moreParams.GetPushReg() != nil).
		Msg("Refreshing auth token")

	payload := &gmproto.RegisterRefreshRequest{
		MessageAuth: &gmproto.AuthMessage{
			RequestID:        requestID,
			TachyonAuthToken: auth.TachyonAuthToken,
			Network:          auth.AuthNetwork(),
			ConfigVersion:    util.ConfigMessage,
		},
		CurrBrowserDevice: auth.Browser,
		UnixTimestamp:     timestamp,
		Signature:         sig,
		Parameters: &gmproto.RegisterRefreshRequest_Parameters{
			EmptyArr:       &gmproto.EmptyArr{},
			MoreParameters: moreParams,
		},
		MessageType: 2, // hmm
	}

	resp, err := typedHTTPResponse[*gmproto.RegisterRefreshResponse](
		c.makeProtobufHTTPRequestContext(ctx, util.RegisterRefreshURL, payload, ContentTypePBLite, false),
	)
	if err != nil {
		return err
	}

	if resp.GetTokenData().GetTachyonAuthToken() == nil {
		return fmt.Errorf("no tachyon auth token in refresh response")
	}

	c.updateTachyonAuthToken(resp.GetTokenData())
	c.triggerEvent(&events.AuthTokenRefreshed{})
	return nil
}
