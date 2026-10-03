package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deLiseLINO/codex-quota/internal/config"
)

const (
	chatGPTRegistrationClientID = "dynamic_agent_client"
	chatGPTAgentName            = "OpenCode"
	chatGPTIssuer               = "https://auth.openai.com"
	chatGPTTokenURL             = chatGPTIssuer + "/api/accounts/oauth/token"
	chatGPTResource             = "https://api.openai.com/v1"
	chatGPTTokenSharingScope    = "chatgpt.tokens.use.direct"
)

type OpenCodeChatGPTLoginStatus struct {
	AuthURL           string
	BrowserOpenFailed bool
}

type chatGPTTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
}

type chatGPTLoginSession struct {
	authURL           string
	browserOpenFailed bool
	listener          net.Listener
	server            *http.Server
	done              chan struct{}
	result            *config.Account
	err               error
	finishOnce        sync.Once
}

var (
	chatGPTLoginMu     sync.Mutex
	activeChatGPTLogin *chatGPTLoginSession
)

func LoginOpenCodeChatGPT(clientID, hostID string) (*config.Account, error) {
	if _, err := StartOpenCodeChatGPTLogin(clientID, hostID); err != nil {
		return nil, err
	}
	for {
		account, done, err := PollOpenCodeChatGPTLogin()
		if done {
			return account, err
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func StartOpenCodeChatGPTLogin(savedClientID, savedHostID string) (OpenCodeChatGPTLoginStatus, error) {
	chatGPTLoginMu.Lock()
	if activeChatGPTLogin != nil && activeChatGPTLogin.isDone() {
		activeChatGPTLogin = nil
	}
	if activeChatGPTLogin != nil {
		status := OpenCodeChatGPTLoginStatus{
			AuthURL:           activeChatGPTLogin.authURL,
			BrowserOpenFailed: activeChatGPTLogin.browserOpenFailed,
		}
		chatGPTLoginMu.Unlock()
		return status, nil
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		chatGPTLoginMu.Unlock()
		return OpenCodeChatGPTLoginStatus{}, err
	}
	state, err := randomHex(32)
	if err != nil {
		chatGPTLoginMu.Unlock()
		return OpenCodeChatGPTLoginStatus{}, err
	}
	nonce, err := randomHex(32)
	if err != nil {
		chatGPTLoginMu.Unlock()
		return OpenCodeChatGPTLoginStatus{}, err
	}
	hostID := strings.TrimSpace(savedHostID)
	if hostID == "" {
		hostID, err = randomHostID()
		if err != nil {
			chatGPTLoginMu.Unlock()
			return OpenCodeChatGPTLoginStatus{}, err
		}
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		chatGPTLoginMu.Unlock()
		return OpenCodeChatGPTLoginStatus{}, fmt.Errorf("failed to bind ChatGPT callback server: %w", err)
	}
	redirect := "http://localhost:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port) + "/auth/callback"
	session := &chatGPTLoginSession{
		authURL:  buildChatGPTAuthorizeURL(redirect, challenge, state, nonce, savedClientID, hostID),
		listener: listener,
		done:     make(chan struct{}),
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/callback" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		query := r.URL.Query()
		callbackErr := strings.TrimSpace(query.Get("error_description"))
		if callbackErr == "" {
			callbackErr = strings.TrimSpace(query.Get("error"))
		}
		if callbackErr != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, callbackErr)
			session.finish(nil, errors.New(callbackErr))
			return
		}
		if query.Get("state") != state {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "State mismatch")
			session.finish(nil, fmt.Errorf("ChatGPT OAuth state mismatch"))
			return
		}
		code := strings.TrimSpace(query.Get("code"))
		if code == "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "Missing code")
			session.finish(nil, fmt.Errorf("ChatGPT OAuth authorization code is missing"))
			return
		}
		callbackClientID := strings.TrimSpace(query.Get("client_id"))
		if callbackClientID == "" {
			callbackClientID = strings.TrimSpace(savedClientID)
		}
		if callbackClientID == "" {
			callbackClientID = chatGPTRegistrationClientID
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "Authentication successful. You can close this window.")
		go func() {
			tokens, exchangeErr := exchangeChatGPTCode(code, callbackClientID, redirect, verifier)
			if exchangeErr != nil {
				session.finish(nil, exchangeErr)
				return
			}
			account, accountErr := accountFromChatGPTTokenResponse(tokens, callbackClientID, nonce, hostID)
			session.finish(account, accountErr)
		}()
	})}
	session.server = server
	activeChatGPTLogin = session
	chatGPTLoginMu.Unlock()

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			session.finish(nil, err)
		}
	}()
	if err := openBrowser(session.authURL); err != nil {
		session.browserOpenFailed = true
		fmt.Fprintf(os.Stderr, "failed to open browser automatically: %v\n", err)
		fmt.Fprintf(os.Stderr, "open this URL manually to continue login:\n%s\n", session.authURL)
	}
	go func() {
		timer := time.NewTimer(5 * time.Minute)
		defer timer.Stop()
		select {
		case <-timer.C:
			session.finish(nil, fmt.Errorf("ChatGPT authentication timed out; open %s", session.authURL))
		case <-session.done:
		}
	}()
	return OpenCodeChatGPTLoginStatus{AuthURL: session.authURL, BrowserOpenFailed: session.browserOpenFailed}, nil
}

func PollOpenCodeChatGPTLogin() (*config.Account, bool, error) {
	chatGPTLoginMu.Lock()
	session := activeChatGPTLogin
	if session == nil {
		chatGPTLoginMu.Unlock()
		return nil, true, ErrLoginCancelled
	}
	if !session.isDone() {
		chatGPTLoginMu.Unlock()
		return nil, false, nil
	}
	activeChatGPTLogin = nil
	chatGPTLoginMu.Unlock()
	return session.result, true, session.err
}

func CancelOpenCodeChatGPTLogin() error {
	chatGPTLoginMu.Lock()
	session := activeChatGPTLogin
	activeChatGPTLogin = nil
	chatGPTLoginMu.Unlock()
	if session != nil {
		session.finish(nil, ErrLoginCancelled)
	}
	return nil
}

func (s *chatGPTLoginSession) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *chatGPTLoginSession) finish(account *config.Account, err error) {
	s.finishOnce.Do(func() {
		s.result = account
		s.err = err
		if s.server != nil {
			shutdownServer(s.server)
		}
		if s.listener != nil {
			_ = s.listener.Close()
		}
		close(s.done)
	})
}

func buildChatGPTAuthorizeURL(redirect, challenge, state, nonce, savedClientID, hostID string) string {
	params := url.Values{}
	clientID := strings.TrimSpace(savedClientID)
	if clientID == "" {
		clientID = chatGPTRegistrationClientID
		params.Set("agent_name_hint", chatGPTAgentName)
	}
	params.Set("client_id", clientID)
	params.Set("ext_agent_host_id", hostID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", redirect)
	params.Set("scope", "openid profile email offline_access resource.invoke "+chatGPTTokenSharingScope)
	params.Set("resource", chatGPTResource)
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge_method", "S256")
	params.Set("code_challenge", challenge)
	return chatGPTIssuerURL() + "/api/accounts/authorize?" + params.Encode()
}

func exchangeChatGPTCode(code, clientID, redirect, verifier string) (*chatGPTTokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("client_id", clientID)
	form.Set("code", code)
	form.Set("code_verifier", verifier)
	form.Set("redirect_uri", redirect)
	form.Set("resource", chatGPTResource)
	req, err := http.NewRequest(http.MethodPost, chatGPTTokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create ChatGPT token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute ChatGPT token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("ChatGPT token exchange failed with status %d: %s", resp.StatusCode, truncateResponse(body, 500))
	}
	var tokens chatGPTTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, fmt.Errorf("failed to decode ChatGPT token response: %w", err)
	}
	if strings.TrimSpace(tokens.AccessToken) == "" || strings.TrimSpace(tokens.RefreshToken) == "" || strings.TrimSpace(tokens.IDToken) == "" {
		return nil, fmt.Errorf("ChatGPT token response is missing required fields")
	}
	if !hasScope(tokens.Scope, chatGPTTokenSharingScope) {
		return nil, fmt.Errorf("ChatGPT token response is missing %q scope", chatGPTTokenSharingScope)
	}
	return &tokens, nil
}

func accountFromChatGPTTokenResponse(tokens *chatGPTTokenResponse, clientID, nonce, hostID string) (*config.Account, error) {
	claims, err := verifyChatGPTIDToken(tokens.IDToken, clientID, nonce)
	if err != nil {
		return nil, err
	}
	credential := &config.OpenCodeCredential{
		MethodID:     config.OpenCodeChatGPTTokenSharingMethod,
		AccessToken:  strings.TrimSpace(tokens.AccessToken),
		RefreshToken: strings.TrimSpace(tokens.RefreshToken),
		ClientID:     strings.TrimSpace(clientID),
		Metadata: map[string]any{
			"clientID": strings.TrimSpace(clientID),
			"hostID":   strings.TrimSpace(hostID),
			"scopes":   strings.Fields(tokens.Scope),
		},
	}
	if tokens.ExpiresIn > 0 {
		credential.ExpiresAt = time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second)
	}
	account := &config.Account{OpenCode: credential, Source: config.SourceManaged, Writable: true}
	accessClaims := config.ParseAccessToken(tokens.AccessToken)
	account.AccountID = config.CanonicalAccountID(accessClaims.AccountID, claims.AccountID)
	account.Email = firstNonEmpty(accessClaims.Email, claims.Email)
	account.Label = account.Email
	return account, nil
}

type chatGPTJWTClaims struct {
	Issuer    string
	Audience  []string
	ExpiresAt int64
	Nonce     string
	Subject   string
	Email     string
	AccountID string
}

func verifyChatGPTIDToken(token, clientID, nonce string) (chatGPTJWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token")
	}
	decode := func(part string, target any) error {
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil {
			return err
		}
		return json.Unmarshal(data, target)
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
	}
	var payload map[string]any
	if err := decode(parts[0], &header); err != nil || header.Algorithm != "RS256" || header.KeyID == "" {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token header")
	}
	if err := decode(parts[1], &payload); err != nil {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token payload")
	}
	key, err := fetchChatGPTJWK(header.KeyID)
	if err != nil {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token: %w", err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token signature")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], signature); err != nil {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token signature")
	}
	issuer, _ := payload["iss"].(string)
	if issuer != chatGPTIssuerURL() {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token issuer")
	}
	audience := jwtAudience(payload["aud"])
	if !containsString(audience, clientID) {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token audience")
	}
	exp, ok := jsonNumberInt64(payload["exp"])
	if !ok || time.Now().Unix() >= exp {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an expired ID token")
	}
	if got, _ := payload["nonce"].(string); got != nonce {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an invalid ID token nonce")
	}
	sub, _ := payload["sub"].(string)
	if strings.TrimSpace(sub) == "" {
		return chatGPTJWTClaims{}, fmt.Errorf("ChatGPT sign-in returned an ID token without a subject")
	}
	return chatGPTJWTClaims{Issuer: issuer, Audience: audience, ExpiresAt: exp, Nonce: nonce, Subject: sub, Email: stringClaim(payload, "email"), AccountID: nestedAccountID(payload)}, nil
}

func fetchChatGPTJWK(keyID string) (*rsa.PublicKey, error) {
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Get(chatGPTJWKSURL())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}
	var body struct {
		Keys []struct {
			KeyType  string `json:"kty"`
			KeyID    string `json:"kid"`
			Modulus  string `json:"n"`
			Exponent string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	for _, jwk := range body.Keys {
		if jwk.KeyType != "RSA" || jwk.KeyID != keyID {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
		if err != nil || len(eBytes) == 0 {
			return nil, fmt.Errorf("invalid JWK exponent")
		}
		exponent := 0
		for _, value := range eBytes {
			exponent = exponent<<8 | int(value)
		}
		if exponent < 2 {
			return nil, fmt.Errorf("invalid JWK exponent")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: exponent}, nil
	}
	return nil, fmt.Errorf("JWK %q not found", keyID)
}

func chatGPTTokenEndpoint() string {
	if value := strings.TrimSpace(os.Getenv("CQ_CHATGPT_TOKEN_URL")); value != "" {
		return value
	}
	return chatGPTIssuerURL() + "/api/accounts/oauth/token"
}

func chatGPTIssuerURL() string {
	if value := strings.TrimSpace(os.Getenv("CQ_CHATGPT_ISSUER")); value != "" {
		return strings.TrimRight(value, "/")
	}
	return chatGPTIssuer
}

func chatGPTJWKSURL() string {
	if value := strings.TrimSpace(os.Getenv("CQ_CHATGPT_JWKS_URL")); value != "" {
		return value
	}
	return chatGPTIssuerURL() + "/.well-known/jwks.json"
}

func hasScope(scope, required string) bool { return containsString(strings.Fields(scope), required) }
func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
func stringClaim(values map[string]any, key string) string {
	value, _ := values[key].(string)
	return strings.TrimSpace(value)
}
func nestedAccountID(values map[string]any) string {
	if value, ok := values["https://api.openai.com/auth"].(map[string]any); ok {
		return strings.TrimSpace(stringClaim(value, "chatgpt_account_id"))
	}
	return firstNonEmpty(stringClaim(values, "chatgpt_account_id"), stringClaim(values, "account_id"))
}
func jwtAudience(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}
func jsonNumberInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), typed == float64(int64(typed))
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	}
	return 0, false
}

func randomHostID() (string, error) {
	value, err := randomHex(16)
	if err != nil {
		return "", err
	}
	return "urn:uuid:" + value[0:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:32], nil
}
func truncateResponse(body []byte, limit int) string {
	text := strings.TrimSpace(string(body))
	if len(text) > limit {
		return text[:limit]
	}
	return text
}
