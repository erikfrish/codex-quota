package auth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestBuildChatGPTAuthorizeURLMatchesOpenCodeTokenSharingContract(t *testing.T) {
	got := buildChatGPTAuthorizeURL(
		"http://localhost:4321/auth/callback",
		"challenge",
		"state",
		"nonce",
		"",
		"urn:uuid:test-host",
	)
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Path != "/api/accounts/authorize" {
		t.Fatalf("path = %q", parsed.Path)
	}
	if query.Get("client_id") != chatGPTRegistrationClientID || query.Get("agent_name_hint") != chatGPTAgentName {
		t.Fatalf("registration parameters = %#v", query)
	}
	if query.Get("redirect_uri") != "http://localhost:4321/auth/callback" || query.Get("resource") != chatGPTResource {
		t.Fatalf("redirect/resource parameters = %#v", query)
	}
	if !strings.Contains(query.Get("scope"), chatGPTTokenSharingScope) || !strings.Contains(query.Get("scope"), "resource.invoke") {
		t.Fatalf("scope = %q", query.Get("scope"))
	}
	if query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") != "challenge" {
		t.Fatalf("PKCE parameters = %#v", query)
	}
}

func TestVerifyChatGPTIDTokenChecksSignatureAndClaims(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA",
			"kid": "test-key",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}),
		}}})
	}))
	defer server.Close()
	t.Setenv("CQ_CHATGPT_ISSUER", server.URL)
	t.Setenv("CQ_CHATGPT_JWKS_URL", server.URL+"/jwks")

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	payload, _ := json.Marshal(map[string]any{
		"iss":   server.URL,
		"aud":   "client-id",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"nonce": "nonce-value",
		"sub":   "subject",
		"email": "user@example.com",
	})
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	unsigned := encodedHeader + "." + encodedPayload
	sum := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	token := unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)

	claims, err := verifyChatGPTIDToken(token, "client-id", "nonce-value")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.Subject != "subject" || claims.Email != "user@example.com" {
		t.Fatalf("claims = %#v", claims)
	}
}
