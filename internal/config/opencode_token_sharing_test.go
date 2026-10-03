package config

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"
)

func TestBuildOpenCode2OAuthValueUsesTokenSharingCredential(t *testing.T) {
	account := &Account{
		AccountID:   "acct-token-sharing",
		AccessToken: "codex-access",
		OpenCode: &OpenCodeCredential{
			MethodID:     OpenCodeChatGPTTokenSharingMethod,
			AccessToken:  "sharing-access",
			RefreshToken: "sharing-refresh",
			ExpiresAt:    time.UnixMilli(1234),
			ClientID:     "client-sharing",
			Metadata: map[string]any{
				"scopes": []any{"openid", OpenCodeChatGPTTokenSharingMethod},
			},
		},
	}

	value, err := buildOpenCode2OAuthValue(account, map[string]any{"custom": "preserve"})
	if err != nil {
		t.Fatalf("build credential: %v", err)
	}
	if got := value["methodID"]; got != OpenCodeChatGPTTokenSharingMethod {
		t.Fatalf("methodID = %v, want %q", got, OpenCodeChatGPTTokenSharingMethod)
	}
	if got := value["access"]; got != "sharing-access" {
		t.Fatalf("access = %v, want token-sharing access", got)
	}
	metadata, ok := value["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("metadata type = %T", value["metadata"])
	}
	if metadata["clientID"] != "client-sharing" || metadata["accountID"] != "acct-token-sharing" {
		t.Fatalf("metadata identity = %#v", metadata)
	}
	if value["custom"] != "preserve" {
		t.Fatalf("existing credential metadata was not preserved")
	}
}

func TestOpenCode2AccountFromTokenSharingRowPreservesCredential(t *testing.T) {
	value := map[string]any{
		"type":     "oauth",
		"methodID": OpenCodeChatGPTTokenSharingMethod,
		"access":   "sharing-access",
		"refresh":  "sharing-refresh",
		"expires":  float64(1234),
		"metadata": map[string]any{"accountID": "acct-token-sharing", "clientID": "client-sharing", "scopes": []any{"openid"}},
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	account, active := openCode2AccountFromRow(openCode2CredentialRow{ID: "cred", Label: "OAuth", Value: string(encoded), Active: sql.NullInt64{Int64: 1, Valid: true}}, "native.db")
	if !active {
		t.Fatal("expected active native credential")
	}
	if account == nil || account.OpenCode == nil {
		t.Fatalf("account = %#v, want token-sharing credential", account)
	}
	if account.AccessToken != "" {
		t.Fatalf("main CQ access token = %q, want empty for token-sharing-only row", account.AccessToken)
	}
	if account.OpenCode.MethodID != OpenCodeChatGPTTokenSharingMethod || account.OpenCode.ClientID != "client-sharing" {
		t.Fatalf("credential = %#v", account.OpenCode)
	}
	if account.AccountID != "acct-token-sharing" {
		t.Fatalf("account ID = %q", account.AccountID)
	}
}
func TestLoadLatestOpenCode2TokenSharingCredential(t *testing.T) {
	dbPath := t.TempDir() + "/opencode.db"
	db := createOpenCode2TestDB(t, dbPath)
	t.Setenv("OPENCODE_DB", dbPath)

	value := map[string]any{
		"type":     "oauth",
		"methodID": OpenCodeChatGPTTokenSharingMethod,
		"access":   "native-access",
		"refresh":  "native-refresh",
		"expires":  float64(1234),
		"metadata": map[string]any{"clientID": "native-client", "scopes": []any{"chatgpt.tokens.use.direct"}},
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO credential (id, integration_id, label, value, active, time_created, time_updated) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"native", openCode2Integration, "OAuth", string(encoded), 1, 10, 20); err != nil {
		t.Fatal(err)
	}

	credential, err := LoadLatestOpenCode2TokenSharingCredential()
	if err != nil {
		t.Fatalf("load latest token-sharing credential: %v", err)
	}
	if credential.MethodID != OpenCodeChatGPTTokenSharingMethod ||
		credential.AccessToken != "native-access" ||
		credential.RefreshToken != "native-refresh" ||
		credential.ClientID != "native-client" ||
		!credential.ExpiresAt.Equal(time.UnixMilli(1234)) {
		t.Fatalf("credential = %#v", credential)
	}
}

func TestManagedAccountPersistsOpenCodeCredential(t *testing.T) {
	t.Setenv("CQ_CONFIG_HOME", t.TempDir())
	account := &Account{
		AccountID:   "acct-token-sharing",
		AccessToken: "codex-access",
		OpenCode: &OpenCodeCredential{
			MethodID:     OpenCodeChatGPTTokenSharingMethod,
			AccessToken:  "sharing-access",
			RefreshToken: "sharing-refresh",
			ExpiresAt:    time.UnixMilli(1234),
			ClientID:     "client-sharing",
			Metadata:     map[string]any{"scopes": []any{"chatgpt.tokens.use.direct"}},
		},
	}
	if err := UpsertManagedAccount(account); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	loaded, err := LoadManagedAccounts()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded) != 1 || loaded[0].OpenCode == nil {
		t.Fatalf("loaded accounts = %#v", loaded)
	}
	credential := loaded[0].OpenCode
	if credential.MethodID != OpenCodeChatGPTTokenSharingMethod || credential.AccessToken != "sharing-access" || credential.ClientID != "client-sharing" {
		t.Fatalf("loaded credential = %#v", credential)
	}
}
