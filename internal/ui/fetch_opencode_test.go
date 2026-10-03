package ui

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/deLiseLINO/codex-quota/internal/config"
	_ "modernc.org/sqlite"
)

func TestFinalizeOpenCodeNativeLoginImportsCredentialWithoutIdentityMatch(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("CQ_CONFIG_HOME", filepath.Join(root, "cq"))
	t.Setenv("OPENCODE_AUTH_PATH", "")
	t.Setenv("OPENCODE_DATA_DIR", "")
	dbPath := filepath.Join(root, "opencode", "opencode.db")
	t.Setenv("OPENCODE_DB", dbPath)

	if err := os.MkdirAll(filepath.Dir(dbPath), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE credential (
		id TEXT PRIMARY KEY,
		integration_id TEXT,
		label TEXT NOT NULL,
		value TEXT NOT NULL,
		connector_id TEXT,
		method_id TEXT,
		active INTEGER,
		time_created INTEGER NOT NULL,
		time_updated INTEGER NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	value, err := json.Marshal(map[string]any{
		"type":     "oauth",
		"methodID": config.OpenCodeChatGPTTokenSharingMethod,
		"access":   "sharing-access",
		"refresh":  "sharing-refresh",
		"expires":  float64(1234),
		"metadata": map[string]any{"clientID": "dynamic-client", "scopes": []any{"chatgpt.tokens.use.direct"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO credential (id, integration_id, label, value, active, time_created, time_updated)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, "native", "openai", "OAuth", string(value), 1, 10, 20); err != nil {
		t.Fatal(err)
	}

	target := &config.Account{
		Key:          "managed:codex-account",
		AccountID:    "codex-account",
		Email:        "codex@example.com",
		AccessToken:  "codex-access",
		RefreshToken: "codex-refresh",
		Source:       config.SourceManaged,
		Writable:     true,
	}

	msg := FinalizeOpenCodeNativeLoginCmd(target)()
	if errMsg, ok := msg.(ErrMsg); ok {
		t.Fatalf("native credential import failed: %v", errMsg.Err)
	}
	if _, ok := msg.(AccountsMsg); !ok {
		t.Fatalf("finalization message = %T, want AccountsMsg", msg)
	}

	var stored string
	if err := db.QueryRow(`SELECT value FROM credential WHERE id = ?`, "native").Scan(&stored); err != nil {
		t.Fatal(err)
	}
	var storedValue map[string]any
	if err := json.Unmarshal([]byte(stored), &storedValue); err != nil {
		t.Fatal(err)
	}
	metadata, ok := storedValue["metadata"].(map[string]any)
	if !ok || metadata["accountID"] != "codex-account" {
		t.Fatalf("native credential metadata = %#v, want local account association", storedValue["metadata"])
	}
}
