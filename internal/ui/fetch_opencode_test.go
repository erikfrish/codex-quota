package ui

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deLiseLINO/codex-quota/internal/config"
	_ "modernc.org/sqlite"
)

func TestFinalizeOpenCodeLoginAllowsDifferentOAuthIdentity(t *testing.T) {
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

	target := &config.Account{
		Key:          "managed:codex-account",
		AccountID:    "codex-account",
		Email:        "codex@example.com",
		AccessToken:  "codex-access",
		RefreshToken: "codex-refresh",
		Source:       config.SourceManaged,
		Writable:     true,
	}
	loginResult := &config.Account{
		AccountID: "different-token-identity",
		Email:     "different@example.com",
		OpenCode: &config.OpenCodeCredential{
			MethodID:     config.OpenCodeChatGPTTokenSharingMethod,
			AccessToken:  "sharing-access",
			RefreshToken: "sharing-refresh",
			ClientID:     "dynamic-client",
			ExpiresAt:    time.Now().Add(time.Hour),
			Metadata:     map[string]any{"scopes": []any{"chatgpt.tokens.use.direct"}},
		},
	}

	msg := FinalizeOpenCodeLoginCmd(target, loginResult)()
	if errMsg, ok := msg.(ErrMsg); ok {
		t.Fatalf("cross-flow identity mismatch rejected: %v", errMsg.Err)
	}
	if _, ok := msg.(AccountsMsg); !ok {
		t.Fatalf("finalization message = %T, want AccountsMsg", msg)
	}
}
