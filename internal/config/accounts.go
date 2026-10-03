package config

import (
	"fmt"
	"strings"
	"time"
)

type Source string

const (
	SourceManaged  Source = "managed"
	SourceOpenCode Source = "opencode"
	SourceCodex    Source = "codex"
	SourcePi       Source = "pi"
	SourceOMP      Source = "omp"

	OpenCodeChatGPTBrowserMethod      = "chatgpt-browser"
	OpenCodeChatGPTHeadlessMethod     = "chatgpt-headless"
	OpenCodeChatGPTTokenSharingMethod = "chatgpt-token-sharing"
)

type OpenCodeCredential struct {
	MethodID     string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	ClientID     string
	Metadata     map[string]any
}

type Account struct {
	Key          string
	Label        string
	Email        string
	AccountID    string
	AccessToken  string
	RefreshToken string
	IDToken      string
	ExpiresAt    time.Time
	ClientID     string
	OpenCode     *OpenCodeCredential
	Source       Source
	FilePath     string
	Writable     bool
}

func CloneOpenCodeCredential(credential *OpenCodeCredential) *OpenCodeCredential {
	if credential == nil {
		return nil
	}
	cloned := *credential
	if credential.Metadata != nil {
		if metadata, err := cloneJSONMap(credential.Metadata); err == nil {
			cloned.Metadata = metadata
		}
	}
	return &cloned
}

func cloneOpenCodeCredential(credential *OpenCodeCredential) *OpenCodeCredential {
	return CloneOpenCodeCredential(credential)
}

type AccessTokenClaims struct {
	ClientID  string
	AccountID string
	ExpiresAt time.Time
	Email     string
}

func mergeOpenCodeCredentials(primary, secondary *OpenCodeCredential) *OpenCodeCredential {
	if primary == nil {
		return cloneOpenCodeCredential(secondary)
	}
	if secondary == nil {
		return cloneOpenCodeCredential(primary)
	}
	best := primary
	if !secondary.ExpiresAt.IsZero() && (primary.ExpiresAt.IsZero() || secondary.ExpiresAt.After(primary.ExpiresAt)) {
		best = secondary
	}
	merged := cloneOpenCodeCredential(best)
	if strings.TrimSpace(merged.MethodID) == "" {
		merged.MethodID = strings.TrimSpace(primary.MethodID)
		if merged.MethodID == "" {
			merged.MethodID = strings.TrimSpace(secondary.MethodID)
		}
	}
	if strings.TrimSpace(merged.RefreshToken) == "" {
		merged.RefreshToken = strings.TrimSpace(primary.RefreshToken)
		if merged.RefreshToken == "" {
			merged.RefreshToken = strings.TrimSpace(secondary.RefreshToken)
		}
	}
	if strings.TrimSpace(merged.ClientID) == "" {
		merged.ClientID = strings.TrimSpace(primary.ClientID)
		if merged.ClientID == "" {
			merged.ClientID = strings.TrimSpace(secondary.ClientID)
		}
	}
	if merged.Metadata == nil {
		merged.Metadata = cloneOpenCodeCredential(primary).Metadata
		if merged.Metadata == nil {
			merged.Metadata = cloneOpenCodeCredential(secondary).Metadata
		}
	}
	return merged
}

type AccountsLoadResult struct {
	Accounts                []*Account
	SourcesByAccountID      map[string][]string
	ActiveSourcesByIdentity map[string][]string
}

func (a *Account) SourceLabel() string {
	switch a.Source {
	case SourceManaged:
		return "app"
	case SourceOpenCode:
		return "opencode"
	case SourceCodex:
		return "codex"
	case SourcePi:
		return "pi"
	case SourceOMP:
		return "omp"
	default:
		return "unknown"
	}
}

func LoadAllAccounts() ([]*Account, error) {
	result, err := LoadAllAccountsWithSources()
	if err != nil {
		return nil, err
	}
	return result.Accounts, nil
}

func SaveAccount(account *Account) error {
	if account == nil || !account.Writable {
		return nil
	}

	switch account.Source {
	case SourceManaged:
		return saveManagedAccount(account)
	case SourceOpenCode:
		if account.FilePath == "" {
			return nil
		}
		return saveOpenCodeAccount(account)
	case SourceCodex:
		if account.FilePath == "" {
			return nil
		}
		return saveCodexAccount(account)
	case SourcePi:
		if account.FilePath == "" {
			return nil
		}
		return savePiAccount(account)
	case SourceOMP:
		if account.FilePath == "" {
			return nil
		}
		return saveOMPAccount(account)
	default:
		return nil
	}
}

func ApplyAccountToTarget(account *Account, target Source) (string, error) {
	if account == nil {
		return "", fmt.Errorf("account is nil")
	}
	accountToApply := account
	if fresh, _, err := ResolveFreshAccount(account); err != nil {
		return "", err
	} else if fresh != nil {
		accountToApply = fresh
	}

	switch target {
	case SourceOpenCode:
		return ApplyAccountToOpenCode(accountToApply)
	case SourceCodex:
		return ApplyAccountToCodex(accountToApply)
	case SourcePi:
		return ApplyAccountToPi(accountToApply)
	case SourceOMP:
		return ApplyAccountToOMP(accountToApply)
	default:
		return "", fmt.Errorf("unsupported apply target: %s", target)
	}
}

func ApplyAccountToTargets(account *Account, targets []Source) (map[Source]string, map[Source]error) {
	paths := make(map[Source]string)
	errorsBySource := make(map[Source]error)

	if account == nil {
		errorsBySource[SourceCodex] = fmt.Errorf("account is nil")
		return paths, errorsBySource
	}

	seen := make(map[Source]bool, len(targets))
	for _, target := range targets {
		if target != SourceCodex && target != SourceOpenCode && target != SourcePi && target != SourceOMP {
			continue
		}
		if seen[target] {
			continue
		}
		seen[target] = true

		path, err := ApplyAccountToTarget(account, target)
		if err != nil {
			errorsBySource[target] = err
			continue
		}
		paths[target] = path
	}

	return paths, errorsBySource
}

func DeleteAccountFromSource(account *Account, source Source) error {
	if account == nil {
		return fmt.Errorf("account is nil")
	}

	switch source {
	case SourceManaged:
		return DeleteManagedAccountByIdentity(account)
	case SourceOpenCode:
		return DeleteOpenCodeAuthAccount(account)
	case SourceCodex:
		return DeleteCodexAuthAccount()
	case SourcePi:
		return DeletePiAuthAccount(account)
	case SourceOMP:
		return DeleteOMPAuthAccount(account)
	default:
		return fmt.Errorf("unsupported source: %s", source)
	}
}
