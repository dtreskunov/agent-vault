// Package mcpauth implements vault-isolated OAuth for MCP resource servers.
package mcpauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
	"github.com/Infisical/agent-vault/internal/store"
)

type Failure struct {
	Code     string `json:"code"`
	Message  string `json:"error"`
	Provider string `json:"provider,omitempty"`
}

func (f *Failure) Error() string { return f.Message }

func failure(code, message string) error { return &Failure{Code: code, Message: message} }

type Core interface {
	GetVaultByID(context.Context, string) (*store.Vault, error)
	GetCredential(context.Context, string, string) (*store.Credential, error)
	LockVault(context.Context, string) (func(), error)
	GetSetting(context.Context, string) (string, error)
	SetSetting(context.Context, string, string) error
}

type Client struct {
	Issuer          string
	ID              string
	Secret          string
	AuthMethod      string
	Kind            string
	Source          string
	ManagementURI   string
	ManagementToken string
	RedirectURI     string
	SecretExpiresAt time.Time
	// Name is the client_name sent at dynamic registration (e.g. the agent group's name).
	Name string
}

type Account struct {
	Key          string
	ResourceURL  string
	Resource     string
	Issuer       string
	Metadata     oauthex.AuthServerMeta
	Client       Client
	Scopes       string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	ConnectedAt  *time.Time
	LastUsedAt   *time.Time
	UpdatedAt    time.Time
	Reconnect    bool
}

type Flow struct {
	VaultID     string
	Account     Account
	Verifier    string
	RedirectURI string
	ExpiresAt   time.Time
}

type AccountInfo struct {
	Key         string     `json:"key"`
	ResourceURL string     `json:"resource_url"`
	Account     *string    `json:"account"`
	ConnectedAt *time.Time `json:"connected_at"`
	LastUsedAt  *time.Time `json:"last_used_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	Status      string     `json:"status"`
	Client      string     `json:"client"`
	Scopes      []string   `json:"scopes"`
}

func (a Account) Info() AccountInfo {
	status := "connected"
	if a.Reconnect || a.AccessToken == "" {
		status = "needs_reconnect"
	}
	return AccountInfo{Key: a.Key, ResourceURL: a.ResourceURL, ConnectedAt: a.ConnectedAt,
		LastUsedAt: a.LastUsedAt, UpdatedAt: a.UpdatedAt, Status: status, Client: a.Client.Kind,
		Scopes: strings.Fields(a.Scopes)}
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func accountKey(resource string) string { return "MCP_" + strings.ToUpper(digest(resource)[:24]) }

func provider(issuer string) string {
	switch strings.TrimSuffix(issuer, "/") {
	case "https://github.com/login/oauth":
		return "github"
	case "https://accounts.google.com":
		return "google"
	default:
		return ""
	}
}

func unsupported(issuer string) error {
	return &Failure{Code: "registration_unsupported", Provider: provider(issuer),
		Message: fmt.Sprintf("Authorization server %s supports neither usable registration nor a configured app or client metadata", issuer)}
}

// CleanClientName trims a requested client_name; empty means "keep the
// current name". It rejects control characters and names over 100 runes.
func CleanClientName(name string) (string, bool) {
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > 100 || !utf8.ValidString(name) {
		return "", false
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return name, true
}
