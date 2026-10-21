// Package oauthrelay completes private-gateway OAuth flows for a public host relay.
package oauthrelay

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/oauth"
	"github.com/Infisical/agent-vault/internal/store"
)

var ErrState = errors.New("invalid or expired OAuth state")

type Config struct {
	RedirectURI string
	MetadataURI string
}

func Configuration(base string) (Config, error) {
	redirect := os.Getenv("AGENT_VAULT_OAUTH_REDIRECT_URL")
	if redirect == "" {
		redirect = base + "/v1/oauth/callback"
	}
	u, err := url.Parse(redirect)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return Config{}, fmt.Errorf("AGENT_VAULT_OAUTH_REDIRECT_URL must be an absolute callback URL without userinfo, query or fragment")
	}
	loopback := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return Config{}, fmt.Errorf("OAuth redirect must use HTTPS (HTTP is allowed only on loopback)")
	}
	metadata := *u
	metadata.Path, metadata.RawPath = "/oauth/client-metadata.json", ""
	return Config{RedirectURI: redirect, MetadataURI: metadata.String()}, nil
}

func (c Config) Metadata() map[string]any {
	return map[string]any{
		"client_id": c.MetadataURI, "client_name": "NanoClaw credential gateway",
		"redirect_uris": []string{c.RedirectURI}, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	}
}

type Store interface {
	GetCredentialOAuthStateByHash(context.Context, string) (*store.CredentialOAuthState, error)
	DeleteCredentialOAuthState(context.Context, string) error
	GetCredentialOAuth(context.Context, string, string) (*store.CredentialOAuth, error)
	GetVaultByID(context.Context, string) (*store.Vault, error)
	UpdateCredentialOAuthTokens(context.Context, string, string, []byte, []byte, []byte, []byte, *time.Time) error
	LockVault(context.Context, string) (func(), error)
}

type Input struct {
	State string `json:"state"`
	Code  string `json:"code"`
	Error string `json:"error,omitempty"`
}

type Result struct {
	Status  string  `json:"status"`
	Vault   string  `json:"vault"`
	Key     string  `json:"key,omitempty"`
	Account *string `json:"account,omitempty"`
	Code    string  `json:"code,omitempty"`
	Error   string  `json:"error,omitempty"`
}

func Hash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

func Complete(ctx context.Context, db Store, key []byte, config Config, input Input, authorize func(string) error) (*Result, error) {
	if input.State == "" || (input.Code == "" && input.Error == "") {
		return nil, ErrState
	}
	st, err := db.GetCredentialOAuthStateByHash(ctx, Hash(input.State))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrState
	}
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, ErrState
	}
	if authorize != nil {
		if err := authorize(st.VaultID); err != nil {
			return nil, err
		}
	}
	unlock, err := db.LockVault(ctx, st.VaultID)
	if err != nil {
		return nil, err
	}
	defer unlock()
	// Re-read under the cross-process vault lock so one state cannot be exchanged twice.
	st, err = db.GetCredentialOAuthStateByHash(ctx, Hash(input.State))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrState
	}
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, ErrState
	}
	if err := db.DeleteCredentialOAuthState(ctx, st.ID); err != nil {
		return nil, err
	}
	if time.Now().After(st.ExpiresAt) {
		return nil, ErrState
	}
	vault, err := db.GetVaultByID(ctx, st.VaultID)
	if err != nil || vault == nil {
		return nil, fmt.Errorf("OAuth vault unavailable")
	}
	result := &Result{Status: "failed", Vault: vault.Name, Key: st.CredentialKey}
	if input.Error != "" {
		result.Code, result.Error = "declined", "OAuth authorization was declined"
		return result, nil
	}
	cfg, err := db.GetCredentialOAuth(ctx, st.VaultID, st.CredentialKey)
	if err != nil {
		return nil, fmt.Errorf("OAuth configuration unavailable")
	}
	var secret string
	if len(cfg.ClientSecretCT) != 0 {
		plaintext, err := crypto.Decrypt(cfg.ClientSecretCT, cfg.ClientSecretNonce, key)
		if err != nil {
			return nil, fmt.Errorf("decrypting OAuth client secret")
		}
		secret = string(plaintext)
		crypto.WipeBytes(plaintext)
	}
	redirect := st.RedirectURL
	if redirect == "" {
		redirect = config.RedirectURI
	}
	tok, err := oauth.Exchange(ctx, oauth.ExchangeConfig{
		TokenURL: cfg.TokenURL, ClientID: cfg.ClientID, ClientSecret: secret,
		Code: input.Code, RedirectURI: redirect, CodeVerifier: st.CodeVerifier, TokenAuthMethod: cfg.TokenAuthMethod,
	})
	if err != nil || tok.AccessToken == "" {
		result.Code, result.Error = "token_exchange_failed", "OAuth token exchange failed; start a new sign-in"
		return result, nil
	}
	access, accessNonce, err := crypto.Encrypt([]byte(tok.AccessToken), key)
	if err != nil {
		return nil, err
	}
	var refresh, refreshNonce []byte
	if tok.RefreshToken != "" {
		refresh, refreshNonce, err = crypto.Encrypt([]byte(tok.RefreshToken), key)
		if err != nil {
			return nil, err
		}
	}
	var expiry *time.Time
	if !tok.ExpiresAt.IsZero() {
		expiry = &tok.ExpiresAt
	}
	if err := db.UpdateCredentialOAuthTokens(ctx, st.VaultID, st.CredentialKey, access, accessNonce, refresh, refreshNonce, expiry); err != nil {
		return nil, err
	}
	result.Status = "connected"
	return result, nil
}
