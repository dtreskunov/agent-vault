// Package headless contains the NanoClaw gateway's account-free bootstrap.
package headless

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/gatewayconfig"
	"github.com/Infisical/agent-vault/internal/store"
)

const AgentName = "nanoclaw-host"

func Bootstrap(ctx context.Context, db store.Store) error {
	path := os.Getenv("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE")
	agent, err := db.GetAgentByName(ctx, AgentName)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("checking bootstrap agent: %w", err)
	}
	if agent != nil {
		data, err := readTokenFile(path)
		if err != nil {
			return recoveryError(err)
		}
		sess, err := db.GetSession(ctx, strings.TrimSpace(string(data)))
		if err != nil || sess == nil || sess.AgentID != agent.ID || sess.IsExpired(time.Now()) ||
			agent.Role != "owner" || agent.Status != "active" {
			return recoveryError(fmt.Errorf("bootstrap token is invalid or agent is not an active owner"))
		}
		return nil
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("bootstrap token output must not already exist: %s", path)
	}
	vault, err := db.GetVault(ctx, "default")
	if err != nil {
		return fmt.Errorf("loading default vault: %w", err)
	}
	if vault == nil {
		vault, err = db.CreateVault(ctx, "default")
		if err != nil {
			return fmt.Errorf("creating default vault: %w", err)
		}
	}
	_, sess, err := db.CreateAgentWithGrantsAndToken(ctx, AgentName, "", "owner",
		[]store.AgentVaultGrantSpec{{VaultID: vault.ID, Role: "admin"}}, nil)
	if err != nil {
		return fmt.Errorf("creating bootstrap agent: %w", err)
	}
	if err := writeTokenFile(path, sess.ID); err != nil {
		return recoveryError(err)
	}
	return nil
}

func recoveryError(err error) error {
	return fmt.Errorf("%w; stop the gateway and run 'agent-vault agent rotate nanoclaw-host' with the same gateway environment", err)
}

// Rotate is an explicit offline recovery operation, never an automatic startup action.
func Rotate(ctx context.Context, db store.Store) error {
	agent, err := db.GetAgentByName(ctx, AgentName)
	if err != nil {
		return err
	}
	if agent == nil || agent.Role != "owner" || agent.Status != "active" {
		return fmt.Errorf("bootstrap agent is not an active owner")
	}
	sess, err := db.RotateAgentToken(ctx, agent.ID, nil)
	if err != nil {
		return err
	}
	if err := writeTokenFile(os.Getenv("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE"), sess.ID); err != nil {
		return recoveryError(err)
	}
	return nil
}

func readTokenFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("bootstrap token file unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("bootstrap token file must be a regular file with mode 0600")
	}
	return os.ReadFile(path)
}

func writeTokenFile(path, token string) error {
	if path == "" {
		return fmt.Errorf("AGENT_VAULT_BOOTSTRAP_TOKEN_FILE is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".bootstrap-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(token + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

// Wrap removes the UI, human-account surface, SMTP and cookie authentication.
func Wrap(next http.Handler) http.Handler {
	if !gatewayconfig.Headless() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		disabled := path != "/health" && path != "/discover" && !strings.HasPrefix(path, "/v1/")
		for _, part := range strings.Split(path, "/") {
			disabled = disabled || part == "auth" || part == "users" || part == "invites" || part == "email"
		}
		if !strings.HasPrefix(path, "/v1/managed-users") {
			for _, part := range strings.Split(path, "/") {
				disabled = disabled || part == "credentials" || part == "services" || part == "keys" || part == "key-sets" || part == "oauth-apps" || part == "accounts" || part == "mcp-oauth" || part == "proposals"
			}
		}
		if disabled {
			http.NotFound(w, r)
			return
		}
		r.Header.Del("Cookie")
		next.ServeHTTP(w, r)
	})
}
