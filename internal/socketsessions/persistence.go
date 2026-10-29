package socketsessions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
)

const stateKey = "gateway.socket_sessions"

type savedEntry struct {
	Item
	Owner   string `json:"owner"`
	VaultID string `json:"vault_id"`
	Dir     string `json:"dir"`
	Token   string `json:"token"`
}

type savedState struct {
	Root    string       `json:"root"`
	Entries []savedEntry `json:"entries"`
}

type encryptedState struct {
	Version    int    `json:"version"`
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
}

func (m *Manager) persist(ctx context.Context) error {
	state := savedState{Root: m.root, Entries: make([]savedEntry, 0, len(m.items))}
	for _, e := range m.items {
		state.Entries = append(state.Entries, savedEntry{
			Item: e.Item, Owner: e.owner, VaultID: e.vaultID, Dir: filepath.Dir(e.SocketPath), Token: e.token,
		})
	}
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer crypto.WipeBytes(plaintext)
	ct, nonce, err := crypto.Encrypt(plaintext, m.key)
	if err != nil {
		return err
	}
	data, err := json.Marshal(encryptedState{Version: 1, Ciphertext: ct, Nonce: nonce})
	if err != nil {
		return err
	}
	return m.store.SetSetting(ctx, stateKey, string(data))
}

func (m *Manager) restore() error {
	if len(m.key) != 32 {
		return fmt.Errorf("socket persistence requires the 32-byte vault encryption key")
	}
	lock, err := os.Open(m.root)
	if err != nil {
		return err
	}
	m.lock = lock
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("socket root is already in use: %w", err)
	}
	ctx := context.Background()
	raw, err := m.store.GetSetting(ctx, stateKey)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("loading socket sessions: %w", err)
	}
	var envelope encryptedState
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		return fmt.Errorf("decoding socket sessions: %w", err)
	}
	if envelope.Version != 1 {
		return fmt.Errorf("unsupported socket persistence version %d", envelope.Version)
	}
	plaintext, err := crypto.Decrypt(envelope.Ciphertext, envelope.Nonce, m.key)
	if err != nil {
		return fmt.Errorf("decrypting socket sessions: %w", err)
	}
	defer crypto.WipeBytes(plaintext)
	var state savedState
	if err := json.Unmarshal(plaintext, &state); err != nil {
		return fmt.Errorf("decoding socket bindings: %w", err)
	}
	if state.Root != m.root {
		return fmt.Errorf("persisted socket root differs from AGENT_VAULT_SOCKET_ROOT")
	}
	paths := make(map[string]bool)
	for _, saved := range state.Entries {
		if saved.ID == "" || saved.Owner == "" || saved.VaultID == "" || saved.Token == "" ||
			saved.SocketPath != filepath.Join(saved.Dir, "egress.sock") ||
			paths[saved.SocketPath] || m.items[saved.ID] != nil {
			return fmt.Errorf("invalid persisted socket binding")
		}
		paths[saved.SocketPath] = true
		sess, err := m.store.GetSession(ctx, saved.Token)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("validating persisted socket identity: %w", err)
		}
		if sess == nil || sess.IsExpired(time.Now()) {
			m.logger.Warn("skipping revoked socket session", "id", saved.ID)
			continue
		}
		if sess.PublicID != saved.ID || sess.VaultID != saved.VaultID || sess.VaultRole != "proxy" ||
			sess.CreatedByActorID != saved.Owner || sess.CreatedByActorType != "agent" {
			return fmt.Errorf("persisted socket identity does not match its binding")
		}
		vault, err := m.store.GetVaultByID(ctx, saved.VaultID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				m.logger.Warn("skipping socket session for deleted vault", "id", saved.ID)
				continue
			}
			return err
		}
		if vault == nil {
			return fmt.Errorf("persisted socket vault is missing")
		}
		if vault.Purpose == "library" {
			return fmt.Errorf("personal libraries cannot restore group socket bindings")
		}
		agent, err := m.store.GetAgentByID(ctx, saved.Owner)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("loading persisted socket owner: %w", err)
		}
		role, roleErr := m.store.GetVaultRole(ctx, saved.Owner, saved.VaultID)
		if roleErr != nil && !errors.Is(roleErr, sql.ErrNoRows) {
			return fmt.Errorf("checking persisted socket membership: %w", roleErr)
		}
		if agent == nil || agent.Status != "active" || role == "" {
			if err := m.store.DeleteSession(ctx, saved.Token); err != nil {
				return err
			}
			m.logger.Warn("skipping socket session without an active vault member", "id", saved.ID)
			continue
		}
		saved.Vault = vault.Name
		e := &entry{Item: saved.Item, owner: saved.Owner, vaultID: saved.VaultID, token: saved.Token}
		m.items[e.ID] = e
		dir, err := m.directory(saved.Dir)
		if err != nil {
			if _, statErr := os.Stat(saved.Dir); errors.Is(statErr, os.ErrNotExist) {
				m.logger.Warn("skipping socket rebind: session directory vanished", "id", e.ID, "dir", saved.Dir)
				continue
			}
			return fmt.Errorf("validating persisted socket directory: %w", err)
		}
		if dir != saved.Dir {
			return fmt.Errorf("persisted socket directory changed after symlink resolution")
		}
		listener, err := rebind(e.SocketPath)
		if err != nil {
			return fmt.Errorf("rebinding socket session %s: %w", e.ID, err)
		}
		e.listener = newTrackedListener(listener)
		e.proxy = m.bound(e.token)
		m.serve(e)
	}
	return nil
}

func rebind(path string) (net.Listener, error) {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("persisted socket path is occupied by a non-socket")
		}
		conn, dialErr := net.DialTimeout("unix", path, 200*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			return nil, fmt.Errorf("persisted socket is still accepting connections")
		}
		if !errors.Is(dialErr, syscall.ECONNREFUSED) {
			return nil, fmt.Errorf("checking stale socket: %w", dialErr)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0666); err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	return listener, nil
}

func (m *Manager) serve(e *entry) {
	go func() {
		if err := e.proxy.Serve(e.listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			m.logger.Error("socket proxy stopped", "id", e.ID, "err", err)
		}
	}()
}

func stopEntry(ctx context.Context, e *entry) error {
	var errs []error
	if e.listener != nil {
		errs = append(errs, e.listener.Close())
	}
	if e.proxy != nil {
		errs = append(errs, e.proxy.Shutdown(ctx))
	}
	return errors.Join(errs...)
}
