// Package socketsessions binds revocable proxy identities to Unix listeners.
package socketsessions

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Infisical/agent-vault/internal/mitm"
	"github.com/Infisical/agent-vault/internal/store"
)

type Store interface {
	GetSession(context.Context, string) (*store.Session, error)
	GetAgentByID(context.Context, string) (*store.Agent, error)
	GetVault(context.Context, string) (*store.Vault, error)
	GetVaultRole(context.Context, string, string) (string, error)
	CreateScopedSession(context.Context, store.CreateScopedSessionParams) (*store.Session, error)
	DeleteSession(context.Context, string) error
}

type Item struct {
	ID         string    `json:"id"`
	Vault      string    `json:"vault"`
	Label      string    `json:"label"`
	SocketPath string    `json:"socket_path"`
	CreatedAt  time.Time `json:"created_at"`
}

type entry struct {
	Item
	owner, vaultID, token string
	proxy                 *mitm.Proxy
	listener              *trackedListener
}

type Manager struct {
	root   string
	store  Store
	bound  func(string) *mitm.Proxy
	logger *slog.Logger
	mu     sync.Mutex
	items  map[string]*entry
	closed bool
}

func New(root string, db Store, bound func(string) *mitm.Proxy, logger *slog.Logger) (*Manager, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return nil, fmt.Errorf("creating socket root: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, fmt.Errorf("resolving socket root: %w", err)
	}
	return &Manager{root: resolved, store: db, bound: bound, logger: logger, items: make(map[string]*entry)}, nil
}

func (m *Manager) Wrap(next http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/socket-sessions", m.create)
	mux.HandleFunc("GET /v1/socket-sessions", m.list)
	mux.HandleFunc("DELETE /v1/socket-sessions/{id}", m.delete)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/socket-sessions" || strings.HasPrefix(r.URL.Path, "/v1/socket-sessions/") {
			mux.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (m *Manager) authenticate(w http.ResponseWriter, r *http.Request) string {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		fail(w, 401, "Agent bearer token required")
		return ""
	}
	sess, err := m.store.GetSession(r.Context(), strings.TrimPrefix(header, "Bearer "))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 401, "Invalid agent token")
		} else {
			m.internal(w, "authenticating socket host", err)
		}
		return ""
	}
	if sess == nil || sess.AgentID == "" || sess.VaultID != "" || sess.IsExpired(time.Now()) {
		fail(w, 401, "Instance-level agent token required")
		return ""
	}
	agent, err := m.store.GetAgentByID(r.Context(), sess.AgentID)
	if err != nil {
		m.internal(w, "loading socket host", err)
		return ""
	}
	if agent == nil || agent.Status != "active" {
		fail(w, 401, "Agent is inactive")
		return ""
	}
	return agent.ID
}

func (m *Manager) authorize(w http.ResponseWriter, r *http.Request, actor, vault string) bool {
	role, err := m.store.GetVaultRole(r.Context(), actor, vault)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		m.internal(w, "checking socket vault membership", err)
		return false
	}
	if role == "" || errors.Is(err, sql.ErrNoRows) {
		fail(w, 403, "Host is not a vault member")
		return false
	}
	return true
}

func (m *Manager) directory(dir string) (string, error) {
	if !filepath.IsAbs(dir) {
		return "", fmt.Errorf("dir must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("dir must exist")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("dir must be an existing directory")
	}
	rel, err := filepath.Rel(m.root, resolved)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("dir must be beneath AGENT_VAULT_SOCKET_ROOT after resolving symlinks")
	}
	return resolved, nil
}

func (m *Manager) create(w http.ResponseWriter, r *http.Request) {
	actor := m.authenticate(w, r)
	if actor == "" {
		return
	}
	var req struct{ Vault, Label, Dir string }
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(&req); err != nil {
		fail(w, 400, "Invalid request body")
		return
	}
	if decoder.Decode(new(any)) != io.EOF {
		fail(w, 400, "Expected a single JSON object")
		return
	}
	dir, err := m.directory(req.Dir)
	if err != nil {
		fail(w, 400, err.Error())
		return
	}
	vault, err := m.store.GetVault(r.Context(), req.Vault)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		m.internal(w, "loading socket vault", err)
		return
	}
	if vault == nil || errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "Unknown vault")
		return
	}
	if !m.authorize(w, r, actor, vault.ID) {
		return
	}
	path := filepath.Join(dir, "egress.sock")
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		fail(w, 503, "Socket sessions are shutting down")
		return
	}
	for _, e := range m.items {
		if e.SocketPath == path {
			fail(w, 409, "Directory is already bound")
			return
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		fail(w, 409, "Socket path already exists or is inaccessible")
		return
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		m.internal(w, "binding socket", err)
		return
	}
	if err := os.Chmod(path, 0666); err != nil {
		listener.Close()
		m.internal(w, "setting socket permissions", err)
		return
	}
	// Internal sessions have no expiry; their lifetime is owned by this manager.
	sess, err := m.store.CreateScopedSession(r.Context(), store.CreateScopedSessionParams{
		VaultID: vault.ID, VaultRole: "proxy", Label: req.Label, CreatedByActorID: actor, CreatedByActorType: "agent",
	})
	if err != nil {
		listener.Close()
		m.internal(w, "creating socket identity", err)
		return
	}
	e := &entry{
		Item:  Item{ID: sess.PublicID, Vault: vault.Name, Label: req.Label, SocketPath: path, CreatedAt: sess.CreatedAt},
		owner: actor, vaultID: vault.ID, token: sess.ID, proxy: m.bound(sess.ID),
		listener: newTrackedListener(listener),
	}
	m.items[e.ID] = e
	go func() {
		if err := e.proxy.Serve(e.listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			m.logger.Error("socket proxy stopped", "id", e.ID, "err", err)
		}
	}()
	write(w, 201, map[string]string{"id": e.ID, "vault": e.Vault, "socket_path": path})
}

func (m *Manager) list(w http.ResponseWriter, r *http.Request) {
	actor := m.authenticate(w, r)
	if actor == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	items := make([]Item, 0)
	for _, e := range m.items {
		if e.owner == actor {
			items = append(items, e.Item)
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.Before(items[j].CreatedAt) })
	write(w, 200, map[string]any{"items": items})
}

func (m *Manager) delete(w http.ResponseWriter, r *http.Request) {
	actor := m.authenticate(w, r)
	if actor == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.items[r.PathValue("id")]
	if e == nil || e.owner != actor {
		fail(w, 404, "Socket session not found")
		return
	}
	if !m.authorize(w, r, actor, e.vaultID) {
		return
	}
	if err := m.remove(e); err != nil {
		m.internal(w, "deleting socket session", err)
		return
	}
	delete(m.items, e.ID)
	w.WriteHeader(204)
}

func (m *Manager) remove(e *entry) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(m.store.DeleteSession(ctx, e.token), e.listener.Close(), e.proxy.Shutdown(ctx))
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	var errs []error
	for id, e := range m.items {
		errs = append(errs, m.remove(e))
		delete(m.items, id)
	}
	return errors.Join(errs...)
}

func (m *Manager) internal(w http.ResponseWriter, action string, err error) {
	m.logger.Error(action, "err", err)
	fail(w, 500, "Socket session operation failed; see server logs")
}

func fail(w http.ResponseWriter, code int, message string) {
	write(w, code, map[string]string{"error": message})
}

func write(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Warn("writing socket session response", "err", err)
	}
}
