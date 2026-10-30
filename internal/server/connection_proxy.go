package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/gatewayconfig"
	"github.com/Infisical/agent-vault/internal/mcpauth"
	"github.com/Infisical/agent-vault/internal/store"
)

type sharedBinding struct {
	id, label, kind, library, revision, approved, status, handle, creator string
	owner                                                                 connectionOwner
	services                                                              []broker.Service
}

func (s *Server) loadBindings(ctx context.Context, vault string) ([]sharedBinding, error) {
	db, d := s.connectionSQL()
	if db == nil {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, d.Rebind(`SELECT c.id,c.label,c.kind,c.library_vault_id,c.revision,g.approved_revision,g.status,g.binding_handle,g.creator_user_id,c.owner_user_id,u.display_name,g.bound_services_json,g.services_json
		FROM connection_grants g JOIN connections c ON c.id=g.connection_id JOIN users u ON u.id=c.owner_user_id
		WHERE g.vault_id=? ORDER BY c.id`), vault)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []sharedBinding{}
	for rows.Next() {
		var b sharedBinding
		var raw, selectedRaw string
		if err = rows.Scan(&b.id, &b.label, &b.kind, &b.library, &b.revision, &b.approved, &b.status, &b.handle, &b.creator, &b.owner.ID, &b.owner.Label, &raw, &selectedRaw); err != nil {
			return nil, err
		}
		var services []broker.Service
		var selected []string
		if err = json.Unmarshal([]byte(raw), &services); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(selectedRaw), &selected); err != nil {
			return nil, err
		}
		for _, service := range services {
			if slices.Contains(selected, service.Name) {
				service.Host, service.Path, service.Port = broker.SplitInlineHost(service.Host, service.Path)
				b.services = append(b.services, service)
			}
		}
		items = append(items, b)
	}
	return items, rows.Err()
}

func serviceOverlap(a, b broker.Service) bool {
	a.Host, a.Path, a.Port = broker.SplitInlineHost(a.Host, a.Path)
	b.Host, b.Path, b.Port = broker.SplitInlineHost(b.Host, b.Path)
	if !broker.HostsOverlap(a, b) {
		return false
	}
	if a.Port != nil && b.Port != nil && *a.Port != *b.Port {
		return false
	}
	// Conservative prefix intersection rejects ambiguous glob expressions too.
	prefix := func(path string) string {
		if i := strings.IndexAny(path, "*?["); i >= 0 {
			return path[:i]
		}
		return path
	}
	ap, bp := prefix(a.Path), prefix(b.Path)
	return strings.HasPrefix(ap, bp) || strings.HasPrefix(bp, ap)
}
func (s *Server) assertBindingDestinationsCompatible(ctx context.Context, vault, exclude, kind string, selected []broker.Service) error {
	bindings, err := s.loadBindings(ctx, vault)
	if err != nil {
		return err
	}
	var occupied []broker.Service
	for _, b := range bindings {
		if b.id != exclude && b.status != "revoked" {
			if kind != "static" && b.kind != "static" {
				continue
			}
			occupied = append(occupied, b.services...)
		}
	}
	cfg, err := s.store.GetBrokerConfig(ctx, vault)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if cfg != nil && cfg.ServicesJSON != "" {
		var local []broker.Service
		if err = json.Unmarshal([]byte(cfg.ServicesJSON), &local); err != nil {
			return err
		}
		occupied = append(occupied, local...)
	}
	for _, candidate := range selected {
		for _, old := range occupied {
			if candidate.Name == old.Name || serviceOverlap(candidate, old) {
				return fmt.Errorf("a local or shared binding already occupies this service destination or name")
			}
		}
	}
	return nil
}
func (s *Server) authorizeBinding(ctx context.Context, vault string, b sharedBinding) error {
	db, d := s.connectionSQL()
	var count int
	err := db.QueryRowContext(ctx, d.Rebind(`SELECT COUNT(*) FROM connection_grants g JOIN connections c ON c.id=g.connection_id
		JOIN users u ON u.id=c.owner_user_id JOIN users creator ON creator.id=g.creator_user_id
		JOIN vaults v ON v.id=g.vault_id
		WHERE g.vault_id=? AND c.id=? AND g.binding_handle=? AND g.status='active' AND c.status='ready' AND c.deleted=0
		AND c.revision=? AND g.approved_revision=c.revision AND u.auth_mode='managed' AND u.is_active=?
		AND creator.is_active=? AND creator.id=c.owner_user_id AND v.purpose='group'
		AND EXISTS(SELECT 1 FROM vault_grants vg WHERE vg.actor_id=g.creator_user_id AND vg.actor_type='user' AND vg.vault_id=g.vault_id AND vg.role='admin')
		AND EXISTS(SELECT 1 FROM vaults library WHERE library.id=c.library_vault_id AND library.purpose='library' AND library.owner_user_id=c.owner_user_id)`),
		vault, b.id, b.handle, b.revision, d.BoolVal(true), d.BoolVal(true)).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return fmt.Errorf("%w: shared binding is revoked, suspended or stale", brokercore.ErrServiceDisabled)
	}
	return nil
}

type connectionCredentialStore struct {
	s   *Server
	b   sharedBinding
	raw string
}

func (a connectionCredentialStore) GetBrokerConfig(context.Context, string) (*store.BrokerConfig, error) {
	return &store.BrokerConfig{ServicesJSON: a.raw}, nil
}
func (a connectionCredentialStore) UnmatchedHostPolicy(context.Context, string) (brokercore.UnmatchedHostPolicy, error) {
	return brokercore.PolicyDeny, nil
}
func (a connectionCredentialStore) GetCredential(ctx context.Context, _ string, key string) (*store.Credential, error) {
	if a.b.kind == "static" {
		return a.s.store.GetCredential(ctx, a.b.library, connectionKey(a.b.id, key))
	}
	if key != a.b.id {
		return nil, fmt.Errorf("unknown connection credential")
	}
	if a.s.mcpOAuth == nil {
		return nil, fmt.Errorf("OAuth unavailable")
	}
	return a.s.mcpOAuth.Credential(ctx, a.b.library, key)
}

type sharedCredentialProvider struct {
	s     *Server
	local brokercore.CredentialProvider
}

func accessBindingHandle(values []string) (string, error) {
	for _, value := range values {
		if !strings.Contains(value, mcpauth.AccessPlaceholderPrefix) {
			continue
		}
		parts := strings.Fields(value)
		if len(values) != 1 || len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") ||
			!strings.HasPrefix(parts[1], mcpauth.AccessPlaceholderPrefix) {
			return "", fmt.Errorf("%w: malformed OAuth binding selector", brokercore.ErrServiceDisabled)
		}
		handle := strings.TrimPrefix(parts[1], mcpauth.AccessPlaceholderPrefix)
		if handle == "" {
			return "", fmt.Errorf("%w: empty OAuth binding selector", brokercore.ErrServiceDisabled)
		}
		return handle, nil
	}
	return "", nil
}

func (p sharedCredentialProvider) Inject(ctx context.Context, vault, host string, port int, path string) (*brokercore.InjectResult, error) {
	if db, _ := p.s.connectionSQL(); db == nil {
		return p.local.Inject(ctx, vault, host, port, path)
	}
	v, err := p.s.store.GetVaultByID(ctx, vault)
	if err != nil {
		return nil, err
	}
	if v.Purpose == "library" {
		return nil, fmt.Errorf("%w: personal libraries cannot proxy", brokercore.ErrServiceDisabled)
	}
	if gatewayconfig.Headless() {
		cfg, err := p.s.store.GetBrokerConfig(ctx, vault)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if cfg != nil && cfg.ServicesJSON != "" && cfg.ServicesJSON != "[]" {
			return nil, fmt.Errorf("%w: headless group-local credential services are unsupported", brokercore.ErrServiceDisabled)
		}
	}
	bindings, err := p.s.loadBindings(ctx, vault)
	if err != nil {
		return nil, err
	}
	if h, _, e := net.SplitHostPort(host); e == nil {
		host = h
	}
	if path == "" {
		path = "/"
	}
	handle, err := accessBindingHandle(brokercore.RequestAuthorization(ctx))
	if err != nil {
		return nil, err
	}
	var matchedBindings []int
	var matchedServices []*broker.Service
	for i := range bindings {
		b := &bindings[i]
		matched, _ := broker.MatchService(host, port, path, b.services)
		if matched == nil {
			continue
		}
		if b.status != "revoked" || handle == b.handle {
			matchedBindings = append(matchedBindings, i)
			matchedServices = append(matchedServices, matched)
		}
	}
	var chosen *sharedBinding
	var service *broker.Service
	for i, index := range matchedBindings {
		b := &bindings[index]
		if len(matchedBindings) > 1 && b.kind == "static" {
			return nil, fmt.Errorf("%w: static/shared binding conflict", brokercore.ErrServiceDisabled)
		}
		if handle != "" {
			if b.handle == handle && b.kind != "static" {
				chosen, service = b, matchedServices[i]
			}
		} else if len(matchedBindings) == 1 {
			chosen, service = b, matchedServices[i]
		}
	}
	if handle != "" && chosen == nil {
		return nil, fmt.Errorf("%w: OAuth binding selector is not authorized at this destination", brokercore.ErrServiceDisabled)
	}
	if handle == "" && len(matchedBindings) > 1 {
		return nil, fmt.Errorf("%w: ambiguous shared bindings require an explicit OAuth access placeholder", brokercore.ErrServiceDisabled)
	}
	if chosen == nil {
		for _, b := range bindings {
			if matched, _ := broker.MatchService(host, port, path, b.services); matched != nil && b.status == "revoked" {
				return nil, fmt.Errorf("%w: matching shared binding was revoked", brokercore.ErrServiceDisabled)
			}
		}
		return p.local.Inject(ctx, vault, host, port, path)
	}
	if err = p.s.authorizeBinding(ctx, vault, *chosen); err != nil {
		_ = p.s.auditConnectionUse(ctx, vault, *chosen, "denied")
		return nil, err
	}
	// Local rules can never shadow or compete with a shared authorization.
	cfg, err := p.s.store.GetBrokerConfig(ctx, vault)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if cfg != nil {
		var local []broker.Service
		if err = json.Unmarshal([]byte(cfg.ServicesJSON), &local); err != nil {
			return nil, err
		}
		for _, candidate := range local {
			if serviceOverlap(*service, candidate) {
				return nil, fmt.Errorf("%w: local/shared binding conflict", brokercore.ErrServiceDisabled)
			}
		}
	}
	raw, _ := json.Marshal([]broker.Service{*service})
	provider := brokercore.NewStoreCredentialProvider(connectionCredentialStore{p.s, *chosen, string(raw)}, p.s.encKey)
	result, err := provider.Inject(ctx, vault, host, port, path)
	if err != nil {
		_ = p.s.auditConnectionUse(ctx, vault, *chosen, "resolution_error")
		return nil, err
	}
	// Refresh and remote discovery can block while another request revokes a
	// grant. Never inject the resolved material without a second native check.
	if err = p.s.authorizeBinding(ctx, vault, *chosen); err != nil {
		_ = p.s.auditConnectionUse(ctx, vault, *chosen, "revoked_during_resolution")
		return nil, err
	}
	b := *chosen
	result.Authorize = func(check context.Context) error { return p.s.authorizeBinding(check, vault, b) }
	if err = p.s.auditConnectionUse(ctx, vault, b, "authorized"); err != nil {
		return nil, err
	}
	return result, nil
}
func (s *Server) auditConnectionUse(ctx context.Context, vault string, b sharedBinding, status string) error {
	db, d := s.connectionSQL()
	_, err := db.ExecContext(ctx, d.Rebind(`INSERT INTO connection_audit (id,created_at,transport_actor_id,effective_user_id,connection_id,vault_id,revision,action,status) VALUES (?,?,?,?,?,?,?,?,?)`),
		revision(), d.FormatTime(timeNow()), brokercore.ProxyActor(ctx), b.owner.ID, b.id, vault, b.revision, "use", status)
	return err
}

// sharedTokenResponse consumes F8 refresh handles in their authenticated group,
// never in a credential owner's library or by an arbitrary account key.
func (s *Server) sharedTokenResponse(ctx context.Context, vault string, r *http.Request) (*http.Response, error) {
	if s.mcpOAuth == nil {
		return nil, nil
	}
	if raw := r.Header.Get("Authorization"); strings.HasPrefix(raw, "Bearer "+mcpauth.AccessPlaceholderPrefix) {
		handle := strings.TrimPrefix(raw, "Bearer "+mcpauth.AccessPlaceholderPrefix)
		bindings, err := s.loadBindings(ctx, vault)
		if err != nil {
			return nil, err
		}
		allowed := false
		port := 443
		if r.URL.Port() != "" {
			value, err := strconv.Atoi(r.URL.Port())
			if err != nil {
				return nil, err
			}
			port = value
		}
		for _, b := range bindings {
			if b.handle != handle || b.kind == "static" {
				continue
			}
			matched, _ := broker.MatchService(r.URL.Hostname(), port, r.URL.Path, b.services)
			if matched != nil && r.URL.Scheme == "https" && s.authorizeBinding(ctx, vault, b) == nil {
				allowed = true
			}
		}
		if !allowed {
			body, _ := json.Marshal(map[string]string{"error": "invalid_binding", "message": "Access placeholder is unknown, revoked or not authorized at this destination"})
			return &http.Response{StatusCode: 403, Header: http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body))}, nil
		}
	}
	return s.mcpOAuth.BindingTokenResponse(ctx, r, func(handle string) (*mcpauth.Account, error) {
		bindings, err := s.loadBindings(ctx, vault)
		if err != nil {
			return nil, err
		}
		for _, b := range bindings {
			if b.handle != handle {
				continue
			}
			if b.kind == "static" {
				return nil, fmt.Errorf("binding is not OAuth")
			}
			if err = s.authorizeBinding(ctx, vault, b); err != nil {
				return nil, err
			}
			account, err := s.mcpOAuth.ConnectionAccount(ctx, b.library, b.id)
			if err != nil {
				return nil, err
			}
			if account.Reconnect || account.AccessToken == "" {
				return nil, fmt.Errorf("connection needs sign-in")
			}
			if err = s.authorizeBinding(ctx, vault, b); err != nil {
				return nil, err
			}
			return account, nil
		}
		return nil, fmt.Errorf("unknown or revoked group binding")
	})
}

func (s *Server) sharedDiscovery(ctx context.Context, vault string) ([]discoverService, []string, error) {
	bindings, err := s.loadBindings(ctx, vault)
	if err != nil {
		return nil, nil, err
	}
	services := []discoverService{}
	keys := []string{}
	for _, b := range bindings {
		if err = s.authorizeBinding(ctx, vault, b); err != nil {
			continue
		}
		for _, service := range b.services {
			item := discoverService{Name: service.Name, Host: service.MatcherPattern()}
			if b.kind != "static" {
				item.AccessPlaceholder = mcpauth.AccessPlaceholderPrefix + b.handle
				for _, other := range bindings {
					if other.id == b.id || other.status == "revoked" {
						continue
					}
					for _, candidate := range other.services {
						if serviceOverlap(service, candidate) {
							item.SelectionRequired = true
						}
					}
				}
				keys = append(keys, b.handle)
			} else {
				keys = append(keys, service.CredentialKeys()...)
			}
			services = append(services, item)
		}
	}
	slices.Sort(keys)
	keys = slices.Compact(keys)
	return services, keys, nil
}
