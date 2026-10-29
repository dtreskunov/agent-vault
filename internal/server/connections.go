package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/headless"
	"github.com/Infisical/agent-vault/internal/store"
)

func timeNow() time.Time { return time.Now().UTC() }

type connectionOwner struct {
	ID    string `json:"id"`
	Label string `json:"label,omitempty"`
}
type connectionGrant struct {
	Vault    string   `json:"vault"`
	Services []string `json:"services"`
	Status   string   `json:"status"`
}
type connection struct {
	ID              string            `json:"id"`
	Label           string            `json:"label"`
	Kind            string            `json:"kind"`
	Status          string            `json:"status"`
	Revision        string            `json:"revision"`
	Owner           connectionOwner   `json:"owner"`
	Services        []broker.Service  `json:"services"`
	Credentials     []string          `json:"credentials"`
	Grants          []connectionGrant `json:"grants"`
	ResourceURL     string            `json:"resource_url,omitempty"`
	AppID           string            `json:"app_id,omitempty"`
	RequestedScopes []string          `json:"requested_scopes"`
	GrantedScopes   []string          `json:"granted_scopes"`
	ScopeSource     string            `json:"scope_source,omitempty"`
	Account         *string           `json:"account"`
	library         string
	sourceRevision  string
}
type connectionInput struct {
	Label       string            `json:"label"`
	Kind        string            `json:"kind"`
	Services    []broker.Service  `json:"services"`
	Values      map[string]string `json:"values"`
	ResourceURL string            `json:"resource_url"`
	AppID       string            `json:"app_id"`
	Scopes      []string          `json:"scopes"`
}
type connectionUpdate struct {
	Label    *string            `json:"label"`
	Enabled  *bool              `json:"enabled"`
	Services *[]broker.Service  `json:"services"`
	Values   *map[string]string `json:"values"`
}
type accessGrant struct {
	ConnectionID string           `json:"connection_id"`
	Label        string           `json:"label"`
	Owner        connectionOwner  `json:"owner"`
	Services     []broker.Service `json:"services"`
	Status       string           `json:"status"`
}

func (s *Server) connectionSQL() (*sql.DB, store.Dialect) {
	if access, ok := s.store.(interface {
		GatewaySQL() (*sql.DB, store.Dialect)
	}); ok {
		return access.GatewaySQL()
	}
	return nil, nil
}

func (s *Server) registerManaged(mux *http.ServeMux, wrap func(http.HandlerFunc) http.HandlerFunc) {
	mux.HandleFunc("PUT /v1/managed-users", wrap(s.handleManagedReconcile))
	mux.HandleFunc("GET /v1/managed-users/{user}/connections", wrap(s.handleConnectionsList))
	mux.HandleFunc("POST /v1/managed-users/{user}/connections", wrap(s.handleConnectionCreate))
	mux.HandleFunc("GET /v1/managed-users/{user}/connections/{connection}", wrap(s.handleConnectionGet))
	mux.HandleFunc("PUT /v1/managed-users/{user}/connections/{connection}", wrap(s.handleConnectionUpdate))
	mux.HandleFunc("DELETE /v1/managed-users/{user}/connections/{connection}", wrap(s.handleConnectionDelete))
	mux.HandleFunc("POST /v1/managed-users/{user}/connections/{connection}/oauth/start", wrap(s.handleConnectionOAuthStart))
	mux.HandleFunc("PUT /v1/managed-users/{user}/connections/{connection}/grants/{vault}", wrap(s.handleConnectionGrant))
	mux.HandleFunc("DELETE /v1/managed-users/{user}/connections/{connection}/grants/{vault}", wrap(s.handleConnectionDetach))
	mux.HandleFunc("GET /v1/managed-users/{user}/vaults/{vault}/access", wrap(s.handleConnectionAccess))
	mux.HandleFunc("DELETE /v1/managed-users/{user}/vaults/{vault}/access/{connection}", wrap(s.handleConnectionDetach))
	mux.HandleFunc("GET /v1/managed-users/{user}/oauth-apps", wrap(s.handleManagedApps))
	mux.HandleFunc("PUT /v1/managed-users/{user}/oauth-apps/{app}", wrap(s.handleManagedAppPut))
	mux.HandleFunc("DELETE /v1/managed-users/{user}/oauth-apps/{app}", wrap(s.handleManagedAppDelete))
}

func (s *Server) managedTransport(w http.ResponseWriter, r *http.Request) *Actor {
	w.Header().Set("Cache-Control", "no-store")
	a, err := s.requireOwnerActor(w, r)
	if err != nil {
		return nil
	}
	if a.Agent == nil || a.Agent.Name != headless.AgentName || a.Agent.Status != "active" {
		jsonCodedError(w, 403, "host_required", "Only the authorized nanoclaw-host transport may delegate managed APIs")
		return nil
	}
	return a
}
func (s *Server) effectiveManaged(w http.ResponseWriter, r *http.Request) *Actor {
	if s.managedTransport(w, r) == nil {
		return nil
	}
	u, err := s.store.GetUserByID(r.Context(), r.PathValue("user"))
	if err != nil || u == nil || u.AuthMode != "managed" || !u.IsActive || u.InstallationID == "" || u.Subject == "" {
		jsonCodedError(w, 403, "managed_user_inactive", "Mapped managed user is missing or inactive")
		return nil
	}
	return &Actor{ID: u.ID, Type: "user", Role: u.Role, User: u}
}
func (s *Server) managedLibrary(ctx context.Context, user string) (*store.Vault, error) {
	db, d := s.connectionSQL()
	if db == nil {
		return nil, fmt.Errorf("managed storage unavailable")
	}
	var name string
	if err := db.QueryRowContext(ctx, d.Rebind(`SELECT name FROM vaults WHERE owner_user_id=? AND purpose='library'`), user).Scan(&name); err != nil {
		return nil, err
	}
	return s.store.GetVault(ctx, name)
}
func (s *Server) connectionAudit(ctx context.Context, r *http.Request, user, id, vault, revision, action, status string) error {
	db, d := s.connectionSQL()
	transport := sessionFromContext(r.Context())
	host := ""
	if transport != nil {
		host = transport.AgentID
	}
	_, err := db.ExecContext(ctx, d.Rebind(`INSERT INTO connection_audit (id,created_at,transport_actor_id,effective_user_id,connection_id,vault_id,revision,action,status) VALUES (?,?,?,?,?,?,?,?,?)`),
		rand.Text(), d.FormatTime(timeNow()), host, user, id, vault, revision, action, status)
	return err
}

func (s *Server) handleManagedReconcile(w http.ResponseWriter, r *http.Request) {
	host := s.managedTransport(w, r)
	if host == nil {
		return
	}
	var request struct {
		InstallationID string                     `json:"installation_id"`
		Subject        string                     `json:"subject"`
		DisplayName    string                     `json:"display_name"`
		Email          string                     `json:"email"`
		Active         *bool                      `json:"active"`
		Role           string                     `json:"role"`
		VaultGrants    *[]store.ManagedVaultGrant `json:"vault_grants"`
	}
	if !decodeManaged(w, r, &request) {
		return
	}
	if request.Active == nil || request.VaultGrants == nil {
		jsonCodedError(w, 400, "invalid_managed_user", "active and a complete vault_grants array are required")
		return
	}
	in := store.ManagedUserInput{InstallationID: request.InstallationID, Subject: request.Subject, DisplayName: request.DisplayName, Email: request.Email, Active: *request.Active, Role: request.Role, VaultGrants: *request.VaultGrants}
	db, ok := s.store.(interface {
		ReconcileManagedUser(context.Context, store.ManagedUserInput) (*store.ManagedUserResult, error)
	})
	if !ok {
		jsonError(w, 503, "Managed storage unavailable")
		return
	}
	result, err := db.ReconcileManagedUser(r.Context(), in)
	if err != nil {
		jsonCodedError(w, 400, "invalid_managed_user", err.Error())
		return
	}
	for _, g := range in.VaultGrants {
		v, err := s.store.GetVault(r.Context(), g.Vault)
		if err != nil {
			jsonError(w, 500, "Host group membership reconciliation failed")
			return
		}
		if err = s.store.GrantVaultRole(r.Context(), host.ID, "agent", v.ID, "admin"); err != nil {
			jsonError(w, 500, "Host group membership reconciliation failed")
			return
		}
	}
	if err = s.connectionAudit(r.Context(), r, result.ID, "", "", "", "reconcile", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	jsonOK(w, result)
}
func decodeManaged(w http.ResponseWriter, r *http.Request, value any) bool {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		jsonCodedError(w, 400, "invalid_request", "Invalid request body: "+err.Error())
		return false
	}
	if err := d.Decode(new(any)); err != io.EOF {
		jsonError(w, 400, "Expected one JSON object")
		return false
	}
	return true
}
func revision() string                    { return `"` + rand.Text() + `"` }
func connectionKey(id, key string) string { return id + "_" + key }
func (s *Server) loadConnection(ctx context.Context, id string) (*connection, error) {
	db, d := s.connectionSQL()
	if db == nil {
		return nil, fmt.Errorf("managed storage unavailable")
	}
	c := &connection{Grants: []connectionGrant{}}
	var services, keys, scopes string
	err := db.QueryRowContext(ctx, d.Rebind(`SELECT c.id,c.owner_user_id,u.display_name,c.library_vault_id,c.label,c.kind,c.status,c.revision,c.services_json,c.keys_json,c.resource_url,c.app_id,c.scopes_json
		FROM connections c JOIN users u ON u.id=c.owner_user_id WHERE c.id=? AND c.deleted=0`), id).Scan(
		&c.ID, &c.Owner.ID, &c.Owner.Label, &c.library, &c.Label, &c.Kind, &c.Status, &c.sourceRevision, &services, &keys, &c.ResourceURL, &c.AppID, &scopes)
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(services), &c.Services); err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(keys), &c.Credentials); err != nil {
		return nil, err
	}
	if err = json.Unmarshal([]byte(scopes), &c.RequestedScopes); err != nil {
		return nil, err
	}
	if c.Kind != "static" && s.mcpOAuth != nil {
		a, err := s.mcpOAuth.ConnectionAccount(ctx, c.library, c.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if a != nil {
			c.RequestedScopes, c.GrantedScopes, c.ScopeSource, c.Account = a.RequestedScopes, a.GrantedScopes, a.ScopeSource, a.Identity
			if c.Status != "disabled" {
				if a.Reconnect || a.AccessToken == "" {
					c.Status = "needs_reconnect"
				} else {
					c.Status = "ready"
				}
			}
		}
	}
	rows, err := db.QueryContext(ctx, d.Rebind(`SELECT v.name,g.services_json,g.status,g.binding_handle FROM connection_grants g JOIN vaults v ON v.id=g.vault_id WHERE g.connection_id=? AND g.status<>'revoked' ORDER BY v.name`), id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	handles := ""
	for rows.Next() {
		var g connectionGrant
		var raw, handle string
		if err = rows.Scan(&g.Vault, &raw, &g.Status, &handle); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &g.Services); err != nil {
			return nil, err
		}
		c.Grants = append(c.Grants, g)
		handles += handle + "\x00"
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	// The wire ETag covers grant metadata too, while the stored source-policy
	// revision authorizes bindings. Editing one recipient cannot invalidate an
	// unrelated group's already-authorized stream.
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(c.sourceRevision+"\x00"+handles), raw...))
	c.Revision = `"` + hex.EncodeToString(sum[:]) + `"`
	return c, nil
}
func (s *Server) ownedConnection(w http.ResponseWriter, r *http.Request) (*Actor, *connection) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return nil, nil
	}
	c, err := s.loadConnection(r.Context(), r.PathValue("connection"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			jsonCodedError(w, 404, "connection_not_found", "Connection not found")
		} else {
			jsonError(w, 500, "Connection read failed")
		}
		return nil, nil
	}
	if c.Owner.ID != a.ID {
		jsonCodedError(w, 403, "connection_owner_required", "Connection ownership is required")
		return nil, nil
	}
	return a, c
}
func (s *Server) handleConnectionsList(w http.ResponseWriter, r *http.Request) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return
	}
	db, d := s.connectionSQL()
	rows, err := db.QueryContext(r.Context(), d.Rebind(`SELECT id FROM connections WHERE owner_user_id=? AND deleted=0 ORDER BY id`), a.ID)
	if err != nil {
		jsonError(w, 500, "Connection read failed")
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			break
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err != nil {
		jsonError(w, 500, "Connection read failed")
		return
	}
	items := []*connection{}
	for _, id := range ids {
		c, err := s.loadConnection(r.Context(), id)
		if err != nil {
			jsonError(w, 500, "Connection read failed")
			return
		}
		items = append(items, c)
	}
	jsonOK(w, map[string]any{"connections": items})
}
func (s *Server) handleConnectionGet(w http.ResponseWriter, r *http.Request) {
	_, c := s.ownedConnection(w, r)
	if c == nil {
		return
	}
	w.Header().Set("ETag", c.Revision)
	jsonOK(w, c)
}
func normalizeConnectionServices(services []broker.Service, keys []string) error {
	for i := range services {
		services[i].Host, services[i].Path, services[i].Port = broker.SplitInlineHost(services[i].Host, services[i].Path)
		services[i].HTTPSOnly = true
		if services[i].Name == "" {
			return fmt.Errorf("each service needs an explicit name")
		}
		for _, key := range services[i].CredentialKeys() {
			if !slices.Contains(keys, key) {
				return fmt.Errorf("service references unknown credential %s", key)
			}
		}
	}
	if err := broker.Validate(&broker.Config{Vault: "connection", Services: services}); err != nil {
		return err
	}
	for i := range services {
		for j := 0; j < i; j++ {
			if serviceOverlap(services[i], services[j]) {
				return fmt.Errorf("ambiguous overlapping connection services")
			}
		}
	}
	return nil
}
func (s *Server) handleConnectionCreate(w http.ResponseWriter, r *http.Request) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return
	}
	var in connectionInput
	if !decodeManaged(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Label) == "" || (in.Kind != "static" && in.Kind != "mcp_oauth" && in.Kind != "oauth_app") {
		jsonError(w, 400, "A label and supported kind are required")
		return
	}
	library, err := s.managedLibrary(r.Context(), a.ID)
	if err != nil {
		jsonError(w, 500, "Personal library unavailable")
		return
	}
	keys := []string{}
	for key, value := range in.Values {
		if !broker.CredentialKeyPattern.MatchString(key) || value == "" {
			jsonError(w, 400, "Invalid or empty credential")
			return
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if in.Kind == "static" {
		if len(keys) == 0 || len(in.Services) == 0 {
			jsonError(w, 400, "Static connections require values and services")
			return
		}
		if err = normalizeConnectionServices(in.Services, keys); err != nil {
			jsonError(w, 400, err.Error())
			return
		}
	} else if len(in.Values) != 0 || len(in.Services) != 0 {
		jsonError(w, 400, "OAuth services and credentials come only from the authorized connection")
		return
	}
	if in.Kind == "mcp_oauth" && in.ResourceURL == "" {
		jsonError(w, 400, "resource_url is required")
		return
	}
	if in.Kind == "oauth_app" && in.AppID == "" {
		jsonError(w, 400, "app_id is required")
		return
	}
	id := "CONN_" + strings.ToUpper(rand.Text())
	rev := revision()
	status := "draft"
	if in.Kind == "static" {
		status = "ready"
	}
	services, _ := json.Marshal(in.Services)
	if in.Services == nil {
		services = []byte("[]")
	}
	rawKeys, _ := json.Marshal(keys)
	scopes, _ := json.Marshal(in.Scopes)
	db, d := s.connectionSQL()
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		jsonError(w, 500, "Connection storage unavailable")
		return
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(r.Context(), d.Rebind(`INSERT INTO connections (id,owner_user_id,library_vault_id,label,kind,status,revision,services_json,keys_json,resource_url,app_id,scopes_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`),
		id, a.ID, library.ID, in.Label, in.Kind, status, rev, string(services), string(rawKeys), in.ResourceURL, in.AppID, string(scopes))
	if err == nil {
		err = s.writeConnectionValues(r.Context(), tx, library.ID, id, in.Values)
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		jsonError(w, 500, "Connection creation failed")
		return
	}
	if err = s.connectionAudit(r.Context(), r, a.ID, id, "", rev, "create", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	c, err := s.loadConnection(r.Context(), id)
	if err != nil {
		jsonError(w, 500, "Connection read failed")
		return
	}
	w.Header().Set("ETag", c.Revision)
	jsonStatus(w, 201, c)
}
func (s *Server) writeConnectionValues(ctx context.Context, tx *sql.Tx, vault, id string, values map[string]string) error {
	_, d := s.connectionSQL()
	for key, value := range values {
		ct, nonce, err := crypto.Encrypt([]byte(value), s.encKey)
		if err != nil {
			return err
		}
		now := d.FormatTime(timeNow())
		_, err = tx.ExecContext(ctx, d.Rebind(`INSERT INTO credentials (id,vault_id,key,type,ciphertext,nonce,created_at,updated_at) VALUES (?,?,?,'static',?,?,?,?)
			ON CONFLICT(vault_id,key) DO UPDATE SET ciphertext=excluded.ciphertext,nonce=excluded.nonce,updated_at=excluded.updated_at WHERE credentials.type='static'`),
			rand.Text(), vault, connectionKey(id, key), ct, nonce, now, now)
		if err != nil {
			return err
		}
	}
	return nil
}
func (s *Server) handleConnectionUpdate(w http.ResponseWriter, r *http.Request) {
	a, c := s.ownedConnection(w, r)
	if c == nil {
		return
	}
	if !matchConnectionRevision(w, r, c) {
		return
	}
	var in connectionUpdate
	if !decodeManaged(w, r, &in) {
		return
	}
	unlock, err := s.store.LockVault(r.Context(), "connection-policy")
	if err != nil {
		jsonError(w, 500, "Policy lock unavailable")
		return
	}
	defer unlock()
	c, err = s.loadConnection(r.Context(), c.ID)
	if err != nil {
		jsonError(w, 404, "Connection not found")
		return
	}
	if !matchConnectionRevision(w, r, c) {
		return
	}
	oldRevision := c.sourceRevision
	policyChanged := false
	if in.Label != nil {
		if strings.TrimSpace(*in.Label) == "" {
			jsonError(w, 400, "Label must not be empty")
			return
		}
		c.Label = *in.Label
	}
	if in.Values != nil {
		if c.Kind != "static" {
			jsonError(w, 400, "OAuth values cannot be uploaded")
			return
		}
		for key, value := range *in.Values {
			if value == "" || !broker.CredentialKeyPattern.MatchString(key) {
				jsonError(w, 400, "Credential names must be UPPER_SNAKE_CASE and values nonempty")
				return
			}
			if !slices.Contains(c.Credentials, key) {
				c.Credentials = append(c.Credentials, key)
			}
		}
		sort.Strings(c.Credentials)
	}
	if in.Services != nil {
		if c.Kind != "static" {
			jsonError(w, 400, "OAuth services are derived from the connection")
			return
		}
		if err = normalizeConnectionServices(*in.Services, c.Credentials); err != nil {
			jsonError(w, 400, err.Error())
			return
		}
		c.Services = *in.Services
		policyChanged = true
	}
	if in.Enabled != nil {
		if !*in.Enabled {
			c.Status = "disabled"
			policyChanged = true
		} else if c.Kind == "static" {
			c.Status = "ready"
		} else {
			c.Status = "draft"
			if s.mcpOAuth != nil {
				account, accountErr := s.mcpOAuth.ConnectionAccount(r.Context(), c.library, c.ID)
				if accountErr != nil && !errors.Is(accountErr, sql.ErrNoRows) {
					jsonError(w, 500, "OAuth connection state unavailable")
					return
				}
				if account != nil {
					c.Status = "needs_reconnect"
					if !account.Reconnect && account.AccessToken != "" {
						c.Status = "ready"
					}
				}
			}
		}
	}
	c.Revision = revision()
	raw, _ := json.Marshal(c.Services)
	keysRaw, _ := json.Marshal(c.Credentials)
	db, d := s.connectionSQL()
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		jsonError(w, 500, "Connection update failed")
		return
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(r.Context(), d.Rebind(`UPDATE connections SET label=?,status=?,revision=?,services_json=?,keys_json=? WHERE id=? AND revision=? AND deleted=0 AND EXISTS(SELECT 1 FROM users WHERE id=connections.owner_user_id AND is_active=?)`), c.Label, c.Status, c.Revision, string(raw), string(keysRaw), c.ID, oldRevision, d.BoolVal(true))
	if err == nil {
		var n int64
		n, err = result.RowsAffected()
		if err == nil && n != 1 {
			jsonError(w, 412, "Revision changed")
			return
		}
	}
	if err == nil && in.Values != nil {
		err = s.writeConnectionValues(r.Context(), tx, c.library, c.ID, *in.Values)
	}
	if err == nil {
		if policyChanged {
			_, err = tx.ExecContext(r.Context(), d.Rebind(`UPDATE connection_grants SET status='suspended' WHERE connection_id=? AND status='active'`), c.ID)
		} else {
			_, err = tx.ExecContext(r.Context(), d.Rebind(`UPDATE connection_grants SET approved_revision=? WHERE connection_id=? AND status='active' AND approved_revision=?`), c.Revision, c.ID, oldRevision)
		}
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		jsonError(w, 500, "Connection update failed")
		return
	}
	if err = s.connectionAudit(r.Context(), r, a.ID, c.ID, "", c.Revision, "update", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	c, err = s.loadConnection(r.Context(), c.ID)
	if err != nil {
		jsonError(w, 500, "Connection read failed")
		return
	}
	w.Header().Set("ETag", c.Revision)
	jsonOK(w, c)
}
func matchConnectionRevision(w http.ResponseWriter, r *http.Request, c *connection) bool {
	if r.Header.Get("If-Match") == "" {
		jsonCodedError(w, 428, "precondition_required", "Exact If-Match connection revision is required")
		return false
	}
	if r.Header.Get("If-Match") != c.Revision {
		jsonCodedError(w, 412, "revision_conflict", "Connection changed; reload before explicitly retrying")
		return false
	}
	return true
}
func (s *Server) destinationGroup(w http.ResponseWriter, r *http.Request, a *Actor, admin bool) *store.Vault {
	v, err := s.store.GetVault(r.Context(), r.PathValue("vault"))
	if err != nil || v == nil || v.Purpose != "group" {
		jsonError(w, 404, "Group vault not found")
		return nil
	}
	role, err := s.store.GetVaultRole(r.Context(), a.ID, v.ID)
	if err != nil || (admin && role != "admin") {
		jsonCodedError(w, 403, "group_admin_required", "Native destination-vault administration is required")
		return nil
	}
	return v
}
func (s *Server) handleConnectionGrant(w http.ResponseWriter, r *http.Request) {
	a, c := s.ownedConnection(w, r)
	if c == nil {
		return
	}
	if none := r.Header.Get("If-None-Match"); none != "" && (none != "*" || r.Header.Get("If-Match") != "") {
		jsonCodedError(w, 428, "invalid_precondition", "Use If-None-Match:* for creation or one exact If-Match revision for reapproval")
		return
	}
	v := s.destinationGroup(w, r, a, true)
	if v == nil {
		return
	}
	var in struct {
		Services []string `json:"services"`
	}
	if !decodeManaged(w, r, &in) {
		return
	}
	if len(in.Services) == 0 {
		jsonError(w, 400, "Explicit connection service names are required")
		return
	}
	unlock, err := s.store.LockVault(r.Context(), "connection-policy")
	if err != nil {
		jsonError(w, 500, "Policy lock unavailable")
		return
	}
	defer unlock()
	c, err = s.loadConnection(r.Context(), c.ID)
	if err != nil {
		jsonError(w, 404, "Connection not found")
		return
	}
	if c.Status != "ready" {
		jsonError(w, 409, "Only ready connections can be granted")
		return
	}
	selected := []broker.Service{}
	seen := map[string]bool{}
	for _, name := range in.Services {
		if seen[name] {
			jsonError(w, 400, "Duplicate service")
			return
		}
		seen[name] = true
		found := false
		for _, service := range c.Services {
			if service.Name == name {
				selected = append(selected, service)
				found = true
				break
			}
		}
		if !found {
			jsonError(w, 400, "Unknown connection service")
			return
		}
	}
	db, d := s.connectionSQL()
	var existing string
	err = db.QueryRowContext(r.Context(), d.Rebind(`SELECT status FROM connection_grants WHERE connection_id=? AND vault_id=?`), c.ID, v.ID).Scan(&existing)
	if err == nil && existing != "revoked" {
		if r.Header.Get("If-Match") == "" {
			jsonCodedError(w, 409, "grant_exists", "Grant exists; explicit revision is required for reapproval")
			return
		}
		if !matchConnectionRevision(w, r, c) {
			return
		}
	} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 500, "Grant read failed")
		return
	}
	if r.Header.Get("If-Match") != "" && !matchConnectionRevision(w, r, c) {
		return
	}
	if err = s.assertBindingUnambiguous(r.Context(), v.ID, c.ID, selected); err != nil {
		jsonCodedError(w, 409, "binding_conflict", err.Error())
		return
	}
	raw, _ := json.Marshal(in.Services)
	bound, _ := json.Marshal(selected)
	_, err = db.ExecContext(r.Context(), d.Rebind(`INSERT INTO connection_grants (connection_id,vault_id,services_json,bound_services_json,approved_revision,status,creator_user_id,binding_handle)
		VALUES (?,?,?,?,?,'active',?,?) ON CONFLICT(connection_id,vault_id) DO UPDATE SET services_json=excluded.services_json,bound_services_json=excluded.bound_services_json,
		approved_revision=excluded.approved_revision,status='active',creator_user_id=excluded.creator_user_id,binding_handle=excluded.binding_handle`),
		c.ID, v.ID, string(raw), string(bound), c.sourceRevision, a.ID, "BIND_"+strings.ToUpper(rand.Text()))
	if err != nil {
		jsonError(w, 500, "Grant write failed")
		return
	}
	if err = s.connectionAudit(r.Context(), r, a.ID, c.ID, v.ID, c.Revision, "grant", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	c, err = s.loadConnection(r.Context(), c.ID)
	if err != nil {
		jsonError(w, 500, "Connection read failed")
		return
	}
	jsonOK(w, c)
}
func (s *Server) handleConnectionDetach(w http.ResponseWriter, r *http.Request) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return
	}
	c, err := s.loadConnection(r.Context(), r.PathValue("connection"))
	if err != nil {
		jsonError(w, 404, "Connection not found")
		return
	}
	v, err := s.store.GetVault(r.Context(), r.PathValue("vault"))
	if err != nil || v.Purpose != "group" {
		jsonError(w, 404, "Group vault not found")
		return
	}
	role, _ := s.store.GetVaultRole(r.Context(), a.ID, v.ID)
	if c.Owner.ID != a.ID && role != "admin" {
		jsonError(w, 403, "Connection ownership or native destination administration required")
		return
	}
	unlock, err := s.store.LockVault(r.Context(), "connection-policy")
	if err != nil {
		jsonError(w, 500, "Policy lock unavailable")
		return
	}
	defer unlock()
	db, d := s.connectionSQL()
	result, err := db.ExecContext(r.Context(), d.Rebind(`UPDATE connection_grants SET status='revoked' WHERE connection_id=? AND vault_id=? AND status<>'revoked'`), c.ID, v.ID)
	if err != nil {
		jsonError(w, 500, "Detach failed")
		return
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		jsonError(w, 404, "Grant not found")
		return
	}
	if err = s.connectionAudit(r.Context(), r, a.ID, c.ID, v.ID, c.Revision, "detach", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	w.WriteHeader(204)
}
func (s *Server) handleConnectionAccess(w http.ResponseWriter, r *http.Request) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return
	}
	v := s.destinationGroup(w, r, a, true)
	if v == nil {
		return
	}
	bindings, err := s.loadBindings(r.Context(), v.ID)
	if err != nil {
		jsonError(w, 500, "Access read failed")
		return
	}
	items := []accessGrant{}
	for _, b := range bindings {
		if b.status == "revoked" {
			continue
		}
		services := b.services
		for i := range services {
			if b.kind != "static" {
				services[i].Auth.Token = b.handle
			}
		}
		items = append(items, accessGrant{ConnectionID: b.id, Label: b.label, Owner: b.owner, Services: services, Status: b.status})
	}
	jsonOK(w, map[string]any{"grants": items})
}
func (s *Server) handleConnectionDelete(w http.ResponseWriter, r *http.Request) {
	a, c := s.ownedConnection(w, r)
	if c == nil {
		return
	}
	unlock, err := s.store.LockVault(r.Context(), "connection-policy")
	if err != nil {
		jsonError(w, 500, "Policy lock unavailable")
		return
	}
	db, d := s.connectionSQL()
	_, err = db.ExecContext(r.Context(), d.Rebind(`UPDATE connections SET status='disabled',revision=? WHERE id=?`), revision(), c.ID)
	if err == nil {
		_, err = db.ExecContext(r.Context(), d.Rebind(`UPDATE connection_grants SET status='revoked' WHERE connection_id=?`), c.ID)
	}
	unlock()
	if err != nil {
		jsonError(w, 500, "Connection disable failed")
		return
	}
	// Disabling grants precedes network cleanup. A cleanup error retains the
	// disabled state and encrypted account so an operator can retry explicitly.
	if c.Kind != "static" && s.mcpOAuth != nil {
		err = s.mcpOAuth.DisconnectConnection(r.Context(), c.library, c.ID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			jsonCodedError(w, 502, "upstream_cleanup_failed", "Connection disabled, but upstream cleanup failed; retry deletion")
			return
		}
	}
	tx, err := db.BeginTx(r.Context(), nil)
	if err != nil {
		jsonError(w, 500, "Connection delete failed")
		return
	}
	defer tx.Rollback()
	for _, key := range c.Credentials {
		if c.Kind == "static" {
			_, err = tx.ExecContext(r.Context(), d.Rebind(`DELETE FROM credentials WHERE vault_id=? AND key=?`), c.library, connectionKey(c.ID, key))
			if err != nil {
				jsonError(w, 500, "Connection delete failed")
				return
			}
		}
	}
	_, err = tx.ExecContext(r.Context(), d.Rebind(`UPDATE connections SET deleted=1 WHERE id=?`), c.ID)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		jsonError(w, 500, "Connection delete failed")
		return
	}
	if err = s.connectionAudit(r.Context(), r, a.ID, c.ID, "", c.Revision, "delete", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	w.WriteHeader(204)
}
