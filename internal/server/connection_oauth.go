package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"

	"github.com/Infisical/agent-vault/internal/mcpauth"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

func (s *Server) handleManagedScopeOptions(w http.ResponseWriter, r *http.Request) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return
	}
	if s.mcpOAuth == nil {
		jsonError(w, 503, "OAuth unavailable")
		return
	}
	var in struct {
		ResourceURL string `json:"resource_url"`
		AppID       string `json:"app_id"`
		Issuer      string `json:"issuer"`
	}
	if !decodeManaged(w, r, &in) {
		return
	}
	library, err := s.managedLibrary(r.Context(), a.ID)
	if err != nil {
		jsonError(w, 500, "Personal library unavailable")
		return
	}
	options, err := s.mcpOAuth.DiscoverScopes(r.Context(), library.ID, in.ResourceURL, in.AppID, in.Issuer)
	if s.mcpError(w, err) {
		return
	}
	jsonOK(w, options)
}

func (s *Server) handleConnectionOAuthStart(w http.ResponseWriter, r *http.Request) {
	a, c := s.ownedConnection(w, r)
	if c == nil {
		return
	}
	if s.mcpOAuth == nil {
		jsonError(w, 503, "OAuth unavailable")
		return
	}
	if c.Kind == "static" || c.Status == "disabled" {
		jsonError(w, 409, "Connection is not available for OAuth sign-in")
		return
	}
	var in struct {
		ResourceURL string   `json:"resource_url"`
		AppID       string   `json:"app_id"`
		Scopes      []string `json:"scopes"`
		ClientName  string   `json:"client_name"`
	}
	if !decodeManaged(w, r, &in) {
		return
	}
	clientName, valid := mcpauth.CleanClientName(in.ClientName)
	if !valid {
		jsonCodedError(w, 400, "invalid_client_name", "Client name must be at most 100 characters without control characters")
		return
	}
	// Resource and application identity are immutable. Reconnect cannot silently
	// repurpose a connection or carry old recipients to a different authority.
	if (in.ResourceURL != "" && in.ResourceURL != c.ResourceURL) || (in.AppID != "" && in.AppID != c.AppID) {
		jsonCodedError(w, 409, "connection_identity_conflict", "Create a separate connection for a different resource or OAuth app")
		return
	}
	scopes := in.Scopes
	if scopes == nil {
		scopes = c.RequestedScopes
	}
	scopes, err := mcpauth.CanonicalScopes(scopes)
	if s.mcpError(w, err) {
		return
	}
	previous, err := mcpauth.CanonicalScopes(c.RequestedScopes)
	if s.mcpError(w, err) {
		return
	}
	if !reflect.DeepEqual(scopes, previous) {
		unlock, err := s.store.LockVault(r.Context(), "connection-policy")
		if err != nil {
			jsonError(w, 500, "Policy lock unavailable")
			return
		}
		db, d := s.connectionSQL()
		raw, _ := json.Marshal(scopes)
		_, err = db.ExecContext(r.Context(), d.Rebind(`UPDATE connections SET scopes_json=?,revision=? WHERE id=? AND deleted=0`), string(raw), revision(), c.ID)
		unlock()
		if err != nil {
			jsonError(w, 500, "Scope update failed")
			return
		}
	}
	started, err := s.mcpOAuth.StartConnection(r.Context(), c.library, a.ID, c.ID, c.Kind, c.ResourceURL, c.AppID, clientName, scopes)
	if s.mcpError(w, err) {
		return
	}
	if err = s.connectionAudit(r.Context(), r, a.ID, c.ID, "", c.Revision, "oauth_start", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	jsonOK(w, started)
}

func (s *Server) completeManagedOAuth(w http.ResponseWriter, r *http.Request, input oauthrelay.Input) (bool, *oauthrelay.Result, error) {
	if s.mcpOAuth == nil {
		return false, nil, nil
	}
	flow, err := s.mcpOAuth.ConnectionFlow(r.Context(), input.State)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return true, nil, err
	}
	if flow.ConnectionID == "" {
		return false, nil, nil
	}
	if s.managedTransport(w, r) == nil {
		return true, nil, nil
	}
	authorize := func(_ string) error {
		if input.UserID == "" || input.UserID != flow.ManagedUserID {
			return errManagedOAuthDenied
		}
		user, err := s.store.GetUserByID(r.Context(), input.UserID)
		if err != nil || user.AuthMode != "managed" || !user.IsActive || user.InstallationID == "" || user.Subject == "" {
			return errManagedOAuthDenied
		}
		c, err := s.loadConnection(r.Context(), flow.ConnectionID)
		if err != nil || c.Owner.ID != user.ID || c.library != flow.VaultID || c.Status == "disabled" || c.sourceRevision != flow.ConnectionRevision {
			return errManagedOAuthDenied
		}
		return nil
	}
	result, err := s.mcpOAuth.Complete(r.Context(), input, authorize)
	if err == nil {
		err = s.connectionAudit(r.Context(), r, input.UserID, flow.ConnectionID, "", "", "oauth_complete", result.Status)
	}
	return true, result, err
}

var errManagedOAuthDenied = errors.New("initiating managed user is not authorized to complete this connection")

func (s *Server) managedAppScope(w http.ResponseWriter, r *http.Request, a *Actor) (string, bool) {
	scope := r.URL.Query().Get("scope")
	if scope == "" || scope == "user" {
		library, err := s.managedLibrary(r.Context(), a.ID)
		if err != nil {
			jsonError(w, 500, "Personal library unavailable")
			return "", false
		}
		return library.ID, true
	}
	if scope == "install" && a.IsOwner() {
		return "", true
	}
	jsonError(w, 403, "Install app management requires the effective native owner")
	return "", false
}
func managedAppInfo(info *mcpauth.AppInfo) {
	if info.Source == "vault" {
		info.Source = "user"
	}
	info.AccountsAllVaults = nil
}
func (s *Server) handleManagedApps(w http.ResponseWriter, r *http.Request) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return
	}
	if s.mcpOAuth == nil {
		jsonError(w, 503, "OAuth unavailable")
		return
	}
	library, err := s.managedLibrary(r.Context(), a.ID)
	if err != nil {
		jsonError(w, 500, "Personal library unavailable")
		return
	}
	items, err := s.mcpOAuth.ListApps(r.Context(), library.ID)
	if s.mcpError(w, err) {
		return
	}
	for i := range items {
		managedAppInfo(&items[i])
	}
	jsonOK(w, map[string]any{"items": items})
}
func (s *Server) handleManagedAppPut(w http.ResponseWriter, r *http.Request) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return
	}
	if s.mcpOAuth == nil {
		jsonError(w, 503, "OAuth unavailable")
		return
	}
	scope, ok := s.managedAppScope(w, r, a)
	if !ok {
		return
	}
	var in mcpauth.AppInput
	if !decodeManaged(w, r, &in) {
		return
	}
	item, err := s.mcpOAuth.PutApp(r.Context(), scope, r.PathValue("app"), in)
	if s.mcpError(w, err) {
		return
	}
	managedAppInfo(item)
	if err = s.connectionAudit(r.Context(), r, a.ID, "", scope, "", "oauth_app_update", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	jsonOK(w, item)
}
func (s *Server) handleManagedAppDelete(w http.ResponseWriter, r *http.Request) {
	a := s.effectiveManaged(w, r)
	if a == nil {
		return
	}
	if s.mcpOAuth == nil {
		jsonError(w, 503, "OAuth unavailable")
		return
	}
	scope, ok := s.managedAppScope(w, r, a)
	if !ok {
		return
	}
	if s.mcpError(w, s.mcpOAuth.DeleteApp(r.Context(), scope, r.PathValue("app"))) {
		return
	}
	if err := s.connectionAudit(r.Context(), r, a.ID, "", scope, "", "oauth_app_delete", "ok"); err != nil {
		jsonError(w, 500, "Audit persistence failed")
		return
	}
	w.WriteHeader(204)
}
