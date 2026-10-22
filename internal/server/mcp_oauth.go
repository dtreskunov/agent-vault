package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Infisical/agent-vault/internal/mcpauth"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
	"github.com/Infisical/agent-vault/internal/store"
)

func (s *Server) registerMCPOAuth(mux *http.ServeMux, authed func(http.HandlerFunc) http.HandlerFunc) {
	if access, ok := s.store.(interface {
		GatewaySQL() (*sql.DB, store.Dialect)
	}); ok {
		if config, err := oauthrelay.Configuration(s.baseURL); err == nil {
			db, dialect := access.GatewaySQL()
			s.mcpOAuth = mcpauth.New(s.store, mcpauth.NewRepository(db, dialect, s.encKey), config, s.logger)
		} else {
			s.logger.Error("MCP OAuth configuration invalid", "err", err)
		}
	}
	wrap := func(handler http.HandlerFunc) http.HandlerFunc {
		return s.requireInitialized(s.requireAuth(authed(limitBody(handler))))
	}
	mux.HandleFunc("POST /v1/vaults/{name}/mcp-oauth/start", wrap(s.handleMCPOAuthStart))
	mux.HandleFunc("POST /v1/vaults/{name}/mcp-oauth/probe", wrap(s.handleMCPOAuthProbe))
	mux.HandleFunc("GET /v1/vaults/{name}/mcp-oauth", wrap(s.handleMCPOAuthList))
	mux.HandleFunc("DELETE /v1/vaults/{name}/mcp-oauth/{key}", wrap(s.handleMCPOAuthDelete))
}

func (s *Server) mcpVault(w http.ResponseWriter, r *http.Request, mutate bool) *store.Vault {
	if s.mcpOAuth == nil {
		jsonError(w, http.StatusServiceUnavailable, "MCP OAuth is unavailable")
		return nil
	}
	vault, err := s.store.GetVault(r.Context(), r.PathValue("name"))
	if err != nil || vault == nil {
		jsonError(w, http.StatusNotFound, "Vault not found")
		return nil
	}
	if mutate {
		_, err = s.requireVaultAdmin(w, r, vault.ID)
	} else {
		_, err = s.requireVaultMember(w, r, vault.ID)
	}
	if err != nil {
		return nil
	}
	return vault
}

func (s *Server) handleMCPOAuthStart(w http.ResponseWriter, r *http.Request) {
	vault := s.mcpVault(w, r, true)
	if vault == nil || !s.assertBuiltinCredentialStore(w, r.Context(), vault.ID, vault.Name) {
		return
	}
	var input struct {
		ResourceURL string `json:"resource_url"`
		ClientName  string `json:"client_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	name, ok := mcpauth.CleanClientName(input.ClientName)
	if !ok {
		jsonCodedError(w, http.StatusBadRequest, "invalid_client_name", "client_name must be 1-100 printable characters")
		return
	}
	started, err := s.mcpOAuth.StartNamed(r.Context(), vault.ID, input.ResourceURL, name)
	if s.mcpError(w, err) {
		return
	}
	jsonOK(w, started)
}

func (s *Server) handleMCPOAuthProbe(w http.ResponseWriter, r *http.Request) {
	vault := s.mcpVault(w, r, false)
	if vault == nil {
		return
	}
	var input struct {
		ResourceURL string `json:"resource_url"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	probe, err := s.mcpOAuth.Probe(r.Context(), vault.ID, input.ResourceURL)
	if s.mcpError(w, err) {
		return
	}
	jsonOK(w, probe)
}

func (s *Server) handleMCPOAuthList(w http.ResponseWriter, r *http.Request) {
	vault := s.mcpVault(w, r, false)
	if vault == nil {
		return
	}
	items, err := s.mcpOAuth.List(r.Context(), vault.ID)
	if s.mcpError(w, err) {
		return
	}
	jsonOK(w, items)
}

func (s *Server) handleMCPOAuthDelete(w http.ResponseWriter, r *http.Request) {
	vault := s.mcpVault(w, r, true)
	if vault == nil {
		return
	}
	err := s.mcpOAuth.Disconnect(r.Context(), vault.ID, r.PathValue("key"))
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusNotFound, "MCP OAuth account not found")
		return
	}
	if s.mcpError(w, err) {
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) mcpError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var failure *mcpauth.Failure
	if errors.As(err, &failure) {
		status := http.StatusBadRequest
		if failure.Code == "service_conflict" || failure.Code == "credential_conflict" {
			status = http.StatusConflict
		}
		jsonStatus(w, status, failure)
	} else {
		s.logger.Error("MCP OAuth operation failed", "err", err)
		jsonError(w, http.StatusInternalServerError, "MCP OAuth operation failed")
	}
	return true
}

func (s *Server) completeGatewayOAuth(r *http.Request, config oauthrelay.Config, input oauthrelay.Input, authorize func(string) error) (*oauthrelay.Result, error) {
	if strings.HasPrefix(input.State, "mcp_oast_") {
		if s.mcpOAuth == nil {
			return nil, fmt.Errorf("MCP OAuth is unavailable")
		}
		return s.mcpOAuth.Complete(r.Context(), input, authorize)
	}
	return oauthrelay.Complete(r.Context(), s.store, s.encKey, config, input, authorize)
}

func (s *Server) mcpBrowserCallback(w http.ResponseWriter, r *http.Request, state string) bool {
	if !strings.HasPrefix(state, "mcp_oast_") {
		return false
	}
	if s.mcpOAuth == nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "MCP OAuth is unavailable")
		return true
	}
	result, err := s.mcpOAuth.Complete(r.Context(), oauthrelay.Input{State: state,
		Code: r.URL.Query().Get("code"), Issuer: r.URL.Query().Get("iss"), Error: r.URL.Query().Get("error")}, nil)
	if err != nil {
		s.redirectOAuthComplete(w, r, "", "", "error", "MCP OAuth completion failed")
		return true
	}
	status := "success"
	if result.Status != "connected" {
		status = "error"
	}
	s.redirectOAuthComplete(w, r, result.Vault, result.Key, status, result.Error)
	return true
}

type gatewayCredentialStore struct {
	credentialStoreAdapter
	manager *mcpauth.Manager
}

func (a gatewayCredentialStore) GetCredential(ctx context.Context, vault, key string) (*store.Credential, error) {
	credential, err := a.Store.GetCredential(ctx, vault, key)
	if err != nil || credential == nil || credential.Type != "mcp_oauth" {
		return credential, err
	}
	if a.manager == nil {
		return nil, fmt.Errorf("MCP OAuth is unavailable")
	}
	return a.manager.Credential(ctx, vault, key)
}

func (s *Server) FilterMCPResponse(ctx context.Context, vault string, keys []string, headers http.Header) error {
	if s.mcpOAuth == nil {
		return nil
	}
	return s.mcpOAuth.FilterChallenge(ctx, vault, keys, headers)
}

func (s *Server) deleteGatewayVault(ctx context.Context, vault, name string) error {
	if s.mcpOAuth == nil {
		return s.store.DeleteVault(ctx, name)
	}
	unlock, err := s.store.LockVault(ctx, vault)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.mcpOAuth.CleanupVault(ctx, vault); err != nil {
		return err
	}
	return s.store.DeleteVault(ctx, name)
}

func (s *Server) assertNotMCPManaged(w http.ResponseWriter, ctx context.Context, vault, key string) bool {
	if !strings.HasPrefix(key, "MCP_") {
		return true
	}
	credential, err := s.store.GetCredential(ctx, vault, key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		jsonError(w, http.StatusInternalServerError, "Failed to check managed credential")
		return false
	}
	if credential != nil && credential.Type == "mcp_oauth" {
		jsonCodedError(w, http.StatusConflict, "mcp_managed_credential", "Manage this credential through the MCP OAuth account endpoint")
		return false
	}
	return true
}

func (s *Server) lockCredentialMutation(w http.ResponseWriter, ctx context.Context, vault string) (func(), bool) {
	unlock, err := s.store.LockVault(ctx, vault)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "Failed to lock credential mutation")
		return nil, false
	}
	return unlock, true
}
