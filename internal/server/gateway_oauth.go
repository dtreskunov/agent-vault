package server

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/mcpauth"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
	"github.com/Infisical/agent-vault/internal/statickeys"
	"github.com/Infisical/agent-vault/internal/store"
)

func (s *Server) registerMCPOAuth(mux *http.ServeMux, authed func(http.HandlerFunc) http.HandlerFunc) {
	if access, ok := s.store.(interface {
		GatewaySQL() (*sql.DB, store.Dialect)
	}); ok {
		db, d := access.GatewaySQL()
		s.staticKeys = statickeys.New(db, d, s.encKey)
		if config, err := oauthrelay.Configuration(s.baseURL); err == nil {
			s.mcpOAuth = mcpauth.New(s.store, mcpauth.NewRepository(db, d, s.encKey), config, s.logger)
		} else {
			s.logger.Error("OAuth configuration invalid", "err", err)
		}
	}
	wrap := func(handler http.HandlerFunc) http.HandlerFunc {
		return s.requireInitialized(s.requireAuth(authed(limitBody(handler))))
	}
	s.registerManaged(mux, wrap)
}

func (s *Server) mcpError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	var failure *mcpauth.Failure
	if errors.As(err, &failure) {
		status := http.StatusBadRequest
		if failure.Code == "service_conflict" || failure.Code == "credential_conflict" || failure.Code == "ambiguous_app" {
			status = http.StatusConflict
		}
		if failure.Code == "revision_conflict" {
			status = http.StatusPreconditionFailed
		}
		jsonStatus(w, status, failure)
	} else {
		s.logger.Error("OAuth operation failed", "err", err)
		jsonError(w, http.StatusInternalServerError, "OAuth operation failed")
	}
	return true
}
func (s *Server) completeGatewayOAuth(r *http.Request, config oauthrelay.Config, input oauthrelay.Input, authorize func(string) error) (*oauthrelay.Result, error) {
	if strings.HasPrefix(input.State, "mcp_oast_") {
		return nil, fmt.Errorf("connection OAuth requires its initiating managed user")
	}
	return oauthrelay.Complete(r.Context(), s.store, s.encKey, config, input, authorize)
}
func (s *Server) mcpBrowserCallback(w http.ResponseWriter, r *http.Request, state string) bool {
	if !strings.HasPrefix(state, "mcp_oast_") {
		return false
	}
	s.redirectOAuthComplete(w, r, "", "", "error", "Connection OAuth must complete through the authenticated initiating host user")
	return true
}

type gatewayCredentialStore struct {
	credentialStoreAdapter
	usage *statickeys.Repository
}

func (a gatewayCredentialStore) GetCredential(ctx context.Context, vault, key string) (*store.Credential, error) {
	credential, err := a.Store.GetCredential(ctx, vault, key)
	if err == nil && credential != nil && credential.Type == "static" && a.usage != nil {
		if err := a.usage.Touch(ctx, credential); err != nil {
			return nil, err
		}
	}
	if credential != nil && (credential.Type == "mcp_oauth" || credential.Type == "oauth_app") {
		return nil, fmt.Errorf("OAuth connections resolve only through an authorized group binding")
	}
	return credential, err
}
func (s *Server) FilterMCPResponse(ctx context.Context, vault string, keys []string, headers http.Header) error {
	if s.mcpOAuth == nil {
		return nil
	}
	bindings, err := s.loadBindings(ctx, vault)
	if err != nil {
		return err
	}
	for _, b := range bindings {
		if b.kind != "mcp_oauth" || !slices.Contains(keys, b.id) {
			continue
		}
		if err = s.authorizeBinding(ctx, vault, b); err != nil {
			return err
		}
		return s.mcpOAuth.FilterManagedChallenge(headers)
	}
	return nil
}
func (s *Server) deleteGatewayVault(ctx context.Context, vault, name string) error {
	v, err := s.store.GetVaultByID(ctx, vault)
	if err != nil {
		return err
	}
	if v.Purpose == "library" {
		return fmt.Errorf("personal libraries cannot be deleted as group vaults")
	}
	if err = s.store.DeleteVault(ctx, name); err != nil {
		return err
	}
	if s.socketSessions != nil {
		return s.socketSessions.RevokeVault(ctx, vault)
	}
	return nil
}
func (s *Server) assertNotMCPManaged(w http.ResponseWriter, ctx context.Context, vault, key string) bool {
	if !strings.HasPrefix(key, "CONN_") && !strings.HasPrefix(key, "MCP_") && !strings.HasPrefix(key, "OAUTH_") {
		return true
	}
	credential, err := s.store.GetCredential(ctx, vault, key)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 500, "Failed to check managed credential")
		return false
	}
	if credential != nil && (credential.Type == "mcp_oauth" || credential.Type == "oauth_app") {
		jsonCodedError(w, 409, "managed_connection", "Manage this credential through its user-owned connection")
		return false
	}
	return true
}
func (s *Server) lockCredentialMutation(w http.ResponseWriter, ctx context.Context, vault string) (func(), bool) {
	unlock, err := s.store.LockVault(ctx, vault)
	if err != nil {
		jsonError(w, 500, "Failed to lock credential mutation")
		return nil, false
	}
	return unlock, true
}
func (s *Server) allowServiceMutation(w http.ResponseWriter, ctx context.Context, vault string, after []broker.Service) bool {
	before, err := s.loadServices(ctx, vault)
	if err != nil {
		jsonError(w, 500, "Failed to check managed services")
		return false
	}
	if err = statickeys.Protect(before, after); err != nil {
		jsonError(w, 409, err.Error())
		return false
	}
	if err = broker.ValidateExclusiveHosts(after); err != nil {
		jsonCodedError(w, 409, "service_conflict", err.Error())
		return false
	}
	for _, service := range after {
		if statickeys.Managed(service.Name) {
			continue
		}
		for _, key := range service.CredentialKeys() {
			if !s.assertNotMCPManaged(w, ctx, vault, key) {
				return false
			}
		}
	}
	return true
}
func (s *Server) credentialMetadata(ctx context.Context, vault string, entries []credentialEntry) error {
	if s.staticKeys == nil {
		return nil
	}
	usage, err := s.staticKeys.Usage(ctx, vault)
	if err != nil {
		return err
	}
	for i := range entries {
		entries[i].LastUsedAt = usage[entries[i].Key]
	}
	return nil
}
