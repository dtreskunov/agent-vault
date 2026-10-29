package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/Infisical/agent-vault/internal/gatewayconfig"
	"github.com/Infisical/agent-vault/internal/oauthrelay"
)

func (s *Server) registerOAuthRelay(mux *http.ServeMux, authed func(http.HandlerFunc) http.HandlerFunc) {
	s.registerMCPOAuth(mux, authed)
	mux.HandleFunc("POST /v1/oauth/complete", s.requireInitialized(s.requireAuth(authed(limitBody(s.handleOAuthRelayComplete)))))
	mux.HandleFunc("GET /v1/oauth/client-metadata", s.requireInitialized(s.handleOAuthClientMetadata))
}

func (s *Server) handleOAuthClientMetadata(w http.ResponseWriter, r *http.Request) {
	config, err := oauthrelay.Configuration(s.baseURL)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "OAuth redirect is not configured correctly")
		return
	}
	jsonOK(w, config.Metadata())
}

func (s *Server) handleOAuthRelayComplete(w http.ResponseWriter, r *http.Request) {
	var input oauthrelay.Input
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if handled, result, err := s.completeManagedOAuth(w, r, input); handled {
		if errors.Is(err, errManagedOAuthDenied) {
			jsonCodedError(w, 403, "oauth_user_mismatch", err.Error())
			return
		}
		if s.mcpError(w, err) {
			return
		}
		if result != nil {
			jsonOK(w, result)
		}
		return
	}
	if gatewayconfig.Headless() {
		jsonCodedError(w, 400, "invalid_state", "Unknown managed connection flow")
		return
	}
	config, err := oauthrelay.Configuration(s.baseURL)
	if err != nil {
		jsonError(w, http.StatusServiceUnavailable, "OAuth redirect is not configured correctly")
		return
	}
	denied := false
	result, err := s.completeGatewayOAuth(r, config, input, func(vaultID string) error {
		_, err := s.requireVaultMember(w, r, vaultID)
		denied = err != nil
		return err
	})
	if denied {
		return
	}
	if err != nil && strings.HasPrefix(input.State, "mcp_oast_") {
		s.mcpError(w, err)
		return
	}
	if errors.Is(err, oauthrelay.ErrState) {
		jsonCodedError(w, http.StatusBadRequest, "invalid_state", "Invalid or expired OAuth state")
		return
	}
	if err != nil {
		s.logger.Error("OAuth relay completion failed", "err", err)
		jsonError(w, http.StatusInternalServerError, "OAuth completion failed")
		return
	}
	jsonOK(w, result)
}
