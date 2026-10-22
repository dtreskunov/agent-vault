package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Infisical/agent-vault/internal/mcpauth"
)

func (s *Server) registerOAuthApps(mux *http.ServeMux, wrap func(http.HandlerFunc) http.HandlerFunc) {
	for _, base := range []string{"/v1/oauth-apps/{provider}", "/v1/vaults/{name}/oauth-apps/{provider}"} {
		for _, method := range []string{"GET", "PUT", "DELETE"} {
			mux.HandleFunc(method+" "+base, wrap(s.handleOAuthApp))
		}
	}
	mux.HandleFunc("GET /v1/oauth/providers", wrap(func(w http.ResponseWriter, r *http.Request) {
		if _, err := s.requireInstanceMember(w, r); err != nil {
			return
		}
		jsonOK(w, mcpauth.Catalog())
	}))
	mux.HandleFunc("POST /v1/vaults/{name}/oauth-accounts/start", wrap(s.handleProviderAccountStart))
	mux.HandleFunc("GET /v1/vaults/{name}/oauth-accounts", wrap(s.handleProviderAccounts))
	mux.HandleFunc("DELETE /v1/vaults/{name}/oauth-accounts/{key}", wrap(s.handleProviderAccountDelete))
}

func (s *Server) handleOAuthApp(w http.ResponseWriter, r *http.Request) {
	if s.mcpOAuth == nil {
		jsonError(w, 503, "OAuth apps unavailable")
		return
	}
	vault := ""
	if r.PathValue("name") == "" {
		if _, err := s.requireOwnerActor(w, r); err != nil {
			return
		}
	} else {
		v := s.mcpVault(w, r, r.Method != "GET")
		if v == nil {
			return
		}
		vault = v.ID
	}
	provider := r.PathValue("provider")
	switch r.Method {
	case "GET":
		info, err := s.mcpOAuth.GetApp(r.Context(), vault, provider)
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, 404, "OAuth app not configured")
			return
		}
		if s.mcpError(w, err) {
			return
		}
		jsonOK(w, info)
	case "PUT":
		var input mcpauth.AppInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			jsonError(w, 400, "Invalid request body")
			return
		}
		info, err := s.mcpOAuth.PutApp(r.Context(), vault, provider, input)
		if s.mcpError(w, err) {
			return
		}
		jsonOK(w, info)
	case "DELETE":
		err := s.mcpOAuth.DeleteApp(r.Context(), vault, provider)
		if errors.Is(err, sql.ErrNoRows) {
			jsonError(w, 404, "OAuth app not configured")
			return
		}
		if s.mcpError(w, err) {
			return
		}
		w.WriteHeader(204)
	}
}

func (s *Server) handleProviderAccountStart(w http.ResponseWriter, r *http.Request) {
	v := s.mcpVault(w, r, true)
	if v == nil || !s.assertBuiltinCredentialStore(w, r.Context(), v.ID, v.Name) {
		return
	}
	var input struct {
		Provider   string   `json:"provider"`
		ScopeSets  []string `json:"scope_sets"`
		ReplaceKey string   `json:"replace_key,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		jsonError(w, 400, "Invalid request body")
		return
	}
	start, err := s.mcpOAuth.StartProvider(r.Context(), v.ID, input.Provider, input.ScopeSets, input.ReplaceKey)
	if s.mcpError(w, err) {
		return
	}
	jsonOK(w, start)
}

func (s *Server) handleProviderAccounts(w http.ResponseWriter, r *http.Request) {
	v := s.mcpVault(w, r, false)
	if v == nil {
		return
	}
	accounts, err := s.mcpOAuth.List(r.Context(), v.ID)
	if s.mcpError(w, err) {
		return
	}
	providerAccounts := make([]mcpauth.AccountInfo, 0)
	for _, a := range accounts {
		if a.Kind == "oauth_app" {
			providerAccounts = append(providerAccounts, a)
		}
	}
	jsonOK(w, providerAccounts)
}

func (s *Server) handleProviderAccountDelete(w http.ResponseWriter, r *http.Request) {
	v := s.mcpVault(w, r, true)
	if v == nil {
		return
	}
	if len(r.PathValue("key")) < 6 || r.PathValue("key")[:6] != "OAUTH_" {
		jsonError(w, 404, "OAuth account not found")
		return
	}
	err := s.mcpOAuth.Disconnect(r.Context(), v.ID, r.PathValue("key"))
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "OAuth account not found")
		return
	}
	if s.mcpError(w, err) {
		return
	}
	w.WriteHeader(204)
}
