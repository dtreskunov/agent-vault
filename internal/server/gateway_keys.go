package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/statickeys"
	"github.com/Infisical/agent-vault/internal/store"
)

func (s *Server) registerKeyRoutes(mux *http.ServeMux, wrap func(http.HandlerFunc) http.HandlerFunc) {
	if sqlStore, ok := s.store.(interface {
		GatewaySQL() (*sql.DB, store.Dialect)
	}); ok {
		db, d := sqlStore.GatewaySQL()
		s.staticKeys = statickeys.New(db, d, s.encKey)
	}
	mux.HandleFunc("PUT /v1/vaults/{name}/keys/{key}", wrap(s.handleAtomicKey))
	mux.HandleFunc("DELETE /v1/vaults/{name}/keys/{key}", wrap(s.handleAtomicKey))
	mux.HandleFunc("PUT /v1/vaults/{name}/services/{host}", wrap(s.handleSingleServicePut))
}

func (s *Server) handleAtomicKey(w http.ResponseWriter, r *http.Request) {
	if s.staticKeys == nil {
		jsonError(w, 503, "Atomic key API unavailable")
		return
	}
	vault, err := s.store.GetVault(r.Context(), r.PathValue("name"))
	if err != nil || vault == nil {
		jsonError(w, 404, "Vault not found")
		return
	}
	if _, err := s.requireVaultAdmin(w, r, vault.ID); err != nil {
		return
	}
	if !s.assertBuiltinCredentialStore(w, r.Context(), vault.ID, vault.Name) {
		return
	}
	var input struct {
		Value   *string        `json:"value"`
		Service broker.Service `json:"service"`
	}
	if r.Method == "PUT" {
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			jsonError(w, 400, "Invalid request body")
			return
		}
	}
	unlock, err := s.lockVault(r.Context(), vault.ID)
	if err != nil {
		jsonError(w, 500, "Failed to lock vault")
		return
	}
	defer unlock()
	if r.Method == "PUT" {
		err = s.staticKeys.Put(r.Context(), vault.ID, r.PathValue("key"), input.Value, input.Service)
	} else {
		err = s.staticKeys.Delete(r.Context(), vault.ID, r.PathValue("key"))
	}
	if errors.Is(err, statickeys.ErrManaged) || errors.Is(err, statickeys.ErrConflict) {
		jsonError(w, 409, err.Error())
		return
	}
	if errors.Is(err, statickeys.ErrInvalid) {
		jsonError(w, 400, err.Error())
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "Key not found")
		return
	}
	if err != nil {
		s.logger.Error("atomic key update failed", "err", err)
		jsonError(w, 500, "Atomic key update failed")
		return
	}
	if r.Method == "DELETE" {
		w.WriteHeader(204)
		return
	}
	jsonOK(w, map[string]string{"key": r.PathValue("key")})
}

func (s *Server) handleSingleServicePut(w http.ResponseWriter, r *http.Request) {
	vault, err := s.store.GetVault(r.Context(), r.PathValue("name"))
	if err != nil || vault == nil {
		jsonError(w, 404, "Vault not found")
		return
	}
	if _, err := s.requireVaultAdmin(w, r, vault.ID); err != nil {
		return
	}
	var service broker.Service
	if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
		jsonError(w, 400, "Invalid request body")
		return
	}
	if service.Name != "" && service.Name != r.PathValue("host") {
		jsonError(w, 400, "Service name must match the URL")
		return
	}
	service.Name = r.PathValue("host")
	if statickeys.Managed(service.Name) {
		jsonError(w, 409, statickeys.ErrManaged.Error())
		return
	}
	service.Host, service.Path, service.Port = broker.SplitInlineHost(service.Host, service.Path)
	if err := broker.Validate(&broker.Config{Vault: vault.Name, Services: []broker.Service{service}}); err != nil {
		jsonError(w, 400, err.Error())
		return
	}
	unlock, err := s.lockVault(r.Context(), vault.ID)
	if err != nil {
		jsonError(w, 500, "Failed to lock vault")
		return
	}
	defer unlock()
	services, err := s.loadServices(r.Context(), vault.ID)
	if err != nil {
		jsonError(w, 500, "Failed to read services")
		return
	}
	found := false
	for i := range services {
		if services[i].Name == service.Name {
			services[i] = service
			found = true
		}
	}
	if !found {
		services = append(services, service)
	}
	if !s.allowServiceMutation(w, r.Context(), vault.ID, services) {
		return
	}
	data, err := json.Marshal(services)
	if err != nil {
		jsonError(w, 500, "Failed to encode services")
		return
	}
	if _, err := s.store.SetBrokerConfig(r.Context(), vault.ID, string(data)); err != nil {
		jsonError(w, 500, "Failed to save service")
		return
	}
	jsonOK(w, map[string]string{"name": service.Name})
}

func (s *Server) allowServiceMutation(w http.ResponseWriter, ctx context.Context, vault string, after []broker.Service) bool {
	before, err := s.loadServices(ctx, vault)
	if err != nil {
		jsonError(w, 500, "Failed to check managed services")
		return false
	}
	if err := statickeys.Protect(before, after); err != nil {
		jsonError(w, 409, err.Error())
		return false
	}
	if err := broker.ValidateExclusiveHosts(after); err != nil {
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
