package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/statickeys"
)

var keySetRevision = regexp.MustCompile(`^"[a-f0-9]{64}"$`)

func (s *Server) handleAtomicKeySet(w http.ResponseWriter, r *http.Request) {
	if s.staticKeys == nil {
		jsonError(w, 503, "Atomic key-set API unavailable")
		return
	}
	vault, err := s.store.GetVault(r.Context(), r.PathValue("name"))
	if err != nil || vault == nil {
		jsonError(w, 404, "Vault not found")
		return
	}
	if r.Method == "GET" {
		if _, err := s.requireVaultMember(w, r, vault.ID); err != nil {
			return
		}
	} else if _, err := s.requireVaultAdmin(w, r, vault.ID); err != nil {
		return
	}
	if !s.assertBuiltinCredentialStore(w, r.Context(), vault.ID, vault.Name) {
		return
	}
	var input struct {
		Values  map[string]string `json:"values,omitempty"`
		Service broker.Service    `json:"service"`
	}
	createOnly := false
	revision := strings.TrimSpace(r.Header.Get("If-Match"))
	if r.Method != "GET" {
		none := strings.TrimSpace(r.Header.Get("If-None-Match"))
		if len(r.Header.Values("If-Match")) > 1 || len(r.Header.Values("If-None-Match")) > 1 {
			jsonError(w, http.StatusPreconditionRequired, "Supply one exact conditional header")
			return
		}
		if r.Method == "PUT" && none == "*" && revision == "" {
			createOnly = true
		} else if none != "" || !keySetRevision.MatchString(revision) {
			jsonError(w, http.StatusPreconditionRequired, "Create requires If-None-Match: *; edit/delete requires one exact If-Match revision")
			return
		}
	}
	if r.Method == "PUT" {
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&input); err != nil {
			jsonError(w, 400, "Invalid key-set body")
			return
		}
		if err := decoder.Decode(&struct{}{}); err != io.EOF {
			jsonError(w, 400, "Invalid key-set body")
			return
		}
		if input.Service.Name != "" && input.Service.Name != r.PathValue("set") {
			jsonError(w, 400, "Service name must match the key-set URL")
			return
		}
		input.Service.Name = r.PathValue("set")
	}
	unlock, err := s.lockVault(r.Context(), vault.ID)
	if err != nil {
		jsonError(w, 500, "Failed to lock vault")
		return
	}
	defer unlock()
	var result *statickeys.SetInfo
	switch r.Method {
	case "GET":
		result, err = s.staticKeys.GetSet(r.Context(), vault.ID, r.PathValue("set"))
	case "PUT":
		result, err = s.staticKeys.PutSet(r.Context(), vault.ID, input.Service, input.Values, createOnly, revision)
	case "DELETE":
		err = s.staticKeys.DeleteSet(r.Context(), vault.ID, r.PathValue("set"), revision)
	}
	switch {
	case errors.Is(err, statickeys.ErrPrecondition):
		jsonError(w, http.StatusPreconditionFailed, err.Error())
		return
	case errors.Is(err, statickeys.ErrManaged), errors.Is(err, statickeys.ErrConflict):
		jsonError(w, 409, err.Error())
		return
	case errors.Is(err, statickeys.ErrInvalid):
		jsonError(w, 400, err.Error())
		return
	case errors.Is(err, sql.ErrNoRows):
		jsonError(w, 404, "Key set not found")
		return
	case err != nil:
		s.logger.Error("atomic key-set operation failed", "err", err)
		jsonError(w, 500, "Atomic key-set operation failed")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "DELETE" {
		w.WriteHeader(204)
		return
	}
	w.Header().Set("ETag", result.Revision)
	jsonOK(w, result)
}
