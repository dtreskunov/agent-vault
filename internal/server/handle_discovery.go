package server

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Infisical/agent-vault/internal/broker"
)

type discoverService struct {
	ConnectionID      string `json:"connection_id,omitempty"`
	ConnectionKind    string `json:"connection_kind,omitempty"`
	BindingHandle     string `json:"binding_handle,omitempty"`
	Name              string `json:"name"`
	Host              string `json:"host"`
	AccessPlaceholder string `json:"access_placeholder,omitempty"`
	SelectionRequired bool   `json:"selection_required,omitempty"`
}

type discoverResponse struct {
	Vault                string            `json:"vault"`
	Services             []discoverService `json:"services"`
	AvailableCredentials []string          `json:"available_credentials"`
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Require scoped session or agent token with X-Vault.
	sess := sessionFromContext(ctx)
	if sess == nil {
		proxyError(w, http.StatusForbidden, "forbidden", "Discovery requires a vault-scoped session")
		return
	}

	ns, _, err := s.resolveVaultForSession(w, r, sess)
	if err != nil {
		return
	}

	credentialKeys := s.listCredentialKeys(ctx, ns.ID)

	// Load broker config for this vault.
	brokerCfg, err := s.store.GetBrokerConfig(ctx, ns.ID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		proxyError(w, http.StatusInternalServerError, "internal", "Failed to load broker services")
		return
	}

	var svcList []broker.Service
	if brokerCfg != nil {
		if err := json.Unmarshal([]byte(brokerCfg.ServicesJSON), &svcList); err != nil {
			proxyError(w, http.StatusInternalServerError, "internal", "Failed to parse broker services")
			return
		}
	}
	shared, sharedKeys, err := s.sharedDiscovery(ctx, ns.ID)
	if err != nil {
		jsonError(w, 500, "Shared discovery failed")
		return
	}
	credentialKeys = append(credentialKeys, sharedKeys...)
	// MarshalJSON persists Host in joined form; re-split so
	// MatcherPattern emits the same shape regardless of storage form.
	for i := range svcList {
		svcList[i].Host, svcList[i].Path, svcList[i].Port = broker.SplitInlineHost(svcList[i].Host, svcList[i].Path)
	}
	// Heal legacy unnamed entries on the agent-facing read path too —
	// agents identify services by Name (per skill_cli.md) and a blank
	// Name in this response makes the service un-addressable.
	broker.AssignSlugNames(svcList)

	services := make([]discoverService, len(svcList))
	for i, svc := range svcList {
		services[i] = discoverService{
			Name: svc.Name,
			Host: svc.MatcherPattern(),
		}
	}
	services = append(services, shared...)

	jsonOK(w, discoverResponse{
		Vault:                ns.Name,
		Services:             services,
		AvailableCredentials: credentialKeys,
	})
}
