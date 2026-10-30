package mcpauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"slices"

	"github.com/Infisical/agent-vault/internal/broker"
)

type managedFlowKey struct{}
type managedFlowIdentity struct {
	User, Connection string
	Scopes           []string
}

func clientRecordKey(ctx context.Context, issuer string) string {
	if identity, ok := ctx.Value(managedFlowKey{}).(managedFlowIdentity); ok {
		return digest(issuer + "\x00" + identity.Connection)
	}
	return digest(issuer)
}

// StartConnection reuses discovery, configured apps, PKCE and encrypted OAuth
// records but pins the native connection key instead of guessing an account by
// resource or provider identity.
func (m *Manager) StartConnection(ctx context.Context, vault, user, id, kind, resource, app, clientName string, scopes []string) (*Started, error) {
	clientName, valid := CleanClientName(clientName)
	if !valid {
		return nil, failure("invalid_client_name", "Client name must be at most 100 characters without control characters")
	}
	if clientName == "" {
		clientName = "AgentVault"
	}
	ctx = context.WithValue(ctx, managedFlowKey{}, managedFlowIdentity{User: user, Connection: id, Scopes: scopes})
	if kind == "oauth_app" {
		return m.StartAccount(ctx, vault, app, scopes, "")
	}
	if kind != "mcp_oauth" {
		return nil, failure("invalid_connection", "Connection is not OAuth")
	}
	return m.StartNamed(ctx, vault, resource, clientName, app)
}
func (m *Manager) ConnectionFlow(ctx context.Context, state string) (*Flow, error) {
	return m.repo.Flow(ctx, state)
}
func (m *Manager) ConnectionAccount(ctx context.Context, vault, id string) (*Account, error) {
	return m.repo.Account(ctx, vault, id)
}

// syncConnectionAccount runs in the same transaction as the authoritative
// encrypted token/client state. Scope or identity expansion can therefore never
// race a subsequent injection using an old approved revision.
func (r *Repository) syncConnectionAccount(ctx context.Context, tx *sql.Tx, vault string, a *Account, connect bool) error {
	var oldStatus, oldRevision string
	err := tx.QueryRowContext(ctx, r.dialect.Rebind(`SELECT status,revision FROM connections WHERE id=? AND library_vault_id=? AND deleted=0`), a.Key, vault).Scan(&oldStatus, &oldRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var old Account
	var ct, nonce []byte
	err = tx.QueryRowContext(ctx, r.dialect.Rebind(`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE vault_id=? AND kind='account' AND record_key=?`), vault, a.Key).Scan(&ct, &nonce)
	existed := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if existed {
		if err = r.decode(ct, nonce, &old); err != nil {
			return err
		}
	}
	authorityChanged := existed && (old.Issuer != a.Issuer || old.Resource != a.Resource || old.ResourceURL != a.ResourceURL || old.Client.ID != a.Client.ID ||
		old.Metadata.TokenEndpoint != a.Metadata.TokenEndpoint || old.Metadata.AuthorizationEndpoint != a.Metadata.AuthorizationEndpoint ||
		old.Client.Kind != a.Client.Kind || old.Client.AppID != a.Client.AppID || old.Client.Source != a.Client.Source ||
		!reflect.DeepEqual(old.APIHosts, a.APIHosts) || old.Subject != a.Subject ||
		(old.Identity != nil && a.Identity != nil && *old.Identity != *a.Identity) || scopeExpansion(old, *a) ||
		(connect && (old.Subject == "" || a.Subject == "")))
	services, err := a.services()
	if err != nil {
		return err
	}
	if err = broker.Validate(&broker.Config{Vault: vault, Services: services}); err != nil {
		return err
	}
	raw, _ := json.Marshal(services)
	keys, _ := json.Marshal([]string{a.Key})
	scopes, _ := json.Marshal(a.RequestedScopes)
	status := "ready"
	if a.Reconnect || a.AccessToken == "" {
		status = "needs_reconnect"
	}
	if oldStatus == "disabled" {
		status = "disabled"
	}
	nextRevision := oldRevision
	if authorityChanged {
		nextRevision = `"` + rand.Text() + `"`
	}
	_, err = tx.ExecContext(ctx, r.dialect.Rebind(`UPDATE connections SET status=?,revision=?,services_json=?,keys_json=?,scopes_json=? WHERE id=? AND deleted=0`),
		status, nextRevision, string(raw), string(keys), string(scopes), a.Key)
	if err != nil {
		return err
	}
	if authorityChanged || a.Reconnect {
		_, err = tx.ExecContext(ctx, r.dialect.Rebind(`UPDATE connection_grants SET status='suspended' WHERE connection_id=? AND status='active'`), a.Key)
	}
	return err
}
func scopeExpansion(old, next Account) bool {
	before, after := old.GrantedScopes, next.GrantedScopes
	if old.ScopeSource != "provider" {
		before = old.RequestedScopes
	}
	if next.ScopeSource != "provider" {
		after = next.RequestedScopes
	}
	for _, scope := range after {
		if !slices.Contains(before, scope) {
			return true
		}
	}
	return old.ScopeSource == "provider" && next.ScopeSource != "provider"
}
