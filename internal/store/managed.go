package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

type ManagedUserInput struct {
	InstallationID string              `json:"installation_id"`
	Subject        string              `json:"subject"`
	DisplayName    string              `json:"display_name"`
	Email          string              `json:"email"`
	Active         bool                `json:"active"`
	Role           string              `json:"role"`
	VaultGrants    []ManagedVaultGrant `json:"vault_grants"`
}

type ManagedVaultGrant struct {
	Vault string `json:"vault"`
	Role  string `json:"role"`
}

type ManagedUserResult struct {
	ID           string `json:"id"`
	LibraryVault string `json:"library_vault"`
}

// ReconcileManagedUser never links users by email. The external identity is
// stored on the native user and its explicit native memberships are replaced
// in the same transaction.
func (s *SQLStore) ReconcileManagedUser(ctx context.Context, in ManagedUserInput) (*ManagedUserResult, error) {
	if strings.TrimSpace(in.InstallationID) == "" || strings.TrimSpace(in.Subject) == "" || (in.Role != "owner" && in.Role != "no-access") {
		return nil, fmt.Errorf("installation_id, subject and owner/no-access role are required")
	}
	unlock, err := s.LockVault(ctx, "managed-user-reconciliation")
	if err != nil {
		return nil, err
	}
	defer unlock()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	q := s.dialect.Rebind
	id := newUUID()
	_, err = tx.ExecContext(ctx, q(`INSERT INTO users (id,email,role,is_active,auth_mode,installation_id,subject,display_name,created_at,updated_at)
		VALUES (?,?,?,?,'managed',?,?,?,?,?) ON CONFLICT(installation_id,subject) DO UPDATE SET
		email=excluded.email,role=excluded.role,is_active=excluded.is_active,display_name=excluded.display_name,updated_at=excluded.updated_at`),
		id, nullableString(in.Email), in.Role, s.dialect.BoolVal(in.Active), in.InstallationID, in.Subject, in.DisplayName, s.now(), s.now())
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, q(`SELECT id FROM users WHERE installation_id=? AND subject=? AND auth_mode='managed'`), in.InstallationID, in.Subject).Scan(&id); err != nil {
		return nil, err
	}
	libraryID, libraryName := newUUID(), "library-"+id
	_, err = tx.ExecContext(ctx, q(`INSERT INTO vaults (id,name,purpose,owner_user_id,created_at,updated_at) VALUES (?,?,'library',?,?,?) ON CONFLICT DO NOTHING`), libraryID, libraryName, id, s.now(), s.now())
	if err != nil {
		return nil, err
	}
	if err = tx.QueryRowContext(ctx, q(`SELECT id,name FROM vaults WHERE owner_user_id=? AND purpose='library'`), id).Scan(&libraryID, &libraryName); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, q(`INSERT INTO broker_configs (id,vault_id,services_json,created_at,updated_at) VALUES (?,?,'[]',?,?) ON CONFLICT(vault_id) DO NOTHING`), newUUID(), libraryID, s.now(), s.now()); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, q(`INSERT INTO vault_grants (actor_id,actor_type,vault_id,role,created_at) VALUES (?,'user',?,'admin',?) ON CONFLICT(actor_id,vault_id) DO UPDATE SET role='admin'`), id, libraryID, s.now()); err != nil {
		return nil, err
	}
	keep := []any{id, libraryID}
	placeholders := []string{"?"}
	seen := map[string]bool{}
	for _, g := range in.VaultGrants {
		if g.Vault == "" || (g.Role != "admin" && g.Role != "proxy") || seen[g.Vault] {
			return nil, fmt.Errorf("invalid or duplicate vault grant")
		}
		seen[g.Vault] = true
		var vault, purpose string
		err = tx.QueryRowContext(ctx, q(`SELECT id,purpose FROM vaults WHERE name=?`), g.Vault).Scan(&vault, &purpose)
		if err == sql.ErrNoRows {
			if g.Vault == "default" || strings.HasPrefix(g.Vault, "library-") {
				return nil, fmt.Errorf("reserved vault")
			}
			vault, purpose = newUUID(), "group"
			if _, err = tx.ExecContext(ctx, q(`INSERT INTO vaults (id,name,purpose,created_at,updated_at) VALUES (?,?,'group',?,?)`), vault, g.Vault, s.now(), s.now()); err != nil {
				return nil, err
			}
			if _, err = tx.ExecContext(ctx, q(`INSERT INTO broker_configs (id,vault_id,services_json,created_at,updated_at) VALUES (?,?,'[]',?,?)`), newUUID(), vault, s.now(), s.now()); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
		if purpose != "group" {
			return nil, fmt.Errorf("only group vaults may be granted")
		}
		if _, err = tx.ExecContext(ctx, q(`INSERT INTO vault_grants (actor_id,actor_type,vault_id,role,created_at) VALUES (?,'user',?,?,?) ON CONFLICT(actor_id,vault_id) DO UPDATE SET role=excluded.role`), id, vault, g.Role, s.now()); err != nil {
			return nil, err
		}
		keep = append(keep, vault)
		placeholders = append(placeholders, "?")
	}
	if _, err = tx.ExecContext(ctx, q(`DELETE FROM vault_grants WHERE actor_id=? AND actor_type='user' AND vault_id NOT IN (`+strings.Join(placeholders, ",")+`)`), keep...); err != nil {
		return nil, err
	}
	// Once authority is lost it must be explicitly reapproved, not resurrected
	// when a later reconciliation restores the native membership.
	if _, err = tx.ExecContext(ctx, q(`UPDATE connection_grants SET status='suspended' WHERE status='active' AND creator_user_id=? AND
		(NOT EXISTS(SELECT 1 FROM users WHERE id=? AND is_active=?) OR NOT EXISTS(
		SELECT 1 FROM vault_grants WHERE actor_id=? AND vault_id=connection_grants.vault_id AND role='admin'))`), id, id, s.dialect.BoolVal(true), id); err != nil {
		return nil, err
	}
	if !in.Active {
		if _, err = tx.ExecContext(ctx, q(`UPDATE connection_grants SET status='suspended' WHERE connection_id IN (SELECT id FROM connections WHERE owner_user_id=?) AND status='active'`), id); err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return &ManagedUserResult{ID: id, LibraryVault: libraryName}, nil
}
