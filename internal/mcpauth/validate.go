package mcpauth

import (
	"context"
	"fmt"
)

// ValidateModel is read-only. Fork-era provider/catalog or group-owned
// headless data needs a reviewed offline adoption, not a startup converter.
func (m *Manager) ValidateModel(ctx context.Context, managedOnly bool) error {
	ids, err := m.allVaults(ctx)
	if err != nil {
		return err
	}
	for _, vault := range ids {
		accounts, err := m.repo.Accounts(ctx, vault)
		if err != nil {
			return err
		}
		for _, account := range accounts {
			if account.Client.Kind == "app" && account.Client.Config.AuthMethod == "" {
				return fmt.Errorf("unsupported OAuth storage model; reviewed offline adoption is required")
			}
			if account.ConnectionID == "" {
				return fmt.Errorf("unsupported group-owned OAuth state; reviewed revision-7 offline adoption is required")
			}
		}
	}
	if managedOnly {
		var count int
		err = m.repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM gateway_oauth_records r JOIN vaults v ON v.id=r.vault_id WHERE v.purpose<>'library'`).Scan(&count)
		if err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("unsupported group-owned OAuth configuration or pending state; reviewed revision-7 offline adoption is required")
		}
		err = m.repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM credentials c JOIN vaults v ON v.id=c.vault_id WHERE v.purpose<>'library'`).Scan(&count)
		if err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("unsupported group-owned credentials; reviewed revision-7 offline adoption is required")
		}
		err = m.repo.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM broker_configs b JOIN vaults v ON v.id=b.vault_id WHERE v.purpose<>'library' AND b.services_json<>'[]'`).Scan(&count)
		if err != nil {
			return err
		}
		if count != 0 {
			return fmt.Errorf("unsupported group-local credential services; reviewed revision-7 offline adoption is required")
		}
	}
	return nil
}
