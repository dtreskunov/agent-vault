package mcpauth

import (
	"github.com/Infisical/agent-vault/internal/store"
	"gorm.io/gorm"
)

func init() {
	store.RegisterGORMMigration(func(db *gorm.DB) error {
		bytes := "BLOB"
		if db.Name() == "postgres" {
			bytes = "BYTEA"
		}
		if err := db.Exec(`CREATE TABLE gateway_oauth_records (
			vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
			kind TEXT NOT NULL,
			record_key TEXT NOT NULL,
			ciphertext ` + bytes + ` NOT NULL,
			nonce ` + bytes + ` NOT NULL,
			expires_at BIGINT NOT NULL DEFAULT 0,
			account_key TEXT NOT NULL DEFAULT '',
			PRIMARY KEY (vault_id, kind, record_key)
		)`).Error; err != nil {
			return err
		}
		return db.Exec(`CREATE INDEX gateway_oauth_record_lookup ON gateway_oauth_records(kind, record_key)`).Error
	})
}
