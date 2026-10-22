package statickeys

import (
	"github.com/Infisical/agent-vault/internal/store"
	"gorm.io/gorm"
)

func init() {
	store.RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE gateway_credential_usage (
		credential_id TEXT PRIMARY KEY REFERENCES credentials(id) ON DELETE CASCADE,
		last_used_at BIGINT NOT NULL
	)`).Error
	})
}
