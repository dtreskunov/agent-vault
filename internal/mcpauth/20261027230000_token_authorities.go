package mcpauth

import (
	"github.com/Infisical/agent-vault/internal/store"
	"gorm.io/gorm"
)

func init() {
	store.RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Exec(`CREATE TABLE gateway_oauth_token_authorities (authority TEXT PRIMARY KEY)`).Error
	})
}
