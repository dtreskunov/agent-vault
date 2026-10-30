package store

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"
)

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		return db.Transaction(func(tx *gorm.DB) error {
			authority := `SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_user_id
				JOIN vault_grants vg ON vg.actor_id=u.id AND vg.actor_type='user' AND vg.vault_id=NEW.vault_id AND vg.role='admin'
				WHERE c.id=NEW.connection_id AND u.id=NEW.creator_user_id AND u.is_active AND c.deleted=0`
			var statements []string
			if tx.Name() == "sqlite" {
				statements = []string{
					`DROP TRIGGER connection_grant_authority`,
					`DROP TRIGGER connection_grant_authority_update`,
					`CREATE TRIGGER connection_grant_authority BEFORE INSERT ON connection_grants
						WHEN NEW.status='active' AND NOT EXISTS (` + authority + `)
						BEGIN SELECT RAISE(ABORT,'active grants require native owner and destination admin authority'); END`,
					`CREATE TRIGGER connection_grant_authority_update BEFORE UPDATE ON connection_grants
						WHEN NEW.status='active' AND NOT EXISTS (` + authority + `)
						BEGIN SELECT RAISE(ABORT,'active grants require native owner and destination admin authority'); END`,
				}
			} else {
				statements = []string{
					`CREATE OR REPLACE FUNCTION enforce_connection_grant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
						IF NOT EXISTS(SELECT 1 FROM vaults v JOIN connections c ON c.id=NEW.connection_id
							WHERE v.id=NEW.vault_id AND v.purpose='group' AND c.owner_user_id=NEW.creator_user_id)
							THEN RAISE EXCEPTION 'connection grants require a group and native owner'; END IF;
						IF NEW.status='active' AND NOT EXISTS (` + authority + `)
							THEN RAISE EXCEPTION 'active grants require native owner and destination admin authority'; END IF;
						RETURN NEW; END $$`,
				}
			}
			for _, statement := range statements {
				if err := tx.Exec(statement).Error; err != nil {
					return err
				}
			}
			var connections []struct {
				ID       string
				Services string
				Revision string
			}
			if err := tx.Raw(`SELECT DISTINCT c.id,c.services_json AS services,c.revision FROM connections c
				JOIN connection_grants g ON g.connection_id=c.id WHERE g.status<>'revoked'`).Scan(&connections).Error; err != nil {
				return err
			}
			for _, c := range connections {
				var rules []struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal([]byte(c.Services), &rules); err != nil {
					return fmt.Errorf("expand connection grants %s: %w", c.ID, err)
				}
				names := make([]string, 0, len(rules))
				for _, rule := range rules {
					names = append(names, rule.Name)
				}
				raw, err := json.Marshal(names)
				if err != nil {
					return err
				}
				if err := tx.Exec(`UPDATE connection_grants SET services_json=?,bound_services_json=?,approved_revision=?
					WHERE connection_id=? AND status<>'revoked'`, string(raw), c.Services, c.Revision, c.ID).Error; err != nil {
					return err
				}
			}
			return nil
		})
	})
}
