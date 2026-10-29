package store

import "gorm.io/gorm"

func init() {
	RegisterGORMMigration(func(db *gorm.DB) error {
		var statements []string
		if db.Name() == "sqlite" {
			statements = []string{
				`CREATE TABLE users_managed (
					id TEXT PRIMARY KEY, email TEXT, password_hash BLOB, password_salt BLOB,
					role TEXT NOT NULL DEFAULT 'no-access' CHECK(role IN ('owner','member','no-access')),
					created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
					kdf_time INTEGER NOT NULL DEFAULT 3, kdf_memory INTEGER NOT NULL DEFAULT 65536,
					kdf_threads INTEGER NOT NULL DEFAULT 4, is_active INTEGER NOT NULL DEFAULT 0,
					auth_mode TEXT NOT NULL DEFAULT 'local' CHECK(auth_mode IN ('local','managed')),
					installation_id TEXT, subject TEXT, display_name TEXT NOT NULL DEFAULT '',
					UNIQUE(installation_id,subject),
					CHECK((auth_mode='local' AND email IS NOT NULL AND password_hash IS NOT NULL AND password_salt IS NOT NULL AND installation_id IS NULL AND subject IS NULL)
						OR (auth_mode='managed' AND password_hash IS NULL AND password_salt IS NULL AND installation_id IS NOT NULL AND subject IS NOT NULL AND length(installation_id)>0 AND length(subject)>0)))`,
				`INSERT INTO users_managed (id,email,password_hash,password_salt,role,created_at,updated_at,kdf_time,kdf_memory,kdf_threads,is_active)
					SELECT id,email,password_hash,password_salt,role,created_at,updated_at,kdf_time,kdf_memory,kdf_threads,is_active FROM users`,
				`DROP TABLE users`, `ALTER TABLE users_managed RENAME TO users`,
			}
		} else {
			statements = []string{
				`ALTER TABLE users ALTER COLUMN email DROP NOT NULL, ALTER COLUMN password_hash DROP NOT NULL, ALTER COLUMN password_salt DROP NOT NULL`,
				`ALTER TABLE users DROP CONSTRAINT IF EXISTS users_email_key`,
				`ALTER TABLE users ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'local', ADD COLUMN installation_id TEXT, ADD COLUMN subject TEXT, ADD COLUMN display_name TEXT NOT NULL DEFAULT ''`,
				`ALTER TABLE users ADD CONSTRAINT users_managed_identity UNIQUE(installation_id,subject),
					ADD CONSTRAINT users_auth_mode CHECK(auth_mode IN ('local','managed')),
					ADD CONSTRAINT users_auth_material CHECK(
						(auth_mode='local' AND email IS NOT NULL AND password_hash IS NOT NULL AND password_salt IS NOT NULL AND installation_id IS NULL AND subject IS NULL)
						OR (auth_mode='managed' AND password_hash IS NULL AND password_salt IS NULL AND installation_id IS NOT NULL AND length(installation_id)>0 AND subject IS NOT NULL AND length(subject)>0))`,
			}
		}
		statements = append(statements,
			`CREATE UNIQUE INDEX users_local_email ON users(email) WHERE auth_mode='local'`,
			`ALTER TABLE vaults ADD COLUMN purpose TEXT NOT NULL DEFAULT 'group' CHECK(purpose IN ('group','system','library'))`,
			`ALTER TABLE vaults ADD COLUMN owner_user_id TEXT REFERENCES users(id)`,
			`CREATE UNIQUE INDEX vaults_user_library ON vaults(owner_user_id) WHERE purpose='library'`,
			`UPDATE vaults SET purpose='system' WHERE name='default'`,
			`CREATE TABLE connections (
				id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL REFERENCES users(id),
				library_vault_id TEXT NOT NULL REFERENCES vaults(id),
				label TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('static','mcp_oauth','oauth_app')),
				status TEXT NOT NULL CHECK(status IN ('ready','draft','needs_reconnect','disabled')),
				revision TEXT NOT NULL, services_json TEXT NOT NULL DEFAULT '[]', keys_json TEXT NOT NULL DEFAULT '[]',
				resource_url TEXT NOT NULL DEFAULT '', app_id TEXT NOT NULL DEFAULT '',
				scopes_json TEXT NOT NULL DEFAULT 'null', deleted INTEGER NOT NULL DEFAULT 0)`,
			`CREATE TABLE connection_grants (
				connection_id TEXT NOT NULL REFERENCES connections(id), vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
				services_json TEXT NOT NULL, bound_services_json TEXT NOT NULL, approved_revision TEXT NOT NULL,
				status TEXT NOT NULL CHECK(status IN ('active','suspended','revoked')),
				creator_user_id TEXT NOT NULL REFERENCES users(id), binding_handle TEXT NOT NULL UNIQUE,
				PRIMARY KEY(connection_id,vault_id))`,
			`CREATE TABLE connection_audit (
				id TEXT PRIMARY KEY, created_at TEXT NOT NULL, transport_actor_id TEXT NOT NULL,
				effective_user_id TEXT NOT NULL, connection_id TEXT NOT NULL, vault_id TEXT NOT NULL,
				revision TEXT NOT NULL, action TEXT NOT NULL, status TEXT NOT NULL)`,
		)
		if db.Name() == "sqlite" {
			statements = append(statements,
				`CREATE TRIGGER managed_no_human_session BEFORE INSERT ON sessions WHEN NEW.user_id IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND auth_mode='managed') BEGIN SELECT RAISE(ABORT,'managed users cannot receive human sessions'); END`,
				`CREATE TRIGGER managed_no_human_session_update BEFORE UPDATE ON sessions WHEN NEW.user_id IS NOT NULL AND EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND auth_mode='managed') BEGIN SELECT RAISE(ABORT,'managed users cannot receive human sessions'); END`,
				`CREATE TRIGGER library_no_session BEFORE INSERT ON sessions WHEN EXISTS(SELECT 1 FROM vaults WHERE id=NEW.vault_id AND purpose='library') BEGIN SELECT RAISE(ABORT,'personal libraries cannot be proxy scoped'); END`,
				`CREATE TRIGGER library_no_session_update BEFORE UPDATE ON sessions WHEN EXISTS(SELECT 1 FROM vaults WHERE id=NEW.vault_id AND purpose='library') BEGIN SELECT RAISE(ABORT,'personal libraries cannot be proxy scoped'); END`,
				`CREATE TRIGGER managed_identity_immutable BEFORE UPDATE OF auth_mode,installation_id,subject ON users WHEN NEW.auth_mode<>OLD.auth_mode OR NEW.installation_id IS NOT OLD.installation_id OR NEW.subject IS NOT OLD.subject BEGIN SELECT RAISE(ABORT,'native authentication identity is immutable'); END`,
				`CREATE TRIGGER library_native_owner BEFORE INSERT ON vaults WHEN (NEW.purpose='library' AND (NEW.owner_user_id IS NULL OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.owner_user_id AND auth_mode='managed'))) OR (NEW.purpose<>'library' AND NEW.owner_user_id IS NOT NULL) BEGIN SELECT RAISE(ABORT,'invalid native library ownership'); END`,
				`CREATE TRIGGER library_purpose_immutable BEFORE UPDATE OF purpose,owner_user_id ON vaults WHEN NEW.purpose<>OLD.purpose OR NEW.owner_user_id IS NOT OLD.owner_user_id BEGIN SELECT RAISE(ABORT,'vault purpose and ownership are immutable'); END`,
				`CREATE TRIGGER connection_native_owner BEFORE INSERT ON connections WHEN NOT EXISTS(SELECT 1 FROM users u JOIN vaults v ON v.owner_user_id=u.id WHERE u.id=NEW.owner_user_id AND u.auth_mode='managed' AND v.id=NEW.library_vault_id AND v.purpose='library') BEGIN SELECT RAISE(ABORT,'connection requires its native owner library'); END`,
				`CREATE TRIGGER connection_owner_immutable BEFORE UPDATE OF owner_user_id,library_vault_id,kind,resource_url,app_id ON connections WHEN NEW.owner_user_id<>OLD.owner_user_id OR NEW.library_vault_id<>OLD.library_vault_id OR NEW.kind<>OLD.kind OR NEW.resource_url<>OLD.resource_url OR NEW.app_id<>OLD.app_id BEGIN SELECT RAISE(ABORT,'connection identity and ownership are immutable'); END`,
				`CREATE TRIGGER connection_grant_native BEFORE INSERT ON connection_grants WHEN NOT EXISTS(SELECT 1 FROM vaults v JOIN connections c ON c.id=NEW.connection_id WHERE v.id=NEW.vault_id AND v.purpose='group' AND c.owner_user_id=NEW.creator_user_id) BEGIN SELECT RAISE(ABORT,'connection grants require a group and native owner'); END`,
				`CREATE TRIGGER connection_grant_native_update BEFORE UPDATE OF connection_id,vault_id,creator_user_id ON connection_grants WHEN NOT EXISTS(SELECT 1 FROM vaults v JOIN connections c ON c.id=NEW.connection_id WHERE v.id=NEW.vault_id AND v.purpose='group' AND c.owner_user_id=NEW.creator_user_id) BEGIN SELECT RAISE(ABORT,'connection grants require a group and native owner'); END`,
				`CREATE TRIGGER connection_grant_authority BEFORE INSERT ON connection_grants WHEN NEW.status='active' AND NOT EXISTS(
					SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_user_id JOIN vault_grants vg ON vg.actor_id=u.id AND vg.actor_type='user' AND vg.vault_id=NEW.vault_id AND vg.role='admin'
					WHERE c.id=NEW.connection_id AND u.id=NEW.creator_user_id AND u.is_active=1 AND c.status='ready' AND c.deleted=0 AND c.revision=NEW.approved_revision)
					BEGIN SELECT RAISE(ABORT,'active grants require current native owner and destination admin authority'); END`,
				`CREATE TRIGGER connection_grant_authority_update BEFORE UPDATE ON connection_grants WHEN NEW.status='active' AND NOT EXISTS(
					SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_user_id JOIN vault_grants vg ON vg.actor_id=u.id AND vg.actor_type='user' AND vg.vault_id=NEW.vault_id AND vg.role='admin'
					WHERE c.id=NEW.connection_id AND u.id=NEW.creator_user_id AND u.is_active=1 AND c.status='ready' AND c.deleted=0 AND c.revision=NEW.approved_revision)
					BEGIN SELECT RAISE(ABORT,'active grants require current native owner and destination admin authority'); END`,
				`CREATE TRIGGER managed_disable AFTER UPDATE OF is_active ON users WHEN NEW.auth_mode='managed' AND NEW.is_active=0 BEGIN
					UPDATE connections SET status='disabled' WHERE owner_user_id=NEW.id;
					UPDATE connection_grants SET status='suspended' WHERE status='active' AND (creator_user_id=NEW.id OR connection_id IN (SELECT id FROM connections WHERE owner_user_id=NEW.id)); END`,
				`CREATE TRIGGER native_membership_revoke AFTER DELETE ON vault_grants WHEN OLD.actor_type='user' AND OLD.role='admin' BEGIN UPDATE connection_grants SET status='suspended' WHERE creator_user_id=OLD.actor_id AND vault_id=OLD.vault_id AND status='active'; END`,
				`CREATE TRIGGER native_membership_downgrade AFTER UPDATE OF role ON vault_grants WHEN OLD.actor_type='user' AND OLD.role='admin' AND NEW.role<>'admin' BEGIN UPDATE connection_grants SET status='suspended' WHERE creator_user_id=OLD.actor_id AND vault_id=OLD.vault_id AND status='active'; END`,
				`CREATE TRIGGER library_membership BEFORE INSERT ON vault_grants WHEN EXISTS(SELECT 1 FROM vaults WHERE id=NEW.vault_id AND purpose='library' AND (NEW.actor_type<>'user' OR NEW.actor_id<>owner_user_id OR NEW.role<>'admin')) BEGIN SELECT RAISE(ABORT,'personal libraries admit only their native owner'); END`,
				`CREATE TRIGGER library_membership_update BEFORE UPDATE ON vault_grants WHEN EXISTS(SELECT 1 FROM vaults WHERE id=NEW.vault_id AND purpose='library' AND (NEW.actor_type<>'user' OR NEW.actor_id<>owner_user_id OR NEW.role<>'admin')) BEGIN SELECT RAISE(ABORT,'personal libraries admit only their native owner'); END`,
			)
		} else {
			statements = append(statements,
				`CREATE FUNCTION enforce_managed_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
					IF EXISTS(SELECT 1 FROM users WHERE id=NEW.user_id AND auth_mode='managed') OR EXISTS(SELECT 1 FROM vaults WHERE id=NEW.vault_id AND purpose='library') THEN RAISE EXCEPTION 'managed users and libraries cannot receive proxy or human sessions'; END IF; RETURN NEW; END $$`,
				`CREATE TRIGGER managed_session BEFORE INSERT OR UPDATE ON sessions FOR EACH ROW EXECUTE FUNCTION enforce_managed_session()`,
				`CREATE FUNCTION enforce_library_membership() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
					IF EXISTS(SELECT 1 FROM vaults WHERE id=NEW.vault_id AND purpose='library' AND (NEW.actor_type<>'user' OR NEW.actor_id<>owner_user_id OR NEW.role<>'admin')) THEN RAISE EXCEPTION 'personal libraries admit only their native owner'; END IF; RETURN NEW; END $$`,
				`CREATE TRIGGER library_membership BEFORE INSERT OR UPDATE ON vault_grants FOR EACH ROW EXECUTE FUNCTION enforce_library_membership()`,
				`CREATE FUNCTION enforce_managed_identity() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
					IF NEW.auth_mode<>OLD.auth_mode OR NEW.installation_id IS DISTINCT FROM OLD.installation_id OR NEW.subject IS DISTINCT FROM OLD.subject THEN RAISE EXCEPTION 'native authentication identity is immutable'; END IF;
					IF NEW.auth_mode='managed' AND NOT NEW.is_active THEN UPDATE connections SET status='disabled' WHERE owner_user_id=NEW.id; UPDATE connection_grants SET status='suspended' WHERE status='active' AND (creator_user_id=NEW.id OR connection_id IN (SELECT id FROM connections WHERE owner_user_id=NEW.id)); END IF; RETURN NEW; END $$`,
				`CREATE TRIGGER managed_identity BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION enforce_managed_identity()`,
				`CREATE FUNCTION revoke_native_membership() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
					IF OLD.actor_type='user' AND OLD.role='admin' THEN
						IF TG_OP='DELETE' THEN UPDATE connection_grants SET status='suspended' WHERE creator_user_id=OLD.actor_id AND vault_id=OLD.vault_id AND status='active';
						ELSIF NEW.role<>'admin' THEN UPDATE connection_grants SET status='suspended' WHERE creator_user_id=OLD.actor_id AND vault_id=OLD.vault_id AND status='active'; END IF;
					END IF; RETURN NULL; END $$`,
				`CREATE TRIGGER native_membership_revoke AFTER DELETE OR UPDATE ON vault_grants FOR EACH ROW EXECUTE FUNCTION revoke_native_membership()`,
				`CREATE FUNCTION enforce_library_owner() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
					IF TG_OP='UPDATE' AND (NEW.purpose<>OLD.purpose OR NEW.owner_user_id IS DISTINCT FROM OLD.owner_user_id) THEN RAISE EXCEPTION 'vault purpose and ownership are immutable'; END IF;
					IF (NEW.purpose='library' AND (NEW.owner_user_id IS NULL OR NOT EXISTS(SELECT 1 FROM users WHERE id=NEW.owner_user_id AND auth_mode='managed'))) OR (NEW.purpose<>'library' AND NEW.owner_user_id IS NOT NULL) THEN RAISE EXCEPTION 'invalid native library ownership'; END IF; RETURN NEW; END $$`,
				`CREATE TRIGGER library_native_owner BEFORE INSERT OR UPDATE ON vaults FOR EACH ROW EXECUTE FUNCTION enforce_library_owner()`,
				`CREATE FUNCTION enforce_connection_owner() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
					IF TG_OP='UPDATE' AND (NEW.owner_user_id<>OLD.owner_user_id OR NEW.library_vault_id<>OLD.library_vault_id OR NEW.kind<>OLD.kind OR NEW.resource_url<>OLD.resource_url OR NEW.app_id<>OLD.app_id) THEN RAISE EXCEPTION 'connection identity and ownership are immutable'; END IF;
					IF NOT EXISTS(SELECT 1 FROM users u JOIN vaults v ON v.owner_user_id=u.id WHERE u.id=NEW.owner_user_id AND u.auth_mode='managed' AND v.id=NEW.library_vault_id AND v.purpose='library') THEN RAISE EXCEPTION 'connection requires its native owner library'; END IF; RETURN NEW; END $$`,
				`CREATE TRIGGER connection_native_owner BEFORE INSERT OR UPDATE ON connections FOR EACH ROW EXECUTE FUNCTION enforce_connection_owner()`,
				`CREATE FUNCTION enforce_connection_grant() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
					IF NOT EXISTS(SELECT 1 FROM vaults v JOIN connections c ON c.id=NEW.connection_id WHERE v.id=NEW.vault_id AND v.purpose='group' AND c.owner_user_id=NEW.creator_user_id) THEN RAISE EXCEPTION 'connection grants require a group and native owner'; END IF;
					IF NEW.status='active' AND NOT EXISTS(SELECT 1 FROM connections c JOIN users u ON u.id=c.owner_user_id JOIN vault_grants vg ON vg.actor_id=u.id AND vg.actor_type='user' AND vg.vault_id=NEW.vault_id AND vg.role='admin'
					WHERE c.id=NEW.connection_id AND u.id=NEW.creator_user_id AND u.is_active AND c.status='ready' AND c.deleted=0 AND c.revision=NEW.approved_revision) THEN RAISE EXCEPTION 'active grants require current native owner and destination admin authority'; END IF; RETURN NEW; END $$`,
				`CREATE TRIGGER connection_grant_native BEFORE INSERT OR UPDATE ON connection_grants FOR EACH ROW EXECUTE FUNCTION enforce_connection_grant()`,
			)
		}
		for _, statement := range statements {
			if err := db.Exec(statement).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
