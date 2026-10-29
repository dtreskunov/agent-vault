package store

import (
	"context"
	"database/sql"
	"strings"
)

func copyConnectionTable(ctx context.Context, src *SQLStore, tx *sql.Tx, d Dialect, table, columns string) (int, error) {
	rows, err := src.db.QueryContext(ctx, "SELECT "+columns+" FROM "+table)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	names := strings.Split(columns, ",")
	marks := make([]string, len(names))
	for i := range marks {
		marks[i] = "?"
	}
	count := 0
	for rows.Next() {
		values := make([]any, len(names))
		targets := make([]any, len(names))
		for i := range targets {
			targets[i] = &values[i]
		}
		if err = rows.Scan(targets...); err != nil {
			return count, err
		}
		if _, err = tx.ExecContext(ctx, d.Rebind("INSERT INTO "+table+" ("+columns+") VALUES ("+strings.Join(marks, ",")+")"), values...); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}
func copyConnections(ctx context.Context, s *SQLStore, tx *sql.Tx, d Dialect) (int, error) {
	return copyConnectionTable(ctx, s, tx, d, "connections", "id,owner_user_id,library_vault_id,label,kind,status,revision,services_json,keys_json,resource_url,app_id,scopes_json,deleted")
}
func copyConnectionGrants(ctx context.Context, s *SQLStore, tx *sql.Tx, d Dialect) (int, error) {
	return copyConnectionTable(ctx, s, tx, d, "connection_grants", "connection_id,vault_id,services_json,bound_services_json,approved_revision,status,creator_user_id,binding_handle")
}
func copyConnectionAudit(ctx context.Context, s *SQLStore, tx *sql.Tx, d Dialect) (int, error) {
	return copyConnectionTable(ctx, s, tx, d, "connection_audit", "id,created_at,transport_actor_id,effective_user_id,connection_id,vault_id,revision,action,status")
}
