package store

import (
	"context"
	"database/sql"
)

func copyGatewayOAuthRecords(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	exists, err := tableExists(src.db, src.DialectName(), "gateway_oauth_records")
	if err != nil || !exists {
		return 0, err
	}
	rows, err := src.db.QueryContext(ctx,
		`SELECT vault_id,kind,record_key,ciphertext,nonce,expires_at,account_key FROM gateway_oauth_records`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var vault, kind, key, account string
		var ciphertext, nonce []byte
		var expires int64
		if err := rows.Scan(&vault, &kind, &key, &ciphertext, &nonce, &expires, &account); err != nil {
			return count, err
		}
		if _, err := tx.ExecContext(ctx, dstDialect.Rebind(`INSERT INTO gateway_oauth_records
			(vault_id,kind,record_key,ciphertext,nonce,expires_at,account_key) VALUES (?,?,?,?,?,?,?)`),
			vault, kind, key, ciphertext, nonce, expires, account); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}

func copyGatewayTokenAuthorities(ctx context.Context, src *SQLStore, tx *sql.Tx, dstDialect Dialect) (int, error) {
	exists, err := tableExists(src.db, src.DialectName(), "gateway_oauth_token_authorities")
	if err != nil || !exists {
		return 0, err
	}
	rows, err := src.db.QueryContext(ctx, `SELECT authority FROM gateway_oauth_token_authorities`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var authority string
		if err := rows.Scan(&authority); err != nil {
			return count, err
		}
		if _, err := tx.ExecContext(ctx, dstDialect.Rebind(
			`INSERT INTO gateway_oauth_token_authorities (authority) VALUES (?)`), authority); err != nil {
			return count, err
		}
		count++
	}
	return count, rows.Err()
}
