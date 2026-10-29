package mcpauth

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

func databaseSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	queries := []string{
		`SELECT vault_id,kind,record_key,hex(ciphertext),hex(nonce),expires_at,account_key FROM gateway_oauth_records ORDER BY vault_id,kind,record_key`,
		`SELECT vault_id,key,type,hex(ciphertext),hex(nonce),updated_at FROM credentials ORDER BY vault_id,key`,
		`SELECT vault_id,services_json,updated_at FROM broker_configs ORDER BY vault_id`,
		`SELECT key,value,updated_at FROM instance_settings ORDER BY key`,
		`SELECT authority FROM gateway_oauth_token_authorities ORDER BY authority`,
	}
	var result strings.Builder
	for _, query := range queries {
		rows, err := db.Query(query)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(cols))
			targets := make([]any, len(cols))
			for i := range values {
				targets[i] = &values[i]
			}
			if err = rows.Scan(targets...); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&result, values)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return result.String()
}
