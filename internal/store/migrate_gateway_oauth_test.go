package store

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

func TestCopyGatewayOAuthStateAndTokenAuthorities(t *testing.T) {
	ctx := context.Background()
	src, err := Open(filepath.Join(t.TempDir(), "source.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	dst, err := Open(filepath.Join(t.TempDir(), "destination.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	for _, db := range []*SQLStore{src, dst} {
		for _, query := range []string{
			`CREATE TABLE gateway_oauth_records(vault_id TEXT,kind TEXT,record_key TEXT,ciphertext BLOB,nonce BLOB,expires_at BIGINT,account_key TEXT,PRIMARY KEY(vault_id,kind,record_key))`,
			`CREATE TABLE gateway_oauth_token_authorities(authority TEXT PRIMARY KEY)`,
		} {
			if _, err := db.db.Exec(query); err != nil {
				t.Fatal(err)
			}
		}
	}
	ciphertext, nonce := []byte{1, 2, 3}, []byte{4, 5, 6}
	if _, err := src.db.Exec(`INSERT INTO gateway_oauth_records VALUES ('vault','account','OAUTH_TEST',?,?,0,'')`, ciphertext, nonce); err != nil {
		t.Fatal(err)
	}
	if _, err := src.db.Exec(`INSERT INTO gateway_oauth_token_authorities VALUES ('github.com:443')`); err != nil {
		t.Fatal(err)
	}
	tx, err := dst.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if count, err := copyGatewayOAuthRecords(ctx, src, tx, PostgresDialect{}); err != nil || count != 1 {
		t.Fatal("account copy failed", count, err)
	}
	if count, err := copyGatewayTokenAuthorities(ctx, src, tx, PostgresDialect{}); err != nil || count != 1 {
		t.Fatal("token authority copy failed", count, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var gotCiphertext, gotNonce []byte
	if err := dst.db.QueryRow(`SELECT ciphertext,nonce FROM gateway_oauth_records WHERE record_key='OAUTH_TEST'`).Scan(&gotCiphertext, &gotNonce); err != nil ||
		!bytes.Equal(gotCiphertext, ciphertext) || !bytes.Equal(gotNonce, nonce) {
		t.Fatal("encrypted account bytes changed during backend copy", err)
	}
	var authority string
	if err := dst.db.QueryRow(`SELECT authority FROM gateway_oauth_token_authorities`).Scan(&authority); err != nil || authority != "github.com:443" {
		t.Fatal("token interception registry was lost", err)
	}
	counts, err := CountSourceTables(src)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, count := range counts {
		if count.Table == "gateway_oauth_records" || count.Table == "gateway_oauth_token_authorities" {
			found++
			if count.Count != 1 {
				t.Fatal("backend migration preview omitted OAuth state")
			}
		}
	}
	if found != 2 {
		t.Fatal("backend migration preview omitted OAuth tables")
	}
}

func TestCopyGatewayOAuthMissingTablesAndErrors(t *testing.T) {
	ctx := context.Background()
	src, err := Open(filepath.Join(t.TempDir(), "older.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if count, err := copyGatewayOAuthRecords(ctx, src, nil, PostgresDialect{}); err != nil || count != 0 {
		t.Fatal("older source without fork tables rejected", err)
	}
	if count, err := copyGatewayTokenAuthorities(ctx, src, nil, PostgresDialect{}); err != nil || count != 0 {
		t.Fatal("older source without token registry rejected", err)
	}
	src.Close()
	if _, err := copyGatewayOAuthRecords(ctx, src, nil, PostgresDialect{}); err == nil {
		t.Fatal("database failure was silently treated as missing state")
	}
}
