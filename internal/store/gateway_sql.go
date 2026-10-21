package store

import "database/sql"

// GatewaySQL lets fork packages share the existing connection and dialect.
func (s *SQLStore) GatewaySQL() (*sql.DB, Dialect) { return s.db, s.dialect }
