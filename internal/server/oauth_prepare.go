package server

import (
	"context"
	"fmt"
)

func (s *Server) PrepareGateway(ctx context.Context) error {
	s.oauthPrepare.Do(func() {
		if s.mcpOAuth != nil {
			if err := s.mcpOAuth.Migrate(ctx); err != nil {
				s.oauthPrepareErr = fmt.Errorf("migrating OAuth accounts before gateway startup: %w", err)
			}
		}
	})
	return s.oauthPrepareErr
}
