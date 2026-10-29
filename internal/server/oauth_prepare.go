package server

import (
	"context"
	"fmt"
	"github.com/Infisical/agent-vault/internal/gatewayconfig"
)

func (s *Server) PrepareGateway(ctx context.Context) error {
	s.oauthPrepare.Do(func() {
		if s.mcpOAuth == nil {
			if db, _ := s.connectionSQL(); db != nil {
				s.oauthPrepareErr = fmt.Errorf("validating gateway before startup: OAuth configuration is invalid")
			}
			return
		}
		if err := s.mcpOAuth.ValidateModel(ctx, gatewayconfig.Headless()); err != nil {
			s.oauthPrepareErr = fmt.Errorf("validating OAuth model before gateway startup: %w", err)
		}
	})
	return s.oauthPrepareErr
}
