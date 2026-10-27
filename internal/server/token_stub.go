package server

import (
	"context"
	"net/http"

	"github.com/Infisical/agent-vault/internal/blindtunnel"
)

func (s *Server) GatewayConnectPolicy(base func(context.Context, string, string, int) (blindtunnel.Mode, error)) func(context.Context, string, string, int) (blindtunnel.Mode, error) {
	return func(ctx context.Context, vault, host string, port int) (blindtunnel.Mode, error) {
		if s.mcpOAuth != nil {
			intercept, err := s.mcpOAuth.InterceptTokenHost(ctx, host, port)
			if err != nil {
				return "", err
			}
			if intercept {
				return blindtunnel.MITM, nil
			}
		}
		return base(ctx, vault, host, port)
	}
}
func (s *Server) LocalTokenResponse(ctx context.Context, vault string, r *http.Request) (*http.Response, error) {
	if s.mcpOAuth == nil {
		return nil, nil
	}
	return s.mcpOAuth.TokenResponse(ctx, vault, r)
}
