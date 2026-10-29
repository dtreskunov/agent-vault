package server

import (
	"context"
	"net/http"

	"github.com/Infisical/agent-vault/internal/blindtunnel"
	"github.com/Infisical/agent-vault/internal/broker"
)

func (s *Server) GatewayConnectPolicy(base func(context.Context, string, string, int) (blindtunnel.Mode, error)) func(context.Context, string, string, int) (blindtunnel.Mode, error) {
	return func(ctx context.Context, vault, host string, port int) (blindtunnel.Mode, error) {
		bindings, err := s.loadBindings(ctx, vault)
		if err != nil {
			return "", err
		}
		for _, b := range bindings {
			services := append([]broker.Service(nil), b.services...)
			for i := range services {
				services[i].Path = ""
			}
			if matched, _ := broker.MatchService(host, port, "/", services); matched != nil {
				return blindtunnel.MITM, nil
			}
		}
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
	return s.sharedTokenResponse(ctx, vault, r)
}
