package mitm

import "net/http"

func (p *Proxy) applyResponsePolicy(w http.ResponseWriter, r *http.Request, response *http.Response,
	vault string, keys []string, emit func(int, string)) bool {
	if response.StatusCode == http.StatusUnauthorized && p.options.FilterResponse != nil {
		if err := p.options.FilterResponse(r.Context(), vault, keys, response.Header); err != nil {
			p.logger.Error("MCP response policy failed", "err", err)
			http.Error(w, "response policy unavailable", http.StatusBadGateway)
			emit(http.StatusBadGateway, "response_policy_failed")
			return false
		}
	}
	return true
}
