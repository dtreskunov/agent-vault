package mitm

import (
	"io"
	"net/http"
)

func (p *Proxy) localResponse(w http.ResponseWriter, r *http.Request, vault string, emit func(int, string)) bool {
	if p.options.LocalResponse == nil {
		return false
	}
	response, err := p.options.LocalResponse(r.Context(), vault, r)
	if err != nil {
		p.logger.Error("local proxy response failed", "err", err)
		http.Error(w, "Local proxy response unavailable", http.StatusBadGateway)
		emit(http.StatusBadGateway, "local_response_failed")
		return true
	}
	if response == nil {
		return false
	}
	defer response.Body.Close()
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		p.logger.Debug("local response client closed", "err", err)
	}
	emit(response.StatusCode, "token_stub")
	return true
}
