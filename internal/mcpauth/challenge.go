package mcpauth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
)

func (m *Manager) FilterChallenge(ctx context.Context, vault string, keys []string, headers http.Header) error {
	managed := false
	for _, key := range keys {
		if !strings.HasPrefix(key, "MCP_") {
			continue
		}
		_, err := m.repo.Account(ctx, vault, key)
		if err == nil {
			managed = true
			break
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	if !managed {
		return nil
	}
	challenges, err := oauthex.ParseWWWAuthenticate(headers.Values("WWW-Authenticate"))
	if err != nil {
		headers.Del("WWW-Authenticate")
		m.logger.Warn("removed malformed authentication challenge on a managed MCP service")
		return nil
	}
	headers.Del("WWW-Authenticate")
	for _, challenge := range challenges {
		delete(challenge.Params, "resource_metadata")
		names := make([]string, 0, len(challenge.Params))
		for name := range challenge.Params {
			names = append(names, name)
		}
		slices.Sort(names)
		parts := make([]string, 0, len(names))
		for _, name := range names {
			parts = append(parts, name+"="+strconv.Quote(challenge.Params[name]))
		}
		value := challenge.Scheme
		if len(parts) != 0 {
			value += " " + strings.Join(parts, ", ")
		}
		headers.Add("WWW-Authenticate", value)
	}
	return nil
}
