package mcpauth

import (
	"slices"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/mcpauth/oauthex"
)

type ScopeSet struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	Scopes []string `json:"scopes"`
	Hosts  []string `json:"hosts"`
}

type Provider struct {
	ID                    string     `json:"id"`
	Label                 string     `json:"label"`
	Issuer                string     `json:"issuer"`
	AuthorizationEndpoint string     `json:"authorization_endpoint"`
	TokenEndpoint         string     `json:"token_endpoint"`
	RevocationEndpoint    string     `json:"revocation_endpoint,omitempty"`
	ConsoleURL            string     `json:"console_url"`
	ScopeSets             []ScopeSet `json:"scope_sets"`
	MCPServers            []string   `json:"mcp_servers,omitempty"`
}

func Catalog() []Provider {
	return []Provider{
		{ID: "google", Label: "Google", Issuer: "https://accounts.google.com", AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
			TokenEndpoint: "https://oauth2.googleapis.com/token", RevocationEndpoint: "https://oauth2.googleapis.com/revoke",
			ConsoleURL: "https://console.cloud.google.com/apis/credentials", ScopeSets: []ScopeSet{
				{ID: "gmail-read", Label: "Gmail: read", Scopes: []string{"https://www.googleapis.com/auth/gmail.readonly"}, Hosts: []string{"gmail.googleapis.com"}},
				{ID: "gmail-send", Label: "Gmail: send", Scopes: []string{"https://www.googleapis.com/auth/gmail.send"}, Hosts: []string{"gmail.googleapis.com"}},
				{ID: "calendar", Label: "Calendar", Scopes: []string{"https://www.googleapis.com/auth/calendar"}, Hosts: []string{"www.googleapis.com/calendar/*"}},
				{ID: "drive-read", Label: "Drive: read", Scopes: []string{"https://www.googleapis.com/auth/drive.readonly"}, Hosts: []string{"www.googleapis.com/drive/*"}},
			}},
		{ID: "github", Label: "GitHub", Issuer: "https://github.com/login/oauth", AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
			TokenEndpoint: "https://github.com/login/oauth/access_token", ConsoleURL: "https://github.com/settings/applications/new",
			MCPServers: []string{"https://api.githubcopilot.com/mcp/"}, ScopeSets: []ScopeSet{
				{ID: "repo", Label: "Repositories", Scopes: []string{"repo"}, Hosts: []string{"api.github.com/repos/*"}},
				{ID: "issues", Label: "Issues and pull requests", Scopes: []string{"repo"}, Hosts: []string{"api.github.com/repos/*/issues/*", "api.github.com/repos/*/pulls/*"}},
			}},
	}
}

func catalogProvider(id string) (Provider, error) {
	for _, entry := range Catalog() {
		if entry.ID == id {
			return entry, nil
		}
	}
	return Provider{}, failure("unknown_provider", "Unknown OAuth provider")
}

func (p Provider) metadata() oauthex.AuthServerMeta {
	return oauthex.AuthServerMeta{Issuer: p.Issuer, AuthorizationEndpoint: p.AuthorizationEndpoint,
		TokenEndpoint: p.TokenEndpoint, RevocationEndpoint: p.RevocationEndpoint, CodeChallengeMethodsSupported: []string{"S256"}}
}

func scopeSelection(p Provider, ids []string) ([]string, []string, error) {
	if len(ids) == 0 {
		return nil, nil, failure("invalid_scopes", "At least one catalog scope set is required")
	}
	var scopes, hosts []string
	for _, id := range ids {
		found := false
		for _, set := range p.ScopeSets {
			if set.ID == id {
				found = true
				for _, scope := range set.Scopes {
					if !slices.Contains(scopes, scope) {
						scopes = append(scopes, scope)
					}
				}
				for _, host := range set.Hosts {
					if !slices.Contains(hosts, host) {
						hosts = append(hosts, host)
					}
				}
			}
		}
		if !found {
			return nil, nil, failure("invalid_scopes", "Unknown provider scope set")
		}
	}
	return scopes, hosts, nil
}

func (a Account) providerServices() ([]broker.Service, error) {
	p, err := catalogProvider(a.Provider)
	if err != nil {
		return nil, err
	}
	_, hosts, err := scopeSelection(p, a.ScopeSets)
	if err != nil {
		return nil, err
	}
	services := make([]broker.Service, 0, len(hosts))
	for i, pattern := range hosts {
		host, path, port := broker.SplitInlineHost(pattern, "")
		services = append(services, broker.Service{Name: servicePrefix(a) + string(rune('a'+i)), Host: host, Path: path, Port: port,
			Auth: broker.Auth{Type: "bearer", Token: a.Key}})
	}
	return services, nil
}
