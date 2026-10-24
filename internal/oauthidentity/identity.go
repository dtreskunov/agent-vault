// Package oauthidentity resolves identity only from authenticated provider APIs
// or signature-verified OIDC tokens.
package oauthidentity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type Identity struct {
	Subject string
	Label   string
}

func getJSON(ctx context.Context, client *http.Client, endpoint, token string, value any) error {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return fmt.Errorf("identity endpoint requires an absolute HTTPS URL")
	}
	request, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if client == nil {
		return fmt.Errorf("guarded identity client is required")
	}
	bounded := *client
	bounded.Timeout = 10 * time.Second
	bounded.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := bounded.Do(request)
	if err != nil {
		return fmt.Errorf("identity endpoint request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("identity endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(body) > 1<<20 {
		return fmt.Errorf("identity endpoint response unreadable or oversized")
	}
	if err := json.Unmarshal(body, value); err != nil {
		return fmt.Errorf("identity endpoint response is invalid JSON")
	}
	return nil
}

func Provider(ctx context.Context, client *http.Client, provider, accessToken string) (Identity, error) {
	switch provider {
	case "google":
		var user struct {
			Subject  string `json:"sub"`
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := getJSON(ctx, client, "https://openidconnect.googleapis.com/v1/userinfo", accessToken, &user); err != nil {
			return Identity{}, err
		}
		if user.Subject == "" {
			return Identity{}, fmt.Errorf("Google userinfo omitted subject")
		}
		label := ""
		if user.Verified {
			label = user.Email
		}
		return Identity{Subject: user.Subject, Label: label}, nil
	case "github":
		var user struct {
			ID    int64  `json:"id"`
			Login string `json:"login"`
		}
		if err := getJSON(ctx, client, "https://api.github.com/user", accessToken, &user); err != nil {
			return Identity{}, err
		}
		if user.ID <= 0 || user.Login == "" {
			return Identity{}, fmt.Errorf("GitHub user response omitted identity")
		}
		return Identity{Subject: strconv.FormatInt(user.ID, 10), Label: user.Login}, nil
	default:
		return Identity{}, fmt.Errorf("identity provider not supported")
	}
}
