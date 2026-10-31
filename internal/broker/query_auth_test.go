package broker

import (
	"errors"
	"testing"
)

func TestAPIKeyQueryPlacement(t *testing.T) {
	auth := Auth{Type: "api-key", Key: "API_KEY", Location: "query", Parameter: "api_key"}
	if err := auth.Validate(); err != nil {
		t.Fatal(err)
	}
	resolve := func(key string) (string, error) {
		if key != "API_KEY" {
			t.Fatal("wrong credential key")
		}
		return "synthetic-query-secret", nil
	}
	headers, err := auth.Resolve(resolve)
	if err != nil || len(headers) != 0 {
		t.Fatal("query authentication injected headers", err)
	}
	query, err := auth.ResolveQuery(resolve)
	if err != nil || query["api_key"] != "synthetic-query-secret" {
		t.Fatal("query credential not resolved", err)
	}
	if _, err := auth.ResolveQuery(func(string) (string, error) {
		return "", errors.New("missing credential")
	}); err == nil {
		t.Fatal("missing query credential was ignored")
	}
}

func TestAPIKeyRejectsInvalidPlacement(t *testing.T) {
	for _, auth := range []Auth{
		{Type: "api-key", Key: "KEY", Location: "body"},
		{Type: "api-key", Key: "KEY", Location: "query"},
		{Type: "api-key", Key: "KEY", Location: "query", Parameter: "bad&name"},
		{Type: "api-key", Key: "KEY", Location: "query", Parameter: "key", Header: "X-Key"},
		{Type: "api-key", Key: "KEY", Location: "query", Parameter: "key", Prefix: "Token "},
		{Type: "api-key", Key: "KEY", Parameter: "key"},
		{Type: "bearer", Token: "KEY", Location: "query", Parameter: "key"},
	} {
		if err := auth.Validate(); err == nil {
			t.Fatal("invalid authentication placement accepted")
		}
	}
}
