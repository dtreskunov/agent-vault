package brokercore

import (
	"net/url"
	"testing"
)

func TestQueryAuthenticationOverridesClientValues(t *testing.T) {
	target, _ := url.Parse("https://api.example/data?key=old&key=duplicate&q=hello%20world")
	if err := ApplyQueryInjection(target, map[string]string{"key": "secret &+="}); err != nil {
		t.Fatal(err)
	}
	if values := target.Query()["key"]; len(values) != 1 || values[0] != "secret &+=" {
		t.Fatal("query credential did not replace every duplicate")
	}
	if target.Query().Get("q") != "hello world" {
		t.Fatal("unrelated query value changed")
	}
	target.RawQuery = "invalid=%zz"
	if err := ApplyQueryInjection(target, map[string]string{"key": "secret"}); err == nil {
		t.Fatal("malformed query silently accepted")
	}
	if target.RawQuery != "invalid=%zz" {
		t.Fatal("invalid query partially changed")
	}
}
