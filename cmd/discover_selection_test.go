package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestDiscoverDisplaysOAuthSelection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/discover" {
			t.Error("unexpected discovery route", r.URL.Path)
		}
		fmt.Fprint(w, `{"vault":"group","services":[{"name":"Google one","host":"api.example.com","access_placeholder":"av-access:first","selection_required":true},{"name":"Google two","host":"api.example.com","access_placeholder":"av-access:second","selection_required":true}],"available_credentials":["first","second"]}`)
	}))
	defer server.Close()
	t.Setenv("AGENT_VAULT_TOKEN", "synthetic-token")
	t.Setenv("AGENT_VAULT_ADDR", server.URL)
	t.Setenv("AGENT_VAULT_VAULT", "group")
	command := &cobra.Command{}
	command.Flags().Bool("json", false, "")
	command.Flags().String("vault", "", "")
	var output bytes.Buffer
	command.SetOut(&output)
	if err := discoverCmd.RunE(command, nil); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"Bearer av-access:first", "Bearer av-access:second", "required"} {
		if !strings.Contains(output.String(), required) {
			t.Fatal("discovery table omitted explicit selection", required)
		}
	}
}
