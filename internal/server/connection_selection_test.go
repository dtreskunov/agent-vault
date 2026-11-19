package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/mcpauth"
	"github.com/Infisical/agent-vault/internal/store"
)

func TestManagedOAuthExplicitIdentitySelection(t *testing.T) {
	f, _, first, state := setupManagedOAuth(t)
	ctx := context.Background()
	if w := f.complete(first, state, f.user); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	first, err := f.s.loadConnection(ctx, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	account, err := f.s.mcpOAuth.ConnectionAccount(ctx, first.library, first.ID)
	if err != nil {
		t.Fatal(err)
	}
	other, err := f.db.ReconcileManagedUser(ctx, store.ManagedUserInput{
		InstallationID: "install", Subject: "second-owner", Active: true, Role: "no-access",
		VaultGrants: []store.ManagedVaultGrant{{Vault: "group-one", Role: "admin"}, {Vault: "group-two", Role: "admin"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	otherBase := "/v1/managed-users/" + other.ID
	app := fmt.Sprintf(`{"issuer":%q,"client_id":"test-client","client_secret":"synthetic-client-secret","label":"Second app","authorization_endpoint":%q,"token_endpoint":%q,"api_hosts":["api.example.com"],"default_scopes":["read"],"identity":"none"}`,
		account.Issuer, account.Issuer+"/authorize", account.Issuer+"/token")
	if w := f.call("PUT", otherBase+"/oauth-apps/test-app?scope=user", app, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	w := f.call("POST", otherBase+"/connections", `{"label":"Second identity","kind":"oauth_app","app_id":"test-app","scopes":["read"]}`, "")
	var second connection
	if w.Code != http.StatusCreated || json.Unmarshal(w.Body.Bytes(), &second) != nil {
		t.Fatal(w.Code, w.Body)
	}
	w = f.call("POST", otherBase+"/connections/"+second.ID+"/oauth/start", `{}`, "")
	var flow mcpauth.Started
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &flow) != nil {
		t.Fatal(w.Code, w.Body)
	}
	if w = f.complete(&second, flow.State, other.ID); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	secondPtr, err := f.s.loadConnection(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	second = *secondPtr
	for _, item := range []struct {
		base string
		c    *connection
	}{{f.base(), first}, {otherBase, &second}} {
		a, err := f.s.mcpOAuth.ConnectionAccount(ctx, item.c.library, item.c.ID)
		if err != nil {
			t.Fatal(err)
		}
		a.AccessToken = "synthetic-token-" + item.c.ID
		raw, _ := json.Marshal(a)
		ct, nonce, err := crypto.Encrypt(raw, f.s.encKey)
		if err != nil {
			t.Fatal(err)
		}
		db, d := f.db.GatewaySQL()
		if _, err = db.Exec(d.Rebind(`UPDATE gateway_oauth_records SET ciphertext=?,nonce=? WHERE vault_id=? AND kind='account' AND record_key=?`), ct, nonce, item.c.library, item.c.ID); err != nil {
			t.Fatal(err)
		}
		for _, group := range []string{"group-one", "group-two"} {
			w = f.call("PUT", item.base+"/connections/"+item.c.ID+"/grants/"+group,
				`{}`, "")
			if w.Code != http.StatusOK {
				t.Fatal("explicitly selectable OAuth grants must coexist", w.Code, w.Body)
			}
		}
	}
	one, _ := f.db.GetVault(ctx, "group-one")
	two, _ := f.db.GetVault(ctx, "group-two")
	bindings, err := f.s.loadBindings(ctx, one.ID)
	if err != nil || len(bindings) != 2 {
		t.Fatal("missing account bindings", err)
	}
	services, _, err := f.s.sharedDiscovery(ctx, one.ID)
	if err != nil || len(services) != 2 {
		t.Fatal("missing selector discovery", err)
	}
	for _, service := range services {
		if !service.SelectionRequired || service.AccessPlaceholder == "" {
			t.Fatal("ambiguous discovery omitted explicit selector")
		}
	}
	db, _ := f.db.GatewaySQL()
	if _, err := db.Exec(`DELETE FROM broker_configs WHERE vault_id=?`, one.ID); err != nil {
		t.Fatal(err)
	}
	discover := httptest.NewRequest(http.MethodGet, "/discover", nil)
	discover.Header.Set("Authorization", "Bearer "+f.token)
	discover.Header.Set("X-Vault", "group-one")
	discovered := httptest.NewRecorder()
	f.s.Handler().ServeHTTP(discovered, discover)
	var discovery discoverResponse
	if discovered.Code != http.StatusOK || json.Unmarshal(discovered.Body.Bytes(), &discovery) != nil || len(discovery.Services) != 2 {
		t.Fatal("shared selectors were hidden when no local broker config exists", discovered.Code, discovered.Body)
	}
	for _, service := range discovery.Services {
		if !service.SelectionRequired || service.AccessPlaceholder == "" || service.ConnectionID == "" || service.BindingHandle == "" {
			t.Fatal("wire discovery omitted selector requirements")
		}
	}
	provider := f.s.CredentialProvider()
	for _, b := range bindings {
		selected := brokercore.WithRequestAuthorization(ctx, []string{"bearer " + mcpauth.AccessPlaceholderPrefix + b.handle})
		result, err := provider.Inject(selected, one.ID, "api.example.com", 443, "/items")
		if err != nil || result.Headers["Authorization"] != "Bearer synthetic-token-"+b.id ||
			!slices.Contains(result.CredentialKeys, b.id) {
			t.Fatal("wrong OAuth identity selected", err)
		}
		bound := brokercore.WithRequestBinding(ctx, []string{b.handle})
		pinned, pinErr := provider.Inject(bound, one.ID, "api.example.com", 443, "/items")
		if pinErr != nil || pinned.Headers["Authorization"] != result.Headers["Authorization"] {
			t.Fatal("explicit MCP connection selected the wrong identity", pinErr)
		}
		if _, pinErr = provider.Inject(brokercore.WithRequestBinding(selected, []string{"BIND_OTHER"}), one.ID, "api.example.com", 443, "/items"); !errors.Is(pinErr, brokercore.ErrBindingInvalid) {
			t.Fatal("conflicting selectors were accepted", pinErr)
		}
		if _, err = provider.Inject(selected, two.ID, "api.example.com", 443, "/items"); !errors.Is(err, brokercore.ErrBindingDestinationMismatch) {
			t.Fatal("binding selector crossed groups", err)
		}
		if _, err = provider.Inject(selected, one.ID, "elsewhere.example.com", 443, "/items"); !errors.Is(err, brokercore.ErrBindingDestinationMismatch) {
			t.Fatal("binding selector crossed destinations", err)
		}
		if _, err = provider.Inject(selected, one.ID, "api.example.com", 8443, "/items"); !errors.Is(err, brokercore.ErrBindingDestinationMismatch) {
			t.Fatal("binding selector crossed ports", err)
		}
		request := httptest.NewRequest(http.MethodGet, "https://api.example.com/items", nil)
		request.Header.Set("Authorization", "Bearer "+mcpauth.AccessPlaceholderPrefix+b.handle)
		if response, err := f.s.LocalTokenResponse(ctx, one.ID, request); err != nil || response != nil {
			t.Fatal("authorized API request was intercepted as a token request", err)
		}
		for _, destination := range []string{"https://elsewhere.example.com/items", "https://api.example.com:8443/items", "http://api.example.com/items"} {
			request := httptest.NewRequest(http.MethodGet, destination, nil)
			request.Header.Set("Authorization", "Bearer "+mcpauth.AccessPlaceholderPrefix+b.handle)
			if _, err := f.s.LocalTokenResponse(ctx, one.ID, request); !errors.Is(err, brokercore.ErrBindingDestinationMismatch) {
				t.Fatal("local OAuth interception lost destination mismatch", destination, err)
			}
		}
	}

	for _, tc := range []struct {
		authorization []string
		want          error
	}{
		{nil, brokercore.ErrBindingSelectionRequired},
		{[]string{"Bearer placeholder"}, brokercore.ErrBindingSelectionRequired},
		{[]string{"Bearer " + mcpauth.AccessPlaceholderPrefix + "unknown"}, brokercore.ErrBindingDestinationMismatch},
		{[]string{"Bearer " + mcpauth.AccessPlaceholderPrefix}, brokercore.ErrBindingInvalid},
		{[]string{"Basic " + mcpauth.AccessPlaceholderPrefix + bindings[0].handle}, brokercore.ErrBindingInvalid},
		{[]string{"Bearer " + mcpauth.AccessPlaceholderPrefix + bindings[0].handle, "Bearer ignored"}, brokercore.ErrBindingInvalid},
	} {
		if _, err := provider.Inject(brokercore.WithRequestAuthorization(ctx, tc.authorization), one.ID, "api.example.com", 443, "/items"); !errors.Is(err, tc.want) {
			t.Fatal("missing or invalid selection did not fail closed", tc.authorization, err)
		}
	}
	static := f.create(basicConnection)
	if w = f.call("PUT", f.base()+"/connections/"+static.ID+"/grants/group-one", `{}`, ""); w.Code != http.StatusConflict {
		t.Fatal("static/OAuth overlap was allowed", w.Code)
	}
	if w = f.call("GET", f.base()+"/connections/"+second.ID, "", ""); w.Code != http.StatusForbidden {
		t.Fatal("identity routing exposed another owner's management metadata", w.Code)
	}
	firstBinding := bindings[0]
	firstBase := f.base()
	if firstBinding.id == second.ID {
		firstBase = otherBase
	}
	selected := brokercore.WithRequestAuthorization(ctx, []string{"Bearer " + mcpauth.AccessPlaceholderPrefix + firstBinding.handle})
	injected, err := provider.Inject(selected, one.ID, "api.example.com", 443, "/items")
	if err != nil {
		t.Fatal(err)
	}
	if w = f.call("DELETE", firstBase+"/connections/"+firstBinding.id+"/grants/group-one", "", ""); w.Code != http.StatusNoContent {
		t.Fatal(w.Code, w.Body)
	}
	if _, err = provider.Inject(selected, one.ID, "api.example.com", 443, "/items"); !errors.Is(err, brokercore.ErrBindingInactive) {
		t.Fatal("revoked selection fell through to the other identity", err)
	}
	if _, err = provider.Inject(brokercore.WithRequestBinding(ctx, []string{firstBinding.handle}), one.ID, "api.example.com", 443, "/items"); !errors.Is(err, brokercore.ErrBindingInactive) {
		t.Fatal("revoked named MCP reference fell through to another account", err)
	}
	if err = injected.Authorize(ctx); !errors.Is(err, brokercore.ErrBindingInactive) {
		t.Fatal("in-flight selection retained revoked authority", err)
	}
	request := httptest.NewRequest(http.MethodGet, "https://api.example.com/items", nil)
	request.Header.Set("Authorization", "Bearer "+mcpauth.AccessPlaceholderPrefix+firstBinding.handle)
	if _, err := f.s.LocalTokenResponse(ctx, one.ID, request); !errors.Is(err, brokercore.ErrBindingInactive) {
		t.Fatal("local OAuth interception lost inactive binding", err)
	}
}

func TestManagedOAuthCannotOverlapStaticBinding(t *testing.T) {
	f, _, oauth, state := setupManagedOAuth(t)
	if w := f.complete(oauth, state, f.user); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	oauth, err := f.s.loadConnection(context.Background(), oauth.ID)
	if err != nil {
		t.Fatal(err)
	}
	static := f.create(basicConnection)
	if w := f.call("PUT", f.base()+"/connections/"+static.ID+"/grants/group-one", `{}`, ""); w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body)
	}
	if w := f.call("PUT", f.base()+"/connections/"+oauth.ID+"/grants/group-one",
		`{}`, ""); w.Code != http.StatusConflict {
		t.Fatal("OAuth selection was allowed to shadow static credentials", w.Code, w.Body)
	}
}
