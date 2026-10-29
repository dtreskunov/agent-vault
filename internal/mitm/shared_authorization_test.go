package mitm

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
)

func TestSharedAuthorizationRevokesStreamingResponse(t *testing.T) {
	closed := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer synthetic-shared-token" {
			t.Error("shared credential missing")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "ready\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(closed)
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	var active atomic.Bool
	active.Store(true)
	result := &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer synthetic-shared-token"}, Authorize: func(context.Context) error {
		if !active.Load() {
			return errors.New("shared grant revoked")
		}
		return nil
	}}
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{target.Hostname(): {result: result}}}
	proxyURL, _, _ := setupProxy(t, validTokenResolver("token", &brokercore.ProxyScope{VaultID: "group", VaultName: "group"}), cp)
	proxyURL.User = url.User("token")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	response, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data := make([]byte, len("ready\n"))
	if _, err = io.ReadFull(response.Body, data); err != nil || string(data) != "ready\n" {
		t.Fatal("stream did not open", err)
	}
	active.Store(false)
	_, err = io.ReadAll(response.Body)
	if err == nil {
		t.Fatal("revoked stream ended as success-shaped response")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("revoked upstream stream was left connected")
	}
}

func TestSharedAuthorizationRejectsAfterBodyResolution(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	var checks atomic.Int32
	result := &brokercore.InjectResult{Headers: map[string]string{"Authorization": "Bearer synthetic-shared-token"}, Authorize: func(context.Context) error {
		if checks.Add(1) > 1 {
			return brokercore.ErrServiceDisabled
		}
		return nil
	}}
	cp := &fakeCredProvider{byHost: map[string]fakeInjectResult{target.Hostname(): {result: result}}}
	proxyURL, _, _ := setupProxy(t, validTokenResolver("token", &brokercore.ProxyScope{VaultID: "group", VaultName: "group"}), cp)
	proxyURL.User = url.User("token")
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, Timeout: 5 * time.Second}
	response, err := client.Post(upstream.URL, "text/plain", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 || calls.Load() != 0 {
		t.Fatal("request accepted after final authorization was revoked", response.StatusCode, calls.Load())
	}
}
