// Package blindtunnel implements vault-scoped CONNECT routing without TLS termination.
package blindtunnel

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/Infisical/agent-vault/internal/broker"
	"github.com/Infisical/agent-vault/internal/store"
)

type Mode string

const (
	Tunnel Mode = "tunnel"
	MITM   Mode = "mitm"
	Deny   Mode = "deny"
	key         = "unmatched_host_mode"
)

var ErrInvalidMode = errors.New("unmatched_host_mode must be tunnel, mitm or deny")

type Settings interface {
	GetVaultSetting(context.Context, string, string) (string, error)
	SetVaultSetting(context.Context, string, string, string) error
	DeleteVaultSetting(context.Context, string, string) error
}

func Parse(value string) (Mode, error) {
	mode := Mode(value)
	if mode != Tunnel && mode != MITM && mode != Deny {
		return "", ErrInvalidMode
	}
	return mode, nil
}

func Default() (Mode, error) {
	value := os.Getenv("AGENT_VAULT_UNMATCHED_HOST_MODE")
	if value == "" {
		return MITM, nil
	}
	return Parse(value)
}

func Read(ctx context.Context, db Settings, vault string) (Mode, error) {
	raw, err := db.GetVaultSetting(ctx, vault, key)
	if errors.Is(err, sql.ErrNoRows) {
		return Default()
	}
	if err != nil {
		return "", err
	}
	return Parse(raw)
}

// An empty update removes the override and uses the instance default.
func Update(ctx context.Context, db Settings, vault, value string) (Mode, error) {
	var mode Mode
	var err error
	if value == "" {
		mode, err = Default()
		if err == nil {
			err = db.DeleteVaultSetting(ctx, vault, key)
		}
	} else {
		mode, err = Parse(value)
		if err == nil {
			err = db.SetVaultSetting(ctx, vault, key, value)
		}
	}
	return mode, err
}

type Policy struct {
	Store interface {
		Settings
		GetBrokerConfig(context.Context, string) (*store.BrokerConfig, error)
	}
}

func (p Policy) Decide(ctx context.Context, vault, host string, port int) (Mode, error) {
	cfg, err := p.Store.GetBrokerConfig(ctx, vault)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("reading CONNECT services: %w", err)
	}
	var services []broker.Service
	if cfg != nil && cfg.ServicesJSON != "" {
		if err := json.Unmarshal([]byte(cfg.ServicesJSON), &services); err != nil {
			return "", fmt.Errorf("parsing CONNECT services: %w", err)
		}
	}
	for i := range services {
		name, _, port := broker.SplitInlineHost(services[i].Host, services[i].Path)
		services[i].Host = canonicalHost(name)
		services[i].Path = "" // Any path, including disabled services, requires interception.
		services[i].Port = port
	}
	if matched, _ := broker.MatchService(canonicalHost(host), port, "/", services); matched != nil {
		return MITM, nil
	}
	return Read(ctx, p.Store, vault)
}

func canonicalHost(host string) string {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return strings.ToLower(host)
}
