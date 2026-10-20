package blindtunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/Infisical/agent-vault/internal/brokercore"
	"github.com/Infisical/agent-vault/internal/netguard"
	"github.com/Infisical/agent-vault/internal/ratelimit"
	"github.com/Infisical/agent-vault/internal/requestlog"
)

// Handle returns false only when the caller should continue with TLS interception.
func Handle(mode Mode, w http.ResponseWriter, r *http.Request, host string, port int, scope *brokercore.ProxyScope,
	logger *slog.Logger, sink requestlog.Sink, limits *ratelimit.Registry, lifetime context.Context) bool {
	if mode == MITM {
		return false
	}
	start := time.Now()
	target := net.JoinHostPort(host, strconv.Itoa(port))
	status, errorCode := http.StatusOK, ""
	var sent, received int64
	defer func() {
		logger.Info("CONNECT decision", "decision", string(mode), "vault", scope.VaultName,
			"host", host, "port", port, "bytes_sent", sent, "bytes_received", received,
			"duration_ms", float64(time.Since(start).Microseconds())/1000, "status", status, "error", errorCode)
		actorID, actorType := scope.AgentID, brokercore.ActorTypeAgent
		if scope.UserID != "" {
			actorID, actorType = scope.UserID, brokercore.ActorTypeUser
		}
		if sink != nil {
			sink.Record(context.WithoutCancel(r.Context()), requestlog.Record{
				VaultID: scope.VaultID, ActorID: actorID, ActorType: actorType,
				Ingress: brokercore.IngressMITM, Method: http.MethodConnect, Host: target,
				Status: status, ErrorCode: errorCode, LatencyMs: time.Since(start).Milliseconds(),
			})
		}
	}()
	if mode == Deny {
		status, errorCode = http.StatusForbidden, "no_match"
		http.Error(w, "unmatched CONNECT host denied", status)
		return true
	}
	if mode != Tunnel {
		status, errorCode = http.StatusInternalServerError, "invalid_tunnel_mode"
		http.Error(w, "invalid CONNECT policy", status)
		return true
	}
	enforcement := limits.EnforceProxy(r.Context(), scope.ActorID(), scope.VaultID)
	if !enforcement.Allowed {
		status, errorCode = http.StatusTooManyRequests, enforcement.ErrCode
		ratelimit.WriteDenial(w, enforcement.Decision, enforcement.Message)
		return true
	}
	defer enforcement.Release()
	upstream, err := netguard.SafeDialContext(netguard.AllowPrivateFromEnv())(r.Context(), "tcp", target)
	if err != nil {
		status, errorCode = http.StatusBadGateway, "tunnel_dial_failed"
		logger.Warn("CONNECT dial failed", "host", host, "port", port, "err", err)
		http.Error(w, "upstream connection failed", status)
		return true
	}
	defer upstream.Close()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		status, errorCode = http.StatusInternalServerError, "hijack_not_supported"
		http.Error(w, "hijacking not supported", status)
		return true
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		status, errorCode = http.StatusInternalServerError, "hijack_failed"
		logger.Warn("CONNECT hijack failed", "err", err)
		return true
	}
	defer client.Close()
	stop := context.AfterFunc(lifetime, func() {
		client.Close()
		upstream.Close()
	})
	defer stop()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		errorCode = "tunnel_write_failed"
		return true
	}
	type result struct {
		n   int64
		err error
	}
	out := make(chan result, 1)
	in := make(chan result, 1)
	copyTo := func(dst net.Conn, src io.Reader, done chan<- result) {
		n, err := io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			err = errors.Join(err, closer.CloseWrite())
		} else {
			err = errors.Join(err, dst.Close())
		}
		if err != nil {
			client.Close()
			upstream.Close()
		}
		done <- result{n, err}
	}
	// buffered.Reader preserves bytes sent immediately after the CONNECT headers.
	go copyTo(upstream, buffered.Reader, out)
	go copyTo(client, upstream, in)
	outcome, income := <-out, <-in
	sent, received = outcome.n, income.n
	if err := errors.Join(outcome.err, income.err); err != nil && !errors.Is(err, net.ErrClosed) {
		errorCode = "tunnel_copy_failed"
		logger.Debug("CONNECT stream ended", "host", host, "err", err)
	}
	return true
}
