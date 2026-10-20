package socketsessions

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/Infisical/agent-vault/internal/crypto"
	"github.com/Infisical/agent-vault/internal/ratelimit"
)

// Run with -run '^$' -bench BenchmarkInterceptedLatency -benchtime=1000x.
func BenchmarkInterceptedLatency(b *testing.B) {
	f := setup(b)
	config := f.limits.Config()
	config.Tiers[ratelimit.TierProxy].Rate = 1e9
	config.Tiers[ratelimit.TierProxy].Burst = 100000
	f.limits.Reload(config)
	item := f.create(b)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer benchmark-injected" {
			w.WriteHeader(401)
			return
		}
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	trustUpstream(b, upstream.Certificate())
	ct, nonce, err := crypto.Encrypt([]byte("benchmark-injected"), make([]byte, 32))
	if err != nil {
		b.Fatal(err)
	}
	if _, err := f.db.SetCredential(context.Background(), f.vault.ID, "BENCH_KEY", ct, nonce); err != nil {
		b.Fatal(err)
	}
	if _, err := f.db.SetBrokerConfig(context.Background(), f.vault.ID,
		`[{"name":"benchmark","host":"127.0.0.1/measure","auth":{"type":"bearer","token":"BENCH_KEY"}}]`); err != nil {
		b.Fatal(err)
	}
	direct := upstream.Client()
	defer direct.CloseIdleConnections()
	socket := socketClient(b, item.SocketPath, f.ca)
	var medians [2]time.Duration
	for i, test := range []struct {
		name   string
		client *http.Client
		direct bool
	}{
		{"direct-https", direct, true},
		{"socket-intercepted-https", socket, false},
	} {
		b.Run(test.name, func(b *testing.B) {
			request := func() {
				req, _ := http.NewRequest("GET", upstream.URL+"/measure", nil)
				if test.direct {
					req.Header.Set("Authorization", "Bearer benchmark-injected")
				}
				resp, err := test.client.Do(req)
				if err != nil {
					b.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil || resp.StatusCode != 200 || string(body) != "ok" {
					b.Fatal("latency request did not complete with verified injection")
				}
			}
			for warmup := 0; warmup < 100; warmup++ {
				request()
			}
			samples := make([]time.Duration, b.N)
			b.ResetTimer()
			for n := range samples {
				start := time.Now()
				request()
				samples[n] = time.Since(start)
			}
			b.StopTimer()
			sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
			medians[i] = samples[len(samples)/2]
			b.ReportMetric(float64(medians[i].Nanoseconds())/1e6, "p50-ms")
		})
	}
	added := medians[1] - medians[0]
	b.Logf("intercepted socket minus direct HTTPS p50: %.3f ms (keep-alive, verified injection)", float64(added.Nanoseconds())/1e6)
	if added >= 5*time.Millisecond {
		b.Fatalf("added p50 latency %.3f ms exceeds the 5 ms spike limit", float64(added.Nanoseconds())/1e6)
	}
}
