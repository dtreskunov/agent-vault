package oauthidentity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func jsonClient(value any) *http.Client {
	data, _ := json.Marshal(value)
	return &http.Client{Transport: responseTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(data))), Header: http.Header{"Content-Type": {"application/json"}}}, nil
	})}
}

func TestProviderIdentity(t *testing.T) {
	for _, test := range []struct{ provider, body, subject, label string }{
		{"google", `{"sub":"google-stable","email":"user@example.com","email_verified":true}`, "google-stable", "user@example.com"},
		{"google", `{"sub":"google-stable","email":"unverified@example.com","email_verified":false}`, "google-stable", ""},
		{"github", `{"id":12345,"login":"octocat"}`, "12345", "octocat"},
	} {
		client := &http.Client{Transport: responseTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Scheme != "https" || r.Header.Get("Authorization") != "Bearer synthetic-access" {
				t.Error("identity lookup is not authenticated HTTPS")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(test.body))}, nil
		})}
		got, err := Provider(context.Background(), client, test.provider, "synthetic-access")
		if err != nil || got.Subject != test.subject || got.Label != test.label {
			t.Fatalf("identity mismatch: %+v, %v", got, err)
		}
	}
}

func TestIdentityLookupFailure(t *testing.T) {
	client := &http.Client{Transport: responseTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("must-not-return-provider-body"))}, nil
	})}
	_, err := Provider(context.Background(), client, "google", "synthetic")
	if err == nil || strings.Contains(err.Error(), "must-not") {
		t.Fatal("identity failure missing or exposed response body")
	}
	if err := getJSON(context.Background(), client, "http://public.example.com/user", "", new(any)); err == nil {
		t.Fatal("non-TLS identity endpoint accepted")
	}
}

func TestVerifiedAndUnverifiedIDTokens(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(x any) string { data, _ := json.Marshal(x); return base64.RawURLEncoding.EncodeToString(data) }
	coordinate := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	client := jsonClient(map[string]any{"keys": []any{map[string]string{"kty": "EC", "kid": "one", "alg": "ES256", "crv": "P-256", "x": coordinate(key.X), "y": coordinate(key.Y)}}})
	now := time.Now().Truncate(time.Second)
	cfg := OIDCConfig{Issuer: "https://issuer.example", ClientID: "client", JWKSURI: "https://issuer.example/keys", Nonce: "nonce", Now: now, AccessToken: "synthetic"}
	claims := func() map[string]any {
		return map[string]any{"iss": cfg.Issuer, "sub": "stable-subject", "aud": "client", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "nonce": "nonce", "email": "signed@example.com"}
	}
	sign := func(c map[string]any, algorithm string) string {
		signed := encode(map[string]string{"alg": algorithm, "kid": "one"}) + "." + encode(c)
		hash := sha256.Sum256([]byte(signed))
		r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
	}
	valid := sign(claims(), "ES256")
	identity, err := Verify(context.Background(), client, valid, cfg)
	if err != nil || identity.Label != "signed@example.com" || identity.Subject != "stable-subject" {
		t.Fatal("verified token rejected", err)
	}
	username := claims()
	delete(username, "email")
	username["preferred_username"] = "signed-user"
	if identity, err := Verify(context.Background(), client, sign(username, "ES256"), cfg); err != nil || identity.Label != "signed-user" {
		t.Fatal("preferred_username fallback failed")
	}
	for _, change := range []func(map[string]any){
		func(c map[string]any) { c["iss"] = "https://wrong.example" },
		func(c map[string]any) { c["aud"] = "other-client" },
		func(c map[string]any) { c["aud"] = []string{"client", "other"} },
		func(c map[string]any) { c["exp"] = now.Add(-time.Second).Unix() },
		func(c map[string]any) { c["iat"] = now.Add(time.Hour).Unix() },
		func(c map[string]any) { c["nonce"] = "wrong" },
		func(c map[string]any) { delete(c, "sub") },
		func(c map[string]any) { c["at_hash"] = "wrong" },
	} {
		c := claims()
		change(c)
		if _, err := Verify(context.Background(), client, sign(c, "ES256"), cfg); err == nil {
			t.Fatal("invalid signed claims accepted")
		}
	}
	parts := strings.Split(valid, ".")
	parts[1] = encode(map[string]string{"email": "forged@example.com"})
	for _, invalid := range []string{strings.Join(parts, "."), sign(claims(), "none"), "unsigned", "a.b.c"} {
		if _, err := Verify(context.Background(), client, invalid, cfg); err == nil {
			t.Fatal("unverified ID token accepted")
		}
	}
}

func TestRS256(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	header := enc([]byte(`{"alg":"RS256","kid":"rsa"}`))
	body := enc([]byte(fmt.Sprintf(`{"iss":"https://issuer.example","sub":"s","aud":"client","iat":%d,"exp":%d}`, time.Now().Unix(), time.Now().Add(time.Hour).Unix())))
	hash := sha256.Sum256([]byte(header + "." + body))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		t.Fatal(err)
	}
	client := jsonClient(map[string]any{"keys": []any{map[string]string{"kty": "RSA", "kid": "rsa", "n": enc(key.N.Bytes()), "e": enc(big.NewInt(int64(key.E)).Bytes())}}})
	if _, err := Verify(context.Background(), client, header+"."+body+"."+enc(signature), OIDCConfig{Issuer: "https://issuer.example", ClientID: "client", JWKSURI: "https://issuer.example/keys"}); err != nil {
		t.Fatal(err)
	}
}
