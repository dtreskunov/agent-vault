package oauthidentity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type OIDCConfig struct {
	Issuer, ClientID, JWKSURI, Nonce, AccessToken string
	Now                                           time.Time
}

type jwk struct {
	Type       string   `json:"kty"`
	ID         string   `json:"kid"`
	Algorithm  string   `json:"alg"`
	Use        string   `json:"use"`
	Operations []string `json:"key_ops"`
	N          string   `json:"n"`
	E          string   `json:"e"`
	Curve      string   `json:"crv"`
	X          string   `json:"x"`
	Y          string   `json:"y"`
}

func Verify(ctx context.Context, client *http.Client, token string, cfg OIDCConfig) (Identity, error) {
	if len(token) > 65536 {
		return Identity{}, fmt.Errorf("OIDC token oversized")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Identity{}, fmt.Errorf("invalid OIDC token")
	}
	var header struct {
		Algorithm string   `json:"alg"`
		Key       string   `json:"kid"`
		Critical  []string `json:"crit"`
	}
	bytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(bytes, &header) != nil || len(header.Critical) != 0 ||
		(header.Algorithm != "RS256" && header.Algorithm != "ES256") {
		return Identity{}, fmt.Errorf("unsupported OIDC token algorithm or headers")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Identity{}, fmt.Errorf("invalid OIDC signature encoding")
	}
	var keys struct {
		Keys []jwk `json:"keys"`
	}
	if err := getJSON(ctx, client, cfg.JWKSURI, "", &keys); err != nil {
		return Identity{}, err
	}
	if len(keys.Keys) > 100 {
		return Identity{}, fmt.Errorf("oversized OIDC key set")
	}
	hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	matches := 0
	var selected jwk
	for _, key := range keys.Keys {
		if header.Key != "" && key.ID != header.Key {
			continue
		}
		if key.Algorithm != "" && key.Algorithm != header.Algorithm {
			continue
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if len(key.Operations) > 0 {
			verify := false
			for _, operation := range key.Operations {
				verify = verify || operation == "verify"
			}
			if !verify {
				continue
			}
		}
		if (header.Algorithm == "RS256" && key.Type != "RSA") || (header.Algorithm == "ES256" && key.Type != "EC") {
			continue
		}
		matches++
		selected = key
	}
	if matches != 1 {
		return Identity{}, fmt.Errorf("OIDC signing key is missing or ambiguous")
	}
	if err := verifySignature(selected, header.Algorithm, hash[:], signature); err != nil {
		return Identity{}, fmt.Errorf("OIDC signature verification failed")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Identity{}, fmt.Errorf("invalid OIDC claims encoding")
	}
	var claims struct {
		Issuer          string          `json:"iss"`
		Subject         string          `json:"sub"`
		Audience        json.RawMessage `json:"aud"`
		AuthorizedParty string          `json:"azp"`
		Expires         int64           `json:"exp"`
		Issued          int64           `json:"iat"`
		NotBefore       int64           `json:"nbf"`
		Nonce           string          `json:"nonce"`
		AccessHash      string          `json:"at_hash"`
		Email           string          `json:"email"`
		Verified        *bool           `json:"email_verified"`
		Username        string          `json:"preferred_username"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return Identity{}, fmt.Errorf("invalid OIDC claims")
	}
	now := cfg.Now
	if now.IsZero() {
		now = time.Now()
	}
	var audience []string
	var single string
	if json.Unmarshal(claims.Audience, &single) == nil {
		audience = []string{single}
	} else if json.Unmarshal(claims.Audience, &audience) != nil {
		return Identity{}, fmt.Errorf("invalid OIDC audience")
	}
	found := false
	for _, item := range audience {
		found = found || item == cfg.ClientID
	}
	if cfg.Issuer == "" || cfg.ClientID == "" || claims.Issuer != cfg.Issuer || claims.Subject == "" || !found ||
		(len(audience) > 1 && claims.AuthorizedParty != cfg.ClientID) || (claims.AuthorizedParty != "" && claims.AuthorizedParty != cfg.ClientID) ||
		claims.Expires <= now.Unix() || claims.Issued <= 0 || claims.Issued > now.Add(time.Minute).Unix() ||
		claims.NotBefore > now.Add(time.Minute).Unix() || (cfg.Nonce != "" && claims.Nonce != cfg.Nonce) {
		return Identity{}, fmt.Errorf("OIDC issuer, audience, time or nonce validation failed")
	}
	if claims.AccessHash != "" {
		sum := sha256.Sum256([]byte(cfg.AccessToken))
		if cfg.AccessToken == "" || claims.AccessHash != base64.RawURLEncoding.EncodeToString(sum[:16]) {
			return Identity{}, fmt.Errorf("OIDC access-token hash mismatch")
		}
	}
	label := claims.Email
	if label == "" || (claims.Verified != nil && !*claims.Verified) {
		label = claims.Username
	}
	return Identity{Subject: claims.Subject, Label: label}, nil
}

func integer(encoded string) (*big.Int, error) {
	bytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(bytes) == 0 || len(bytes) > 1024 {
		return nil, fmt.Errorf("invalid OIDC public key")
	}
	return new(big.Int).SetBytes(bytes), nil
}

func verifySignature(key jwk, algorithm string, hash, signature []byte) error {
	switch algorithm {
	case "RS256":
		n, err := integer(key.N)
		if err != nil {
			return err
		}
		e, err := integer(key.E)
		if err != nil || !e.IsInt64() {
			return fmt.Errorf("invalid RSA exponent")
		}
		exponent := e.Int64()
		if n.BitLen() < 2048 || exponent < 3 || exponent > 2147483647 || exponent%2 == 0 {
			return fmt.Errorf("unsafe RSA public key")
		}
		return rsa.VerifyPKCS1v15(&rsa.PublicKey{N: n, E: int(exponent)}, crypto.SHA256, hash, signature)
	case "ES256":
		if key.Curve != "P-256" || len(signature) != 64 {
			return fmt.Errorf("invalid EC signing parameters")
		}
		x, err := integer(key.X)
		if err != nil {
			return err
		}
		y, err := integer(key.Y)
		if err != nil {
			return err
		}
		curve := elliptic.P256()
		if !curve.IsOnCurve(x, y) {
			return fmt.Errorf("invalid EC point")
		}
		if !ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: x, Y: y}, hash, new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
			return fmt.Errorf("invalid ECDSA signature")
		}
		return nil
	}
	return fmt.Errorf("unsupported signing algorithm")
}
