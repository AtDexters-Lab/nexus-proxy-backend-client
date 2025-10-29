package client

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestHMACTokenProviderProducesExpectedClaims(t *testing.T) {
	opts := AttestationOptions{
		HMACSecret:                 "super-secret",
		TokenTTL:                   60 * time.Second,
		ReauthIntervalSeconds:      300,
		ReauthGraceSeconds:         20,
		MaintenanceGraceCapSeconds: 600,
		HandshakeMaxAgeSeconds:     5,
	}

	provider, err := NewHMACTokenProvider(opts, "backend", []string{"example.com"}, 2)
	if err != nil {
		t.Fatalf("failed to build provider: %v", err)
	}

	handshake, err := provider.IssueToken(context.Background(), TokenRequest{
		Stage:       StageHandshake,
		BackendName: "backend",
		Hostnames:   []string{"example.com"},
		Weight:      2,
	})
	if err != nil {
		t.Fatalf("handshake token failed: %v", err)
	}

	parse := func(tok string) jwt.MapClaims {
		parser := jwt.NewParser()
		token, _, err := parser.ParseUnverified(tok, jwt.MapClaims{})
		if err != nil {
			t.Fatalf("failed to parse token: %v", err)
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			t.Fatalf("unexpected claims type: %T", token.Claims)
		}
		return claims
	}

	handshakeClaims := parse(handshake.Value)
	if _, ok := handshakeClaims["session_nonce"]; ok {
		t.Fatalf("expected handshake token to omit session_nonce")
	}
	if handshakeClaims["weight"].(float64) != 2 {
		t.Fatalf("expected weight=2, got %v", handshakeClaims["weight"])
	}

	reauth, err := provider.IssueToken(context.Background(), TokenRequest{
		Stage:        StageReauth,
		BackendName:  "backend",
		Hostnames:    []string{"example.com"},
		Weight:       2,
		SessionNonce: "nonce123",
	})
	if err != nil {
		t.Fatalf("reauth token failed: %v", err)
	}

	reauthClaims := parse(reauth.Value)
	if got := reauthClaims["session_nonce"]; got != "nonce123" {
		t.Fatalf("expected session_nonce 'nonce123', got %v", got)
	}
	if got := reauthClaims["reauth_interval_seconds"]; got != float64(300) {
		t.Fatalf("expected reauth interval claim, got %v", got)
	}
}
