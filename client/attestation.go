package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TokenStage identifies which step of the attestation workflow is requesting a token.
type TokenStage string

const (
	StageHandshake     TokenStage = "handshake"
	StageAttest        TokenStage = "attest"
	StageReauth        TokenStage = "reauth"
	attestEnvStage                = "NEXUS_ATTESTATION_STAGE"
	attestEnvNonce                = "NEXUS_SESSION_NONCE"
	attestEnvBackend              = "NEXUS_BACKEND_NAME"
	attestEnvHostnames            = "NEXUS_HOSTNAMES"
	attestEnvWeight               = "NEXUS_WEIGHT"
)

// Token encapsulates the token value and an optional expiry.
type Token struct {
	Value  string
	Expiry time.Time
}

// TokenRequest conveys the contextual information for issuing a token.
type TokenRequest struct {
	Stage        TokenStage
	SessionNonce string
	BackendName  string
	Hostnames    []string
	Weight       int
}

// TokenProvider issues attestation tokens for a given request.
type TokenProvider interface {
	IssueToken(ctx context.Context, req TokenRequest) (Token, error)
}

// AttestationOptions contains configuration for generating attestation tokens.
type AttestationOptions struct {
	Command                    string
	Args                       []string
	Env                        map[string]string
	Timeout                    time.Duration
	CacheHandshake             time.Duration
	HMACSecret                 string
	HMACSecretFile             string
	TokenTTL                   time.Duration
	HandshakeMaxAgeSeconds     int
	ReauthIntervalSeconds      int
	ReauthGraceSeconds         int
	MaintenanceGraceCapSeconds int
	AuthorizerStatusURI        string
	PolicyVersion              string
}

// CommandTokenProvider implements TokenProvider by invoking an external command.
type CommandTokenProvider struct {
	cfg            AttestationOptions
	handshakeCache tokenCache
}

// tokenCache stores a cached token until its expiry.
type tokenCache struct {
	token  Token
	expiry time.Time
}

func (tc *tokenCache) get(now time.Time) (Token, bool) {
	if tc.expiry.IsZero() {
		return Token{}, false
	}
	if now.After(tc.expiry) {
		return Token{}, false
	}
	return tc.token, true
}

func (tc *tokenCache) set(tok Token, ttl time.Duration) {
	if tok.Value == "" {
		tc.token = Token{}
		tc.expiry = time.Time{}
		return
	}
	tc.token = tok
	if tok.Expiry.IsZero() {
		if ttl <= 0 {
			tc.expiry = time.Time{}
			return
		}
		tc.expiry = time.Now().Add(ttl)
		return
	}
	tc.expiry = tok.Expiry
}

// NewCommandTokenProvider returns a TokenProvider backed by an external command.
func NewCommandTokenProvider(cfg AttestationOptions) (*CommandTokenProvider, error) {
	if strings.TrimSpace(cfg.Command) == "" {
		return nil, fmt.Errorf("attestation command is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &CommandTokenProvider{cfg: cfg}, nil
}

// IssueToken invokes the configured command to retrieve an attestation token.
func (c *CommandTokenProvider) IssueToken(ctx context.Context, req TokenRequest) (Token, error) {
	if req.Stage == StageHandshake && c.cfg.CacheHandshake > 0 {
		if tok, ok := c.handshakeCache.get(time.Now()); ok {
			return tok, nil
		}
	}

	cmdCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, c.cfg.Command, c.cfg.Args...)
	cmd.Env = append(os.Environ(), formatEnv(c.cfg.Env)...)
	cmd.Env = append(cmd.Env,
		fmt.Sprintf("%s=%s", attestEnvStage, string(req.Stage)),
		fmt.Sprintf("%s=%s", attestEnvBackend, req.BackendName),
		fmt.Sprintf("%s=%s", attestEnvHostnames, strings.Join(req.Hostnames, ",")),
		fmt.Sprintf("%s=%d", attestEnvWeight, req.Weight),
	)
	if req.Stage != StageHandshake {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", attestEnvNonce, req.SessionNonce))
	} else {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=", attestEnvNonce))
	}

	out, err := cmd.CombinedOutput()
	if ctxErr := cmdCtx.Err(); ctxErr != nil && ctxErr != context.Canceled {
		return Token{}, fmt.Errorf("attestation command timed out: %w", ctxErr)
	}
	if err != nil {
		return Token{}, fmt.Errorf("attestation command failed: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	tok, err := parseTokenOutput(out)
	if err != nil {
		return Token{}, err
	}

	if req.Stage == StageHandshake && c.cfg.CacheHandshake > 0 && tok.Value != "" {
		c.handshakeCache.set(tok, c.cfg.CacheHandshake)
	}

	return tok, nil
}

func formatEnv(extra map[string]string) []string {
	if len(extra) == 0 {
		return nil
	}
	out := make([]string, 0, len(extra))
	for k, v := range extra {
		out = append(out, fmt.Sprintf("%s=%s", k, v))
	}
	return out
}

func parseTokenOutput(raw []byte) (Token, error) {
	payload := strings.TrimSpace(string(raw))
	if payload == "" {
		return Token{}, fmt.Errorf("attestation command returned empty token")
	}

	if strings.HasPrefix(payload, "{") {
		var resp struct {
			Token  string `json:"token"`
			Expiry string `json:"expiry"`
		}
		if err := json.Unmarshal([]byte(payload), &resp); err != nil {
			return Token{}, fmt.Errorf("failed to decode attestation command JSON: %w", err)
		}
		if strings.TrimSpace(resp.Token) == "" {
			return Token{}, fmt.Errorf("attestation command JSON missing token")
		}
		tok := Token{Value: strings.TrimSpace(resp.Token)}
		if resp.Expiry != "" {
			if ts, err := time.Parse(time.RFC3339, resp.Expiry); err == nil {
				tok.Expiry = ts
			}
		}
		return tok, nil
	}

	lines := strings.Split(payload, "\n")
	tokenValue := strings.TrimSpace(lines[0])
	if tokenValue == "" {
		return Token{}, fmt.Errorf("attestation command output did not contain a token")
	}
	return Token{Value: tokenValue}, nil
}

// HMACTokenProvider produces tokens signed with a shared secret.
type HMACTokenProvider struct {
	secret         []byte
	opts           AttestationOptions
	backendName    string
	hostnames      []string
	weight         int
	handshakeCache tokenCache
}

// NewHMACTokenProvider returns a TokenProvider that signs JWTs locally using HS256.
func NewHMACTokenProvider(opts AttestationOptions, backendName string, hostnames []string, weight int) (*HMACTokenProvider, error) {
	secret := strings.TrimSpace(opts.HMACSecret)
	if opts.HMACSecretFile != "" {
		data, err := os.ReadFile(opts.HMACSecretFile)
		if err != nil {
			return nil, fmt.Errorf("read hmac secret file: %w", err)
		}
		secret = strings.TrimSpace(string(bytes.TrimSpace(data)))
	}
	if secret == "" {
		return nil, errors.New("hmac secret is required")
	}

	provider := &HMACTokenProvider{
		secret:      []byte(secret),
		opts:        opts,
		backendName: backendName,
		hostnames:   append([]string(nil), hostnames...),
		weight:      weight,
	}
	return provider, nil
}

// IssueToken signs a JWT that encodes the attestation claims expected by Nexus.
func (h *HMACTokenProvider) IssueToken(ctx context.Context, req TokenRequest) (Token, error) {
	if req.Stage == StageHandshake && h.opts.CacheHandshake > 0 {
		if tok, ok := h.handshakeCache.get(time.Now()); ok {
			return tok, nil
		}
	}

	now := time.Now()
	ttl := h.opts.TokenTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	exp := now.Add(ttl)

	claims := attestationClaims{
		Hostnames: append([]string(nil), h.hostnames...),
		Weight:    h.weight,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "authorizer",
			Subject:   h.backendName,
			Audience:  jwt.ClaimStrings{"nexus"},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
	}

	if req.Stage != StageHandshake {
		claims.SessionNonce = req.SessionNonce
	} else if h.opts.HandshakeMaxAgeSeconds > 0 {
		claims.HandshakeMaxAgeSeconds = optionalInt(h.opts.HandshakeMaxAgeSeconds)
	}

	if h.opts.ReauthIntervalSeconds > 0 {
		claims.ReauthIntervalSeconds = optionalInt(h.opts.ReauthIntervalSeconds)
	}
	if h.opts.ReauthGraceSeconds > 0 {
		claims.ReauthGraceSeconds = optionalInt(h.opts.ReauthGraceSeconds)
	}
	if h.opts.MaintenanceGraceCapSeconds > 0 {
		claims.MaintenanceGraceCapSeconds = optionalInt(h.opts.MaintenanceGraceCapSeconds)
	}
	if h.opts.AuthorizerStatusURI != "" {
		claims.AuthorizerStatusURI = h.opts.AuthorizerStatusURI
	}
	if h.opts.PolicyVersion != "" {
		claims.PolicyVersion = h.opts.PolicyVersion
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(h.secret)
	if err != nil {
		return Token{}, fmt.Errorf("sign token: %w", err)
	}

	result := Token{Value: signed, Expiry: exp}
	if req.Stage == StageHandshake && h.opts.CacheHandshake > 0 {
		h.handshakeCache.set(result, h.opts.CacheHandshake)
	}

	return result, nil
}

func optionalInt(val int) *int {
	if val <= 0 {
		return nil
	}
	v := val
	return &v
}

type attestationClaims struct {
	Hostnames                  []string `json:"hostnames"`
	Weight                     int      `json:"weight"`
	SessionNonce               string   `json:"session_nonce,omitempty"`
	HandshakeMaxAgeSeconds     *int     `json:"handshake_max_age_seconds,omitempty"`
	ReauthIntervalSeconds      *int     `json:"reauth_interval_seconds,omitempty"`
	ReauthGraceSeconds         *int     `json:"reauth_grace_seconds,omitempty"`
	MaintenanceGraceCapSeconds *int     `json:"maintenance_grace_cap_seconds,omitempty"`
	AuthorizerStatusURI        string   `json:"authorizer_status_uri,omitempty"`
	PolicyVersion              string   `json:"policy_version,omitempty"`
	jwt.RegisteredClaims
}
