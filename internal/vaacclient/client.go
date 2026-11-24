// Package vaacclient implements the commercial-cloud Teams Voice Applications
// Analytics Collector read transport. The wire contract is derived from static
// inspection of the Phenisys Collector 2.12.1 release and Microsoft's VAAC report
// template 3.3.2, not from a live tenant. Neither host is configurable.
package vaacclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	loginOrigin    = "https://login.microsoftonline.com"
	resource       = "https://api.interfaces.records.teams.microsoft.com"
	analytics      = resource + "/Teams.VoiceAnalytics/getanalytics"
	publicClientID = "a672d62c-fc7b-4e81-a576-e60dc46e951d" // Microsoft's public client ID, not a secret.
	maxSecretBytes = 8 << 10
	maxTokenBytes  = 64 << 10
)

var tenantGUID = regexp.MustCompile(`^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$`)

// RFC 6750 b64token. Reject error text or malformed tokens before they can
// enter an analytics request, without including the value in a diagnostic.
var bearerToken = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

// Client uses a separately obtained, short-lived user token, never the Graph
// poller's credential. It keeps neither raw secret in memory between requests.
type Client struct {
	tokenURL, usernameFile, passwordFile string
	http                                 *http.Client
	mu                                   sync.Mutex
	token                                string
	expires                              time.Time
}

// New constructs a client without reading secrets or making requests. Tests
// replace only RoundTripper; the real endpoint, redirect policy and decoder
// are exercised unchanged. A nil transport uses direct HTTPS without proxies.
func New(tenantID, usernameFile, passwordFile string, transport http.RoundTripper) (*Client, error) {
	if !tenantGUID.MatchString(tenantID) {
		return nil, errors.New("VAAC requires an Entra tenant GUID")
	}
	if !ValidSecretPath(usernameFile) || !ValidSecretPath(passwordFile) || usernameFile == passwordFile {
		return nil, errors.New("VAAC requires distinct absolute username and password file paths")
	}
	if transport == nil {
		// Use a dedicated, non-instrumented transport. Request URLs and any
		// response content must not be captured by Graph or OTEL middleware.
		transport = &http.Transport{MaxIdleConns: 2, IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second}
	}
	return &Client{
		tokenURL: loginOrigin + "/" + tenantID + "/oauth2/token", usernameFile: usernameFile, passwordFile: passwordFile,
		http: &http.Client{Transport: transport, Timeout: 45 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// ValidSecretPath rejects relative paths, URLs and control characters without
// echoing the supplied string. Mounted Kubernetes/Docker symlinks are allowed.
func ValidSecretPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator) &&
		strings.TrimSpace(path) == path && !strings.ContainsAny(path, "\x00\r\n")
}

func readSecret(path, field string) (string, error) {
	bad := fmt.Errorf("VAAC %s must be a readable, nonempty regular secret file", field)
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", bad
	}
	f, err := os.Open(path)
	if err != nil {
		return "", bad
	}
	defer f.Close()
	if opened, err := f.Stat(); err != nil || !opened.Mode().IsRegular() {
		return "", bad
	}
	data, err := readBounded(f, maxSecretBytes)
	if err != nil {
		return "", bad
	}
	// Remove the mounted-file line ending, without altering a password's spaces.
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", bad
	}
	return value, nil
}

func readBounded(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("VAAC response read failed or exceeded limit")
	}
	return data, nil
}

func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Now().Before(c.expires) && c.token != "" {
		return c.token, nil
	}
	username, err := readSecret(c.usernameFile, "username_file")
	if err != nil {
		return "", err
	}
	password, err := readSecret(c.passwordFile, "password_file")
	if err != nil {
		return "", err
	}
	form := url.Values{"client_id": {publicClientID}, "scope": {"user_impersonation"}, "grant_type": {"password"},
		"resource": {resource}, "username": {username}, "password": {password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("VAAC token request could not be built")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.send(req, "token")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := readBounded(resp.Body, maxTokenBytes)
	if err != nil {
		return "", errors.New("VAAC token response read failed or exceeded limit")
	}
	var decoded struct {
		Token   string          `json:"access_token"`
		Expires json.RawMessage `json:"expires_in"`
	}
	if json.Unmarshal(body, &decoded) != nil || !bearerToken.MatchString(decoded.Token) {
		return "", errors.New("VAAC token response is malformed")
	}
	// Entra v1 typically sends a string. Unknown lifetimes are not cached.
	var ttl json.Number
	if json.Unmarshal(decoded.Expires, &ttl) == nil {
		if seconds, err := ttl.Int64(); err == nil && seconds > 60 && seconds <= 86400 {
			c.token, c.expires = decoded.Token, time.Now().Add(time.Duration(seconds-60)*time.Second)
		}
	}
	return decoded.Token, nil
}

// send encloses all HTTP failures in a fixed operation and numeric status.
// In particular an http.Client error wraps the full URL and can carry text
// supplied by the transport; a non-success body could echo the credentials.
func (c *Client) send(req *http.Request, operation string) (*http.Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return nil, req.Context().Err()
		}
		return nil, fmt.Errorf("VAAC %s transport failed", operation)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, statusError{operation: operation, code: resp.StatusCode}
	}
	return resp, nil
}

type statusError struct {
	operation string
	code      int
}

func (e statusError) Error() string {
	return fmt.Sprintf("VAAC %s returned HTTP %d", e.operation, e.code)
}
