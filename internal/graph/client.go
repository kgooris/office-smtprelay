// Package graph sends RFC 5322 messages through the Microsoft Graph
// "sendMail" endpoint using the OAuth 2.0 client credentials flow.
package graph

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultAuthority = "https://login.microsoftonline.com"
	defaultGraphBase = "https://graph.microsoft.com"
	graphScope       = "https://graph.microsoft.com/.default"
)

// Credentials identify the Entra ID app registration.
type Credentials struct {
	TenantID     string
	ClientID     string
	ClientSecret string
}

// Error is returned when Microsoft answers with a non-success status.
type Error struct {
	Status  int    // HTTP status code
	Code    string // Graph / Entra error code, if present
	Message string
	// RetryAfter is set for throttling (429) and some 503 answers.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	return fmt.Sprintf("graph: HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// HTTPStatus returns the HTTP status code of the failed request.
func (e *Error) HTTPStatus() int { return e.Status }

// Temporary reports whether retrying later may succeed.
func (e *Error) Temporary() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// Client talks to Entra ID (token) and Microsoft Graph (sendMail).
// The zero value is not usable; use New.
type Client struct {
	creds     Credentials
	http      *http.Client
	authority string
	graphBase string

	mu      sync.Mutex
	token   string
	expires time.Time
	now     func() time.Time
}

// Option customises a Client (mainly for tests).
type Option func(*Client)

// WithHTTPClient sets the HTTP client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithEndpoints overrides the Entra authority and Graph base URLs.
func WithEndpoints(authority, graphBase string) Option {
	return func(c *Client) {
		c.authority = strings.TrimRight(authority, "/")
		c.graphBase = strings.TrimRight(graphBase, "/")
	}
}

// New creates a Client.
func New(creds Credentials, opts ...Option) *Client {
	c := &Client{
		creds:     creds,
		http:      &http.Client{Timeout: 60 * time.Second},
		authority: defaultAuthority,
		graphBase: defaultGraphBase,
		now:       time.Now,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// SendMIME sends a complete MIME message as the given mailbox.
// The sender must be an existing mailbox in the tenant.
func (c *Client) SendMIME(ctx context.Context, sender string, mime []byte) error {
	if sender == "" {
		return errors.New("graph: empty sender")
	}
	err := c.send(ctx, sender, mime, false)
	var ge *Error
	if errors.As(err, &ge) && ge.Status == http.StatusUnauthorized {
		// Token may have been revoked or rotated: fetch a new one once.
		err = c.send(ctx, sender, mime, true)
	}
	return err
}

// CheckCredentials requests a token without sending mail. It validates the
// tenant ID, client ID and client secret.
func (c *Client) CheckCredentials(ctx context.Context) error {
	_, err := c.accessToken(ctx, true)
	return err
}

func (c *Client) send(ctx context.Context, sender string, mime []byte, forceToken bool) error {
	tok, err := c.accessToken(ctx, forceToken)
	if err != nil {
		return err
	}
	body := base64.StdEncoding.EncodeToString(mime)
	u := c.graphBase + "/v1.0/users/" + url.PathEscape(sender) + "/sendMail"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "text/plain")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("graph: sendMail request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return parseError(resp)
}

func (c *Client) accessToken(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && c.now().Before(c.expires.Add(-60*time.Second)) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.creds.ClientID},
		"client_secret": {c.creds.ClientSecret},
		"scope":         {graphScope},
	}
	u := c.authority + "/" + url.PathEscape(c.creds.TenantID) + "/oauth2/v2.0/token"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("graph: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", parseError(resp)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tr); err != nil || tr.AccessToken == "" {
		return "", errors.New("graph: invalid token response")
	}
	c.token = tr.AccessToken
	c.expires = c.now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	return c.token, nil
}

// parseError understands both Graph ({"error":{"code","message"}}) and
// Entra token errors ({"error":"invalid_client","error_description":"..."}).
func parseError(resp *http.Response) *Error {
	e := &Error{Status: resp.StatusCode}
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		var secs int
		if _, err := fmt.Sscanf(ra, "%d", &secs); err == nil && secs > 0 {
			e.RetryAfter = time.Duration(secs) * time.Second
		}
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var graphErr struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &graphErr) == nil && graphErr.Error.Code != "" {
		e.Code, e.Message = graphErr.Error.Code, graphErr.Error.Message
		return e
	}
	var entraErr struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(raw, &entraErr) == nil && entraErr.Error != "" {
		e.Code, e.Message = entraErr.Error, firstLine(entraErr.Description)
		return e
	}
	e.Message = firstLine(string(raw))
	return e
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
