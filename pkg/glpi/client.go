package glpi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/x1thexxx-lgtm/goscanner/pkg/config"
	"github.com/x1thexxx-lgtm/goscanner/pkg/inventory"
)

// Client interacts with GLPI REST API.
type Client struct {
	cfg        config.GLPIConfig
	baseURL    string
	httpClient *http.Client
	token      string
	tokenUntil time.Time
	mu         sync.Mutex
}

// NewClient builds a GLPI client.
func NewClient(cfg config.GLPIConfig) *Client {
	return &Client{cfg: cfg, baseURL: sanitizeBaseURL(cfg.BaseURL), httpClient: &http.Client{}}
}

// UpsertAsset sends inventory data to GLPI.
func (c *Client) UpsertAsset(ctx context.Context, asset inventory.AssetModel) error {
	if c.baseURL == "" {
		return fmt.Errorf("glpi base url not configured")
	}
	if err := c.ensureAuth(ctx); err != nil {
		return err
	}
	body, err := json.Marshal(asset)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/inventory", c.baseURL), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.useOAuth() {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else {
		req.Header.Set("Session-Token", c.token)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("glpi upsert failed: %s", resp.Status)
	}
	return nil
}

func (c *Client) ensureAuth(ctx context.Context) error {
	if c.useOAuth() {
		return c.ensureOAuthToken(ctx)
	}
	return c.ensureLegacySession(ctx)
}

func (c *Client) ensureLegacySession(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" {
		return nil
	}
	if c.cfg.UserToken == "" {
		return fmt.Errorf("glpi user token missing")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s/initSession", c.baseURL), nil)
	if err != nil {
		return err
	}
	if c.cfg.AppToken != "" {
		req.Header.Set("App-Token", c.cfg.AppToken)
	}
	req.Header.Set("Authorization", "user_token "+c.cfg.UserToken)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("glpi init session failed: %s: %s", resp.Status, string(body))
	}
	var payload struct {
		SessionToken string `json:"session_token"`
		Message      string `json:"message"`
		Status       string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.SessionToken == "" {
		return fmt.Errorf("glpi session token empty: %s", payload.Message)
	}
	c.token = payload.SessionToken
	return nil
}

func (c *Client) ensureOAuthToken(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Until(c.tokenUntil) > 30*time.Second {
		return nil
	}
	if c.cfg.OAuth == nil {
		return fmt.Errorf("glpi oauth config missing")
	}
	tokenURL, err := oauthTokenURL(c.baseURL)
	if err != nil {
		return err
	}
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", c.cfg.OAuth.ClientID)
	form.Set("client_secret", c.cfg.OAuth.ClientSecret)
	form.Set("username", c.cfg.OAuth.Username)
	form.Set("password", c.cfg.OAuth.Password)
	scope := c.cfg.OAuth.Scope
	if scope == "" {
		scope = "api"
	}
	form.Set("scope", scope)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("glpi oauth token request failed: %s: %s", resp.Status, string(body))
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return err
	}
	if payload.AccessToken == "" {
		return fmt.Errorf("glpi oauth access token empty")
	}
	if !strings.EqualFold(payload.TokenType, "bearer") && payload.TokenType != "" {
		return fmt.Errorf("glpi oauth unexpected token type %q", payload.TokenType)
	}
	if payload.ExpiresIn <= 0 {
		payload.ExpiresIn = 3600
	}
	c.token = payload.AccessToken
	c.tokenUntil = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	return nil
}

func (c *Client) useOAuth() bool {
	if c.cfg.OAuth == nil {
		return false
	}
	return c.cfg.OAuth.ClientID != "" && c.cfg.OAuth.ClientSecret != "" && c.cfg.OAuth.Username != ""
}

func oauthTokenURL(base string) (string, error) {
	const marker = "/api.php"
	idx := strings.Index(base, marker)
	if idx == -1 {
		return "", fmt.Errorf("glpi oauth requires api.php endpoint, got %s", base)
	}
	return base[:idx+len(marker)] + "/token", nil
}

func sanitizeBaseURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	return strings.TrimRight(trimmed, "/")
}
