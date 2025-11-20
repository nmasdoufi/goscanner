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

	"github.com/nmasdoufi/goscanner/pkg/config"
	"github.com/nmasdoufi/goscanner/pkg/inventory"
)

// GLPIInventory represents the GLPI inventory format
type GLPIInventory struct {
	Action        string              `json:"action"`
	DeviceID      string              `json:"deviceid"`
	ItemType      string              `json:"itemtype"`
	Content       *GLPIInventoryContent `json:"content"`
}

// GLPIInventoryContent contains the actual inventory data
type GLPIInventoryContent struct {
	VersionClient    string                  `json:"versionclient"`
	Hardware         *GLPIHardware           `json:"hardware,omitempty"`
	OperatingSystem  *GLPIOperatingSystem    `json:"operatingsystem,omitempty"`
	Networks         []GLPINetwork           `json:"networks,omitempty"`
	NetworkDevice    *GLPINetworkDevice      `json:"network_device,omitempty"`
	Printers         []GLPIPrinter           `json:"printers,omitempty"`
}

// GLPIHardware represents computer hardware info
type GLPIHardware struct {
	Name         string `json:"name,omitempty"`
	UUID         string `json:"uuid,omitempty"`
	ChassisType  string `json:"chassis_type,omitempty"`
	Workgroup    string `json:"workgroup,omitempty"`
	Description  string `json:"description,omitempty"`
}

// GLPIOperatingSystem represents OS info
type GLPIOperatingSystem struct {
	FullName      string `json:"full_name,omitempty"`
	KernelVersion string `json:"kernel_version,omitempty"`
	Arch          string `json:"arch,omitempty"`
	FQDN          string `json:"fqdn,omitempty"`
}

// GLPINetwork represents network interface info
type GLPINetwork struct {
	Description string   `json:"description,omitempty"`
	IPAddress   string   `json:"ipaddress,omitempty"`
	IPAddress6  string   `json:"ipaddress6,omitempty"`
	MacAddr     string   `json:"macaddr,omitempty"`
	Status      string   `json:"status,omitempty"`
	Type        string   `json:"type,omitempty"`
	Speed       int      `json:"speed,omitempty"`
}

// GLPINetworkDevice represents network equipment
type GLPINetworkDevice struct {
	Type     string `json:"type,omitempty"`
	Model    string `json:"model,omitempty"`
	Firmware string `json:"firmware,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Serial   string `json:"serial,omitempty"`
}

// GLPIPrinter represents printer info
type GLPIPrinter struct {
	Name       string `json:"name,omitempty"`
	Driver     string `json:"driver,omitempty"`
	Port       string `json:"port,omitempty"`
	Serial     string `json:"serial,omitempty"`
	Status     string `json:"status,omitempty"`
}

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

	// Convert AssetModel to GLPI inventory format
	glpiInventory := convertToGLPIInventory(asset)

	body, err := json.Marshal(glpiInventory)
	if err != nil {
		return fmt.Errorf("marshal inventory: %w", err)
	}

	// Debug: Log the JSON being sent (only in development)
	// Uncomment to see inventory JSON:
	fmt.Printf("Sending inventory for %s:\n%s\n", asset.IP, string(body))
	// Debug: Log the JSON being sent
	fmt.Printf("\n[GLPI] Sending inventory for %s:\n%s\n\n", asset.IP, string(body))

	// Construct the inventory endpoint URL
	// Extract the base GLPI URL (before /api.php or /apirest.php)
	inventoryURL := getInventoryURL(c.baseURL)

	// Retry logic with exponential backoff
	maxRetries := 3
	var lastErr error

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 2s, 4s, 8s
			backoff := time.Duration(1<<uint(attempt)) * time.Second
			time.Sleep(backoff)
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, inventoryURL, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		// GLPI inventory endpoint may require authentication depending on configuration
		if c.useOAuth() {
			if err := c.ensureAuth(ctx); err != nil {
				lastErr = fmt.Errorf("oauth auth: %w", err)
				continue
			}
			req.Header.Set("Authorization", "Bearer "+c.token)
		} else if c.cfg.UserToken != "" {
			if err := c.ensureAuth(ctx); err != nil {
				lastErr = fmt.Errorf("legacy auth: %w", err)
				continue
			}
			req.Header.Set("Session-Token", c.token)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("http request: %w", err)
			continue
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Debug: Show successful response
			// Uncomment to see GLPI response:
			fmt.Printf("GLPI inventory accepted (status %d): %s\n", resp.StatusCode, string(bodyBytes))
			fmt.Printf("[GLPI] Inventory accepted for %s (status %d): %s\n\n", asset.IP, resp.StatusCode, string(bodyBytes))
			return nil
		}

		// Handle specific error codes
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			// Authentication failed, clear token and retry once
			c.mu.Lock()
			c.token = ""
			c.tokenUntil = time.Time{}
			c.mu.Unlock()
			if attempt == 0 {
				continue
			}
		}

		lastErr = fmt.Errorf("glpi inventory failed (status %d): %s", resp.StatusCode, string(bodyBytes))

		// Don't retry on 4xx errors (except 401/403 which we handle above)
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 401 && resp.StatusCode != 403 {
			return lastErr
		}
	}

	return fmt.Errorf("glpi inventory failed after %d attempts: %w", maxRetries+1, lastErr)
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
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", c.cfg.OAuth.ClientID)
	form.Set("client_secret", c.cfg.OAuth.ClientSecret)
	// form.Set("username", c.cfg.OAuth.Username)
	// form.Set("password", c.cfg.OAuth.Password)
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
	return c.cfg.OAuth.ClientID != "" && c.cfg.OAuth.ClientSecret != ""
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

// convertToGLPIInventory transforms AssetModel to GLPI inventory format
func convertToGLPIInventory(asset inventory.AssetModel) *GLPIInventory {
	inv := &GLPIInventory{
		Action:        "inventory",
		DeviceID:      asset.Identifier,
		Content:       &GLPIInventoryContent{
			VersionClient: "goscanner-v1.0",
		},
	}

	// Set device ID - use MAC, IP, or serial as fallback
	if inv.DeviceID == "" {
		if asset.MAC != "" {
			inv.DeviceID = asset.MAC
		} else if asset.IP.IsValid() {
			inv.DeviceID = asset.IP.String()
		} else if asset.Serial != "" {
			inv.DeviceID = asset.Serial
		} else {
			inv.DeviceID = fmt.Sprintf("goscanner-%s", asset.IP.String())
		}
	}

	// Use IP address as hostname fallback
	hostname := asset.Hostname
	if hostname == "" && asset.IP.IsValid() {
		hostname = asset.IP.String()
	}

	// Build clean description
	description := fmt.Sprintf("Discovered by goscanner - %s", asset.Vendor)

	// Map asset type to GLPI item type
	switch asset.Type {
	case "Computer", "PC":
		inv.ItemType = "Computer"
		inv.Content.Hardware = &GLPIHardware{
			Name:        hostname,
			UUID:        asset.Serial,
			Description: description,
		}
		if asset.OSName != "" {
			inv.Content.OperatingSystem = &GLPIOperatingSystem{
				FullName:      fmt.Sprintf("%s %s", asset.OSName, asset.OSVersion),
				KernelVersion: asset.OSVersion,
				FQDN:          hostname,
			}
		}
	case "NetworkEquipment", "Switch", "Router":
		inv.ItemType = "NetworkEquipment"
		inv.Content.NetworkDevice = &GLPINetworkDevice{
			Type:   asset.Type,
			Model:  asset.Model,
			MAC:    asset.MAC,
			Serial: asset.Serial,
		}
	case "Printer", "Peripheral":
		// Check if it's actually a printer or generic peripheral
		if strings.Contains(strings.ToLower(asset.Model), "printer") ||
			strings.Contains(strings.ToLower(asset.Vendor), "printer") ||
			asset.Type == "Printer" {
			inv.ItemType = "Printer"
			inv.Content.Printers = []GLPIPrinter{
				{
					Name:   hostname,
					Serial: asset.Serial,
					Status: "active",
				},
			}
		} else {
			// For other peripherals like copiers, use Computer type with description
			inv.ItemType = "Computer"
			inv.Content.Hardware = &GLPIHardware{
				Name:        hostname,
				UUID:        asset.Serial,
				Description: fmt.Sprintf("%s %s - Peripheral", asset.Vendor, asset.Model),
				ChassisType: "Peripheral",
			}
		}
	default:
		// Default to Computer for unknown types
		inv.ItemType = "Computer"
		inv.Content.Hardware = &GLPIHardware{
			Name:        hostname,
			UUID:        asset.Serial,
			Description: fmt.Sprintf("%s %s", asset.Vendor, asset.Model),
		}
	}

	// Add network information if available
	if asset.IP.IsValid() {
		network := GLPINetwork{
			Description: "Primary Network Interface",
			Status:      "up",
			Type:        "ethernet",
		}

		if asset.IP.Is4() {
			network.IPAddress = asset.IP.String()
		} else if asset.IP.Is6() {
			network.IPAddress6 = asset.IP.String()
		}

		if asset.MAC != "" {
			network.MacAddr = asset.MAC
		}

		inv.Content.Networks = []GLPINetwork{network}
	}

	return inv
}

// getInventoryURL extracts the base GLPI URL and constructs inventory endpoint
func getInventoryURL(apiBaseURL string) string {
	// Remove API paths to get base GLPI URL
	base := apiBaseURL

	// Remove /api.php/v2.x or /apirest.php paths
	if idx := strings.Index(base, "/api.php"); idx != -1 {
		base = base[:idx]
	} else if idx := strings.Index(base, "/apirest.php"); idx != -1 {
		base = base[:idx]
	}

	return base + "/front/inventory.php"
}
