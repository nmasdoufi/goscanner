package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config represents scanner configuration file.
type Config struct {
	Sites       []Site             `json:"sites"`
	Credentials []Credential       `json:"credentials"`
	Profiles    map[string]Profile `json:"profiles"`
	Scheduler   SchedulerConfig    `json:"scheduler"`
	GLPI        GLPIConfig         `json:"glpi"`
	Logging     LoggingConfig      `json:"logging"`
}

// Site describes a scanning location.
type Site struct {
	Name      string      `json:"name"`
	Ranges    []ScanRange `json:"ranges"`
	Blacklist []string    `json:"blacklist"`
}

// ScanRange defines the CIDR and profile to use.
type ScanRange struct {
	CIDR        string `json:"cidr"`
	ProfileName string `json:"profile"`
	Frequency   string `json:"frequency"`
}

// Profile defines discovery behavior.
type Profile struct {
	Description string   `json:"description"`
	Ports       []int    `json:"ports"`
	Protocols   []string `json:"protocols"`
	MaxWorkers  int      `json:"max_workers"`
	TimeoutMS   int      `json:"timeout_ms"`
}

// Credential stores auth info for different modules.
type Credential struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Community string `json:"community"`
}

// SchedulerConfig configures the background scheduler.
type SchedulerConfig struct {
	Enabled bool   `json:"enabled"`
	Tick    string `json:"tick"`
}

// GLPIConfig stores API information.
type GLPIConfig struct {
	BaseURL   string           `json:"base_url"`
	AppToken  string           `json:"app_token"`
	UserToken string           `json:"user_token"`
	Mode      string           `json:"mode"`
	OAuth     *GLPIOAuthConfig `json:"oauth"`
}

// GLPIOAuthConfig stores OAuth2 credentials for the high-level API.
type GLPIOAuthConfig struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Scope        string `json:"scope"`
}

// LoggingConfig controls log output.
type LoggingConfig struct {
	Level  string `json:"level"`
	Path   string `json:"path"`
	Format string `json:"format"`
}

// Load reads YAML/JSON configuration.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	cfg := &Config{}
	if err := json.Unmarshal(data, cfg); err == nil {
		return cfg, nil
	}
	converted, err := yamlToJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := json.Unmarshal(converted, cfg); err != nil {
		return nil, fmt.Errorf("parse config json: %w", err)
	}
	return cfg, nil
}
