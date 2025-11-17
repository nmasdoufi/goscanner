package config

import (
	"path/filepath"
	"testing"
)

func TestLoadSampleConfig(t *testing.T) {
	path := filepath.Join("..", "..", "goscanner.example.yaml")
	if _, err := Load(path); err != nil {
		t.Fatalf("failed to load sample config: %v", err)
	}
}
