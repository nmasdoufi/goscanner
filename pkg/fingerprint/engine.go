package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"time"

"github.com/x1thexxx-lgtm/goscanner/pkg/discovery"
"github.com/x1thexxx-lgtm/goscanner/pkg/inventory"
)

// Engine orchestrates host fingerprinting.
type Engine struct {
	httpClient *http.Client
}

// NewEngine creates new fingerprint engine.
func NewEngine() *Engine {
	return &Engine{httpClient: &http.Client{Timeout: 2 * time.Second}}
}

// FingerprintHost builds asset from discovery data.
func (e *Engine) FingerprintHost(ctx context.Context, host discovery.HostResult) inventory.AssetModel {
	asset := inventory.AssetModel{
		IP:   host.IP,
		Type: "Unknown",
		Attributes: map[string]string{
			"open_ports": fmt.Sprint(keys(host.OpenPorts)),
		},
	}
	if _, ok := host.OpenPorts[80]; ok {
		e.tryHTTP(ctx, &asset, host.IP.String(), false)
	}
	if _, ok := host.OpenPorts[443]; ok {
		e.tryHTTP(ctx, &asset, host.IP.String(), true)
	}
	if asset.Type == "Unknown" {
		asset.Type = "Computer"
	}
	return inventory.NormalizeAsset(asset)
}

func (e *Engine) tryHTTP(ctx context.Context, asset *inventory.AssetModel, ip string, tls bool) {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s://%s", scheme, ip), nil)
	if err != nil {
		return
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if asset.Hostname == "" {
		asset.Hostname = resp.Header.Get("Server")
	}
	asset.Attributes[fmt.Sprintf("http_%s_status", scheme)] = fmt.Sprintf("%d", resp.StatusCode)
	if asset.Vendor == "" {
		asset.Vendor = resp.Header.Get("Server")
	}
	asset.Type = "Peripheral"
}

func keys(m map[int]time.Duration) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
