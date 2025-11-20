package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/nmasdoufi/goscanner/pkg/discovery"
	"github.com/nmasdoufi/goscanner/pkg/inventory"
)

// Engine orchestrates host fingerprinting.
type Engine struct {
	httpClient     *http.Client
	snmpCommunity  string
	enableSNMP     bool
	verbose        bool // Enable verbose logging
}

// EngineOption configures the fingerprint engine
type EngineOption func(*Engine)

// WithSNMP enables SNMP fingerprinting with the given community string
func WithSNMP(community string) EngineOption {
	return func(e *Engine) {
		e.snmpCommunity = community
		e.enableSNMP = true
	}
}

// NewEngine creates new fingerprint engine.
func NewEngine(opts ...EngineOption) *Engine {
	// Create HTTP client that accepts self-signed certificates
	// This is necessary for fingerprinting devices like printers, routers, etc.
	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	e := &Engine{
		httpClient:    httpClient,
		snmpCommunity: "public",
		enableSNMP:    true, // Enable by default
		verbose:       true, // Enable verbose logging to show SNMP activity
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Common SNMP OIDs for device identification
const (
	oidSysDescr     = ".1.3.6.1.2.1.1.1.0"   // System description
	oidSysObjectID  = ".1.3.6.1.2.1.1.2.0"   // System Object ID
	oidSysName      = ".1.3.6.1.2.1.1.5.0"   // System name
	oidSysContact   = ".1.3.6.1.2.1.1.4.0"   // System contact
	oidSysLocation  = ".1.3.6.1.2.1.1.6.0"   // System location
	oidHrDeviceDescr = ".1.3.6.1.2.1.25.3.2.1.3.1" // Device description
)

// FingerprintHost builds asset from discovery data.
func (e *Engine) FingerprintHost(ctx context.Context, host discovery.HostResult) inventory.AssetModel {
	asset := inventory.AssetModel{
		IP:   host.IP,
		MAC:  host.MAC,
		Type: "Unknown",
		Attributes: map[string]string{
			"open_ports": fmt.Sprint(keys(host.OpenPorts)),
		},
	}

	if e.verbose {
		fmt.Printf("\n[FINGERPRINT] Starting fingerprint for %s with ports: %v\n", host.IP, keys(host.OpenPorts))
	}

	// Try SNMP first for the most accurate device identification
	if e.enableSNMP {
		if _, ok := host.OpenPorts[161]; ok {
			e.trySNMP(ctx, &asset, host.IP.String())
		} else if e.verbose {
			fmt.Printf("[FINGERPRINT] Port 161 (SNMP) not open, skipping SNMP query\n")
		}
	}

	// Try HTTP/HTTPS fingerprinting
	if _, ok := host.OpenPorts[80]; ok {
		e.tryHTTP(ctx, &asset, host.IP.String(), false)
	}
	if _, ok := host.OpenPorts[443]; ok {
		e.tryHTTP(ctx, &asset, host.IP.String(), true)
	}

	// Enhanced device type classification based on open ports
	if asset.Type == "Unknown" {
		if e.verbose {
			fmt.Printf("[FINGERPRINT] Using port-based classification\n")
		}
		asset.Type = e.classifyByPorts(host.OpenPorts)
		if e.verbose {
			fmt.Printf("[FINGERPRINT] Port-based classification result: %s\n", asset.Type)
		}
	}

	if e.verbose {
		fmt.Printf("[FINGERPRINT] Final classification: Type=%s, Vendor=%s, Model=%s\n\n", asset.Type, asset.Vendor, asset.Model)
	}

	return inventory.NormalizeAsset(asset)
}

func (e *Engine) tryHTTP(ctx context.Context, asset *inventory.AssetModel, ip string, tls bool) {
	scheme := "http"
	if tls {
		scheme = "https"
	}

	if e.verbose {
		fmt.Printf("[HTTP] Attempting %s request to %s://%s\n", strings.ToUpper(scheme), scheme, ip)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("%s://%s", scheme, ip), nil)
	if err != nil {
		if e.verbose {
			fmt.Printf("[HTTP] Failed to create request: %v\n", err)
		}
		return
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		if e.verbose {
			fmt.Printf("[HTTP] Request failed: %v\n", err)
		}
		return
	}
	defer resp.Body.Close()

	if e.verbose {
		fmt.Printf("[HTTP] Response status: %d\n", resp.StatusCode)
	}

	// Extract server header for vendor/model information
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		if e.verbose {
			fmt.Printf("[HTTP] Server header: %s\n", serverHeader)
		}

		// Extract vendor from server header (e.g., "Apache/2.4.59" -> vendor info)
		if asset.Vendor == "" {
			vendor := extractVendorFromHTTP(serverHeader)
			if vendor != "" {
				asset.Vendor = vendor
				if e.verbose {
					fmt.Printf("[HTTP] Extracted vendor: %s\n", vendor)
				}
			}
		}

		// Store full server header in attributes for reference
		asset.Attributes["http_server"] = serverHeader

		// Extract model information from server header
		if asset.Model == "" {
			model := extractModelFromHTTP(serverHeader)
			if model != "" {
				asset.Model = model
				if e.verbose {
					fmt.Printf("[HTTP] Extracted model: %s\n", model)
				}
			}
		}
	}

	asset.Attributes[fmt.Sprintf("http_%s_status", scheme)] = fmt.Sprintf("%d", resp.StatusCode)

	// Only change type to Peripheral if we got a successful response
	// This indicates a web-enabled device (printer, copier, etc.)
	if resp.StatusCode >= 200 && resp.StatusCode < 400 {
		if e.verbose {
			fmt.Printf("[HTTP] Web interface detected, likely a Peripheral device\n")
		}
		asset.Type = "Peripheral"
	}
}

func keys(m map[int]time.Duration) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// trySNMP performs SNMP queries to identify the device
func (e *Engine) trySNMP(ctx context.Context, asset *inventory.AssetModel, ip string) {
	if e.verbose {
		fmt.Printf("[SNMP] Attempting SNMP query to %s (community: %s)\n", ip, e.snmpCommunity)
	}

	snmp := &gosnmp.GoSNMP{
		Target:    ip,
		Port:      161,
		Community: e.snmpCommunity,
		Version:   gosnmp.Version2c,
		Timeout:   time.Second * 2,
		Retries:   1,
	}

	err := snmp.Connect()
	if err != nil {
		if e.verbose {
			fmt.Printf("[SNMP] Connection failed to %s: %v\n", ip, err)
		}
		return
	}
	defer snmp.Conn.Close()

	// Query system description
	oids := []string{oidSysDescr, oidSysName, oidSysObjectID}
	result, err := snmp.Get(oids)
	if err != nil {
		if e.verbose {
			fmt.Printf("[SNMP] Query failed for %s: %v\n", ip, err)
		}
		return
	}

	if e.verbose {
		fmt.Printf("[SNMP] Successfully queried %s\n", ip)
	}

	for _, variable := range result.Variables {
		switch variable.Name {
		case oidSysDescr:
			if desc, ok := variable.Value.([]byte); ok {
				sysDescr := string(desc)
				asset.Attributes["snmp_sysdescr"] = sysDescr

				if e.verbose {
					fmt.Printf("[SNMP]   sysDescr: %s\n", sysDescr)
				}

				// Parse device type from system description
				sysDescrLower := strings.ToLower(sysDescr)

				// Detect copiers/printers
				if strings.Contains(sysDescrLower, "copier") ||
					strings.Contains(sysDescrLower, "multifunction") ||
					strings.Contains(sysDescrLower, "mfp") {
					asset.Type = "Peripheral"
					asset.Model = extractModel(sysDescr)
				} else if strings.Contains(sysDescrLower, "printer") {
					asset.Type = "Printer"
					asset.Model = extractModel(sysDescr)
				} else if strings.Contains(sysDescrLower, "switch") {
					asset.Type = "NetworkEquipment"
					asset.Model = extractModel(sysDescr)
				} else if strings.Contains(sysDescrLower, "router") {
					asset.Type = "Router"
					asset.Model = extractModel(sysDescr)
				} else if strings.Contains(sysDescrLower, "windows") ||
					strings.Contains(sysDescrLower, "linux") ||
					strings.Contains(sysDescrLower, "hardware:") {
					asset.Type = "Computer"
					// Extract OS info
					if strings.Contains(sysDescrLower, "windows") {
						asset.OSName = "Windows"
					} else if strings.Contains(sysDescrLower, "linux") {
						asset.OSName = "Linux"
					}
				}

				// Extract vendor information
				vendor := extractVendor(sysDescr)
				if vendor != "" {
					asset.Vendor = vendor
					if e.verbose {
						fmt.Printf("[SNMP]   Detected vendor: %s\n", vendor)
					}
				}
			}

		case oidSysName:
			if name, ok := variable.Value.([]byte); ok {
				hostname := string(name)
				if asset.Hostname == "" {
					asset.Hostname = hostname
				}
				asset.Attributes["snmp_sysname"] = hostname
				if e.verbose {
					fmt.Printf("[SNMP]   sysName: %s\n", hostname)
				}
			}

		case oidSysObjectID:
			if oid, ok := variable.Value.(string); ok {
				asset.Attributes["snmp_sysobjectid"] = oid
				// Use OID to identify vendor
				if vendor := getVendorFromOID(oid); vendor != "" && asset.Vendor == "" {
					asset.Vendor = vendor
				}
			}
		}
	}
}

// classifyByPorts determines device type based on open ports
func (e *Engine) classifyByPorts(openPorts map[int]time.Duration) string {
	if e.verbose {
		fmt.Printf("[PORT-CLASSIFY] Analyzing ports: %v\n", keys(openPorts))
	}

	// Check for common printer ports
	if hasPort(openPorts, 9100) || hasPort(openPorts, 515) {
		if e.verbose {
			fmt.Printf("[PORT-CLASSIFY] Found printer ports (9100 or 515) → Printer\n")
		}
		return "Printer"
	}

	// Check for typical network equipment ports
	if hasPort(openPorts, 22) && hasPort(openPorts, 161) && !hasPort(openPorts, 135) {
		if e.verbose {
			fmt.Printf("[PORT-CLASSIFY] Found SSH+SNMP without Windows ports → NetworkEquipment\n")
		}
		return "NetworkEquipment"
	}

	// Check for Windows computer
	if hasPort(openPorts, 135) || hasPort(openPorts, 139) || hasPort(openPorts, 445) {
		if e.verbose {
			fmt.Printf("[PORT-CLASSIFY] Found Windows SMB/RPC ports (135/139/445) → Computer\n")
		}
		return "Computer"
	}

	// Check for Unix/Linux computer
	if hasPort(openPorts, 22) && (hasPort(openPorts, 80) || hasPort(openPorts, 443)) {
		if e.verbose {
			fmt.Printf("[PORT-CLASSIFY] Found SSH+HTTP/HTTPS → Computer (Linux)\n")
		}
		return "Computer"
	}

	// Default to Computer for anything with RDP or SSH
	if hasPort(openPorts, 3389) || hasPort(openPorts, 22) {
		if e.verbose {
			fmt.Printf("[PORT-CLASSIFY] Found RDP or SSH → Computer\n")
		}
		return "Computer"
	}

	if e.verbose {
		fmt.Printf("[PORT-CLASSIFY] No specific pattern matched → Computer (default)\n")
	}
	return "Computer"
}

// extractModel attempts to extract model information from system description
func extractModel(sysDescr string) string {
	// Common patterns for model extraction
	patterns := []string{
		"Model:",
		"model:",
		"TYPE:",
	}

	for _, pattern := range patterns {
		if idx := strings.Index(sysDescr, pattern); idx != -1 {
			modelStart := idx + len(pattern)
			modelEnd := strings.IndexAny(sysDescr[modelStart:], ",;\n")
			if modelEnd != -1 {
				return strings.TrimSpace(sysDescr[modelStart : modelStart+modelEnd])
			}
			return strings.TrimSpace(sysDescr[modelStart:])
		}
	}

	// Try to extract model by looking for common patterns
	words := strings.Fields(sysDescr)
	if len(words) >= 2 {
		// Return the first few words as potential model
		return strings.Join(words[0:min(3, len(words))], " ")
	}

	return ""
}

// extractVendor attempts to identify vendor from system description
func extractVendor(sysDescr string) string {
	sysDescrLower := strings.ToLower(sysDescr)

	vendors := map[string]string{
		"cisco":    "Cisco",
		"hp":       "HP",
		"dell":     "Dell",
		"lenovo":   "Lenovo",
		"xerox":    "Xerox",
		"canon":    "Canon",
		"ricoh":    "Ricoh",
		"epson":    "Epson",
		"brother":  "Brother",
		"kyocera":  "Kyocera",
		"sharp":    "Sharp",
		"konica":   "Konica Minolta",
		"microsoft": "Microsoft",
		"vmware":   "VMware",
	}

	for key, vendor := range vendors {
		if strings.Contains(sysDescrLower, key) {
			return vendor
		}
	}

	return ""
}

// extractVendorFromHTTP extracts vendor information from HTTP Server header
func extractVendorFromHTTP(serverHeader string) string {
	serverLower := strings.ToLower(serverHeader)

	// Common web server vendors
	httpVendors := map[string]string{
		"apache":      "Apache",
		"nginx":       "Nginx",
		"microsoft":   "Microsoft",
		"iis":         "Microsoft IIS",
		"lighttpd":    "Lighttpd",
		"tomcat":      "Apache Tomcat",
		"jetty":       "Eclipse Jetty",
		"weblogic":    "Oracle WebLogic",
		"websphere":   "IBM WebSphere",
		"canon":       "Canon",
		"xerox":       "Xerox",
		"ricoh":       "Ricoh",
		"hp":          "HP",
		"dell":        "Dell",
		"cisco":       "Cisco",
		"brother":     "Brother",
		"epson":       "Epson",
		"kyocera":     "Kyocera",
		"sharp":       "Sharp",
		"konica":      "Konica Minolta",
	}

	for key, vendor := range httpVendors {
		if strings.Contains(serverLower, key) {
			return vendor
		}
	}

	// If no specific vendor found, try to extract the first word
	parts := strings.Fields(serverHeader)
	if len(parts) > 0 {
		// Remove version numbers and special chars
		vendorPart := strings.Split(parts[0], "/")[0]
		if vendorPart != "" && len(vendorPart) > 2 {
			return vendorPart
		}
	}

	return ""
}

// extractModelFromHTTP extracts model/version from HTTP Server header
func extractModelFromHTTP(serverHeader string) string {
	// Try to extract version info (e.g., "Apache/2.4.59" -> "2.4.59")
	if strings.Contains(serverHeader, "/") {
		parts := strings.Split(serverHeader, "/")
		if len(parts) >= 2 {
			// Return the full server string as model
			return serverHeader
		}
	}

	// For web-enabled devices, the server header might be the model
	// (e.g., printer models often return custom server strings)
	return serverHeader
}

// getVendorFromOID extracts vendor from enterprise OID
func getVendorFromOID(oid string) string {
	// Enterprise OIDs follow pattern .1.3.6.1.4.1.<enterprise-number>
	enterpriseOIDs := map[string]string{
		".1.3.6.1.4.1.9":     "Cisco",
		".1.3.6.1.4.1.11":    "HP",
		".1.3.6.1.4.1.674":   "Dell",
		".1.3.6.1.4.1.2699":  "Xerox",
		".1.3.6.1.4.1.1602":  "Canon",
		".1.3.6.1.4.1.367":   "Ricoh",
		".1.3.6.1.4.1.1248":  "Epson",
		".1.3.6.1.4.1.2435":  "Brother",
		".1.3.6.1.4.1.1347":  "Kyocera",
	}

	for prefix, vendor := range enterpriseOIDs {
		if strings.HasPrefix(oid, prefix) {
			return vendor
		}
	}

	return ""
}

// hasPort checks if a port exists in the open ports map
func hasPort(ports map[int]time.Duration, port int) bool {
	_, exists := ports[port]
	return exists
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
