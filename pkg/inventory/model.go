package inventory

import "net/netip"

// AssetModel describes normalized device info.
type AssetModel struct {
	Identifier string
	Type       string
	Hostname   string
	IP         netip.Addr
	MAC        string
	Vendor     string
	Model      string
	OSName     string
	OSVersion  string
	Serial     string
	Attributes map[string]string
}
