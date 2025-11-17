package inventory

import "strings"

// NormalizeAsset applies vendor/model canonicalization.
func NormalizeAsset(a AssetModel) AssetModel {
	if a.Attributes == nil {
		a.Attributes = map[string]string{}
	}
	a.Vendor = strings.TrimSpace(strings.Title(strings.ToLower(a.Vendor)))
	a.Model = strings.TrimSpace(a.Model)
	a.Hostname = strings.ToLower(strings.TrimSpace(a.Hostname))
	if a.Type == "" {
		a.Type = classify(a)
	}
	return a
}

func classify(a AssetModel) string {
	if strings.Contains(a.Model, "switch") || strings.Contains(strings.ToLower(a.Attributes["category"]), "network") {
		return "NetworkEquipment"
	}
	if strings.Contains(a.Model, "printer") {
		return "Printer"
	}
	return "Computer"
}
