package inventory

import (
	"strings"
	"unicode"
)

// NormalizeAsset applies vendor/model canonicalization.
func NormalizeAsset(a AssetModel) AssetModel {
	if a.Attributes == nil {
		a.Attributes = map[string]string{}
	}
	a.Vendor = strings.TrimSpace(toTitle(a.Vendor))
	a.Model = strings.TrimSpace(a.Model)
	a.Hostname = strings.ToLower(strings.TrimSpace(a.Hostname))
	if a.Type == "" {
		a.Type = classify(a)
	}
	return a
}

// toTitle converts a string to title case (replacement for deprecated strings.Title)
func toTitle(s string) string {
	if s == "" {
		return s
	}
	// Convert to lowercase first
	s = strings.ToLower(s)

	// Capitalize first letter after spaces or at the beginning
	var result strings.Builder
	capitalizeNext := true

	for _, r := range s {
		if unicode.IsSpace(r) || r == '-' || r == '_' {
			result.WriteRune(r)
			capitalizeNext = true
		} else if capitalizeNext {
			result.WriteRune(unicode.ToUpper(r))
			capitalizeNext = false
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
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
