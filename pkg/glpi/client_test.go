package glpi

import "testing"

func TestSanitizeBaseURL(t *testing.T) {
	cases := map[string]string{
		"":                           "",
		" https://glpi/apirest.php ": "https://glpi/apirest.php",
		"https://glpi/api.php":       "https://glpi/api.php",
		"https://glpi/api.php/v2.1/": "https://glpi/api.php/v2.1",
	}
	for raw, want := range cases {
		if got := sanitizeBaseURL(raw); got != want {
			t.Fatalf("sanitizeBaseURL(%q)=%q want %q", raw, got, want)
		}
	}
}

func TestOAuthTokenURL(t *testing.T) {
	cases := map[string]string{
		"https://glpi/api.php":      "https://glpi/api.php/token",
		"https://glpi/api.php/v2.1": "https://glpi/api.php/token",
	}
	for raw, want := range cases {
		got, err := oauthTokenURL(raw)
		if err != nil {
			t.Fatalf("oauthTokenURL(%q) unexpected error: %v", raw, err)
		}
		if got != want {
			t.Fatalf("oauthTokenURL(%q)=%q want %q", raw, got, want)
		}
	}
	if _, err := oauthTokenURL("https://glpi/apirest.php"); err == nil {
		t.Fatalf("expected error for legacy endpoint")
	}
}
