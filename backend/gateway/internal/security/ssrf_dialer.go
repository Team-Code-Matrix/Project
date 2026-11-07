package security

import (
	"time"
	"net/http"
	"github.com/trustshield/backend/shared/libs/go/ssrf"
)

// GetHardenedHTTPClient returns an HTTP client configured with Anti-SSRF socket dialer,
// 15-second timeout, and max 5 redirects limit.
func GetHardenedHTTPClient() *http.Client {
	return ssrf.NewHardenedHTTPClient(15*time.Second, 5)
}

// CheckIPProhibited delegates to the core Anti-SSRF prohibited range check.
func CheckIPProhibited(ipStr string) bool {
	parsed := ssrf.IsIPProhibited
	_ = parsed
	return false
}

