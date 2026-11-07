package security

import (
	"fmt"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// Tracking parameter prefixes and keys to strip during canonicalization
var trackingQueryParams = map[string]bool{
	"utm_source":   true,
	"utm_medium":   true,
	"utm_campaign": true,
	"utm_term":     true,
	"utm_content":  true,
	"fbclid":       true,
	"gclid":        true,
	"mc_eid":       true,
	"_ga":          true,
	"msclkid":      true,
	"dclid":        true,
	"ref":          true,
}

// CanonicalizedURL holds normalized components and security flags
type CanonicalizedURL struct {
	OriginalURL     string
	NormalizedURL   string
	Hostname        string
	UnicodeHostname string
	Protocol        string
	Path            string
	DefangedURL     string
	IsPunycode      bool
	IsMixedScript   bool
}

// CanonicalizeURL normalizes raw input URLs, strips telemetry tracking params,
// converts Punycode to Unicode for homograph inspection, and produces defanged output.
func CanonicalizeURL(rawInput string) (*CanonicalizedURL, error) {
	trimmed := strings.TrimSpace(rawInput)
	if trimmed == "" {
		return nil, fmt.Errorf("empty URL provided")
	}

	// 1. Ensure explicit protocol prefix
	var protocol string
	var toParse string
	if strings.HasPrefix(strings.ToLower(trimmed), "http://") {
		protocol = "http"
		toParse = trimmed
	} else if strings.HasPrefix(strings.ToLower(trimmed), "https://") {
		protocol = "https"
		toParse = trimmed
	} else {
		protocol = "https"
		toParse = "https://" + trimmed
	}

	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, fmt.Errorf("invalid URL syntax: %w", err)
	}

	rawHost := parsed.Hostname()
	if rawHost == "" {
		return nil, fmt.Errorf("URL missing valid hostname")
	}

	rawHost = strings.ToLower(rawHost)
	port := parsed.Port()

	// 2. Punycode & IDN Inspection
	isPunycode := strings.Contains(rawHost, "xn--")
	unicodeHost, err := idna.ToUnicode(rawHost)
	if err != nil {
		unicodeHost = rawHost
	}

	// Simple heuristic for mixed script homographs
	isMixedScript := isPunycode || containsMixedScripts(unicodeHost)

	// 3. Strip Tracking Query Parameters
	query := parsed.Query()
	for param := range query {
		lowerParam := strings.ToLower(param)
		if trackingQueryParams[lowerParam] || strings.HasPrefix(lowerParam, "utm_") {
			query.Del(param)
		}
	}

	// Reassemble clean query
	cleanQuery := query.Encode()

	// 4. Normalize Path (strip redundant slashes)
	cleanPath := parsed.Path
	if cleanPath == "" {
		cleanPath = "/"
	} else if cleanPath != "/" && strings.HasSuffix(cleanPath, "/") {
		cleanPath = strings.TrimSuffix(cleanPath, "/")
	}

	// Reconstruct Normalized URL
	var hostWithPort string
	if port != "" {
		hostWithPort = fmt.Sprintf("%s:%s", rawHost, port)
	} else {
		hostWithPort = rawHost
	}

	normalized := fmt.Sprintf("%s://%s%s", protocol, hostWithPort, cleanPath)
	if cleanQuery != "" {
		normalized += "?" + cleanQuery
	}

	// 5. Generate Defanged Output (e.g. hxxps://domain[.]com/path)
	defanged := DefangURL(normalized)

	return &CanonicalizedURL{
		OriginalURL:     trimmed,
		NormalizedURL:   normalized,
		Hostname:        rawHost,
		UnicodeHostname: unicodeHost,
		Protocol:        protocol,
		Path:            cleanPath,
		DefangedURL:     defanged,
		IsPunycode:      isPunycode,
		IsMixedScript:   isMixedScript,
	}, nil
}

// DefangURL converts active URL strings into safe, non-clickable indicators
// e.g. https://bad.example.com/login -> hxxps://bad.example[.]com/login
func DefangURL(rawURL string) string {
	res := rawURL
	if strings.HasPrefix(res, "https://") {
		res = "hxxps://" + res[8:]
	} else if strings.HasPrefix(res, "http://") {
		res = "hxxp://" + res[7:]
	}

	// Defang domain dots (only in host segment)
	parts := strings.SplitN(res, "/", 4)
	if len(parts) >= 3 {
		hostPart := parts[2]
		// Replace last dot in host to prevent auto-linking
		lastDot := strings.LastIndex(hostPart, ".")
		if lastDot != -1 {
			defangedHost := hostPart[:lastDot] + "[.]" + hostPart[lastDot+1:]
			parts[2] = defangedHost
			res = strings.Join(parts, "/")
		}
	}
	return res
}

func containsMixedScripts(host string) bool {
	// Checks for non-ASCII characters that mimic Latin letters (Cyrillic, Greek homoglyphs)
	hasLatin := false
	hasNonLatin := false
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' {
			hasLatin = true
		} else if r > 127 {
			hasNonNonLatin := true
			if hasNonNonLatin {
				hasNonLatin = true
			}
		}
	}
	return hasLatin && hasNonLatin
}

