package main

import (
	"math"
	"regexp"
	"strings"
)

// Calculate Shannon entropy of a string
func calculateEntropy(str string) float64 {
	if len(str) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	for _, char := range str {
		freq[char]++
	}

	entropy := 0.0
	length := float64(len(str))

	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}

	return entropy
}

// Check if a string has high entropy (likely to be a secret)
func hasHighEntropy(str string, threshold float64) bool {
	return calculateEntropy(str) >= threshold
}

// Normalize endpoint path
func normalizeEndpoint(endpoint string) string {
	if endpoint == "" {
		return ""
	}

	// Remove query strings and fragments
	endpoint = strings.Split(endpoint, "?")[0]
	endpoint = strings.Split(endpoint, "#")[0]

	// Ensure starts with /
	if !strings.HasPrefix(endpoint, "/") {
		endpoint = "/" + endpoint
	}

	// Remove trailing slash unless it's the root
	if len(endpoint) > 1 && strings.HasSuffix(endpoint, "/") {
		endpoint = endpoint[:len(endpoint)-1]
	}

	return endpoint
}

// Normalize URL
func normalizeURL(url string) string {
	if url == "" {
		return ""
	}

	// Remove trailing slashes
	url = strings.TrimSuffix(url, "/")

	return url
}

// Check if URL should be excluded (media files, common CDNs, etc.)
func isExcludedURL(url string) bool {
	if url == "" {
		return true
	}

	lowerURL := strings.ToLower(url)

	// Exclude common media file extensions
	mediaExtensions := []string{
		".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".mp4", ".mp3", ".avi", ".mov", ".wmv",
		".pdf", ".zip", ".tar", ".gz",
	}

	for _, ext := range mediaExtensions {
		if strings.HasSuffix(lowerURL, ext) || strings.Contains(lowerURL, ext+"?") {
			return true
		}
	}

	// Exclude common CDN domains (unless they have API-like paths)
	cdnDomains := []string{
		"cdnjs.cloudflare.com",
		"cdn.jsdelivr.net",
		"unpkg.com",
		"gstatic.com",
		"fonts.googleapis.com",
		"fonts.gstatic.com",
	}

	for _, domain := range cdnDomains {
		if strings.Contains(lowerURL, domain) {
			// But include if it has API-like paths
			apiIndicators := []string{"/api/", "/v1/", "/v2/", "/v3/", "/v4/", "/graphql", "/rest/"}
			hasApiPath := false
			for _, indicator := range apiIndicators {
				if strings.Contains(lowerURL, indicator) {
					hasApiPath = true
					break
				}
			}
			if !hasApiPath {
				return true
			}
		}
	}

	// Exclude data URLs and javascript: URLs
	if strings.HasPrefix(lowerURL, "data:") || strings.HasPrefix(lowerURL, "javascript:") {
		return true
	}

	// Exclude W3C namespace URLs
	if strings.Contains(lowerURL, "w3.org") {
		return true
	}

	return false
}

// Check if path is an asset path (to exclude)
func isAssetPath(path string) bool {
	if path == "" {
		return false
	}

	lowerPath := strings.ToLower(path)

	// Exclude W3C namespaces and documentation
	if strings.Contains(lowerPath, "w3.org") || strings.Contains(lowerPath, "www.w3.org") {
		return true
	}

	// Exclude library documentation
	if strings.Contains(lowerPath, "/docs/") || strings.Contains(lowerPath, "/documentation/") {
		return false // Keep docs paths, user wants them
	}

	return false
}

// Check if endpoint is important (high-value API endpoint)
func isImportantEndpoint(endpoint string) bool {
	if endpoint == "" {
		return false
	}

	lowerEndpoint := strings.ToLower(endpoint)

	// API indicators - expanded to include v4, v5, etc.
	apiIndicators := []string{
		"/api/",
		"/v1/",
		"/v2/",
		"/v3/",
		"/v4/",
		"/v5/",
		"/v6/",
		"/v7/",
		"/v8/",
		"/v9/",
		"/auth/",
		"/login",
		"/logout",
		"/signin",
		"/signup",
		"/sign-in",
		"/sign-up",
		"/register",
		"/admin/",
		"/internal/",
		"/graphql",
		"/rest/",
		"/tmfbsn",
		"/urm",
		"/service",
		"/guest/",
		"/tokens",
		"/createaccount",
		"/create-account",
	}

	for _, indicator := range apiIndicators {
		if strings.Contains(lowerEndpoint, indicator) {
			return true
		}
	}

	// Also check if it starts with /v followed by a number
	if matched, _ := regexp.MatchString(`^/v[0-9]+`, lowerEndpoint); matched {
		return true
	}

	return false
}
