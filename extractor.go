package main

import (
	"regexp"
	"strings"
)

type Results struct {
	Secrets             []Secret
	Endpoints           []string
	ImportantEndpoints  []string
	URLs                []string
}

type Secret struct {
	Type     string
	File     string
	Value    string
	Severity string
}

type Extractor struct {
	patterns *Patterns
}

func NewExtractor() *Extractor {
	return &Extractor{
		patterns: NewPatterns(),
	}
}

func (e *Extractor) ExtractAll(content, fileName string) *Results {
	return &Results{
		Secrets:            e.extractSecrets(content, fileName),
		Endpoints:          e.extractEndpoints(content),
		ImportantEndpoints: e.extractImportantEndpoints(content),
		URLs:               e.extractURLs(content),
	}
}

func (e *Extractor) extractSecrets(content, fileName string) []Secret {
	var secrets []Secret

	// AWS Access Key ID
	awsKeyIDPattern := regexp.MustCompile(`(?i)(?:aws[_-]?access[_-]?key[_-]?id|access[_-]?key[_-]?id|aws[_-]?key[_-]?id)\s*[:=]\s*['"](AKIA[0-9A-Z]{16})['"]`)
	matches := awsKeyIDPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			secrets = append(secrets, Secret{
				Type:     "AWS_ACCESS_KEY_ID",
				File:     fileName,
				Value:    match[1],
				Severity: "HIGH",
			})
		}
	}

	// AWS Secret Access Key
	awsSecretPattern := regexp.MustCompile(`(?i)(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9/+=]{40})['"]`)
	matches = awsSecretPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			secrets = append(secrets, Secret{
				Type:     "AWS_SECRET_ACCESS_KEY",
				File:     fileName,
				Value:    match[1],
				Severity: "HIGH",
			})
		}
	}

	// JWT tokens
	jwtPattern := regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	jwtMatches := jwtPattern.FindAllString(content, -1)
	for _, match := range jwtMatches {
		secrets = append(secrets, Secret{
			Type:     "JWT",
			File:     fileName,
			Value:    match,
			Severity: "MEDIUM",
		})
	}

	// OAuth Client ID
	clientIDPattern := regexp.MustCompile(`(?i)(?:client[_-]?id|oauth[_-]?client[_-]?id)\s*[:=]\s*['"]([A-Za-z0-9_-]{20,})['"]`)
	matches = clientIDPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && hasHighEntropy(match[1], 3.5) {
			secrets = append(secrets, Secret{
				Type:     "CLIENT_ID",
				File:     fileName,
				Value:    match[1],
				Severity: "MEDIUM",
			})
		}
	}

	// OAuth Client Secret
	clientSecretPattern := regexp.MustCompile(`(?i)(?:client[_-]?secret|oauth[_-]?client[_-]?secret)\s*[:=]\s*['"]([A-Za-z0-9/+=_-]{20,})['"]`)
	matches = clientSecretPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && hasHighEntropy(match[1], 4.0) {
			secrets = append(secrets, Secret{
				Type:     "CLIENT_SECRET",
				File:     fileName,
				Value:    match[1],
				Severity: "HIGH",
			})
		}
	}

	// Bearer tokens
	bearerPattern := regexp.MustCompile(`(?i)(?:bearer|token|api[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9/+=_-]{32,})['"]`)
	matches = bearerPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && hasHighEntropy(match[1], 4.5) {
			secrets = append(secrets, Secret{
				Type:     "BEARER_TOKEN",
				File:     fileName,
				Value:    match[1],
				Severity: "HIGH",
			})
		}
	}

	// Firebase API keys
	firebasePattern := regexp.MustCompile(`(?i)(?:firebase[_-]?api[_-]?key|firebase[_-]?key)\s*[:=]\s*['"](AIza[0-9A-Za-z_-]{35})['"]`)
	matches = firebasePattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			secrets = append(secrets, Secret{
				Type:     "FIREBASE_API_KEY",
				File:     fileName,
				Value:    match[1],
				Severity: "MEDIUM",
			})
		}
	}

	// Stripe keys
	stripePattern := regexp.MustCompile(`(?i)(?:stripe[_-]?(?:secret|private)[_-]?key|stripe[_-]?api[_-]?key)\s*[:=]\s*['"](sk_(live|test)_[0-9A-Za-z]{24,})['"]`)
	matches = stripePattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			secrets = append(secrets, Secret{
				Type:     "STRIPE_SECRET_KEY",
				File:     fileName,
				Value:    match[1],
				Severity: "HIGH",
			})
		}
	}

	// Generic API keys (high entropy)
	apiKeyPattern := regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['"]([A-Za-z0-9/+=_-]{32,})['"]`)
	matches = apiKeyPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && hasHighEntropy(match[1], 4.5) {
			// Exclude common false positives
			if !strings.Contains(match[1], "example") && !strings.Contains(match[1], "test") {
				secrets = append(secrets, Secret{
					Type:     "API_KEY",
					File:     fileName,
					Value:    match[1],
					Severity: "MEDIUM",
				})
			}
		}
	}

	// Hardcoded passwords (auth-related variables only)
	// More strict pattern to avoid false positives with code
	passwordPattern := regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]{8,})['"]`)
	matches = passwordPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 && hasHighEntropy(match[1], 3.0) {
			value := match[1]
			lowerValue := strings.ToLower(value)
			
			// Exclude common false positives
			excludePatterns := []string{
				"example",
				"test",
				"password",
				"void",
				"undefined",
				"null",
				"function",
				"return",
				"if",
				"else",
				"throw",
				"b.hex",
				"b.utf8",
				"b.rstr",
				"b.b64",
				"b.b64u",
			}
			
			isFalsePositive := false
			for _, pattern := range excludePatterns {
				if strings.Contains(lowerValue, pattern) {
					isFalsePositive = true
					break
				}
			}
			
			// Also exclude if it looks like code (contains operators, brackets, etc.)
			if strings.Contains(value, "!=") || strings.Contains(value, "===") || 
			   strings.Contains(value, "!===") || strings.Contains(value, "&&") ||
			   strings.Contains(value, "||") || strings.Contains(value, "(") ||
			   strings.Contains(value, ")") || strings.Contains(value, "{") ||
			   strings.Contains(value, "}") || strings.Contains(value, ".") {
				isFalsePositive = true
			}
			
			if !isFalsePositive {
				secrets = append(secrets, Secret{
					Type:     "PASSWORD",
					File:     fileName,
					Value:    value,
					Severity: "HIGH",
				})
			}
		}
	}

	return deduplicateSecrets(secrets)
}

func (e *Extractor) extractEndpoints(content string) []string {
	var endpoints []string
	seen := make(map[string]bool)

	// Fetch calls - more permissive pattern
	fetchPattern := regexp.MustCompile(`fetch\s*\(\s*['"]([/][A-Za-z0-9\-_/]*?)['"]`)
	matches := fetchPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] && !isAssetPath(normalized) {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// Axios calls - more permissive pattern
	axiosPattern := regexp.MustCompile(`axios\.(?:get|post|put|delete|patch|request)\s*\(\s*['"]([/][A-Za-z0-9\-_/]*?)['"]`)
	matches = axiosPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] && !isAssetPath(normalized) {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// XHR calls - more permissive pattern
	xhrPattern := regexp.MustCompile(`\.open\s*\(\s*['"][A-Z]+\s*['"]\s*,\s*['"]([/][A-Za-z0-9\-_/]*?)['"]`)
	matches = xhrPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] && !isAssetPath(normalized) {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// Route definitions - more permissive pattern
	routePattern := regexp.MustCompile(`\.(?:get|post|put|delete|patch|all)\s*\(\s*['"]([/][A-Za-z0-9\-_/]*?)['"]`)
	matches = routePattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] && !isAssetPath(normalized) {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// GraphQL endpoints
	graphqlPattern := regexp.MustCompile(`(?:graphql|gql)\s*[:=]\s*['"]([/]?[A-Za-z0-9\-_/]*graphql[A-Za-z0-9\-_/]*)['"]`)
	matches = graphqlPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// Config paths
	configPattern := regexp.MustCompile(`(?:signIn|signUp|signOut|api|auth|endpoint|route|path|basePath|baseUrl|baseURL)[Pp]ath?\s*[:=]\s*['"]([/][A-Za-z0-9\-_/]+)['"]`)
	matches = configPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// Path assignments
	pathPattern := regexp.MustCompile(`(?:path|endpoint|route|url|uri)\s*[:=]\s*['"]([/][A-Za-z0-9\-_/]+)['"]`)
	matches = pathPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// Common routes - expanded to catch v4, v5, etc. and more patterns
	commonRoutePattern := regexp.MustCompile(`['"]([/](?:v[0-9]+|v[0-9]+/|signin|signup|sign-out|sign-in|login|logout|register|auth|api|admin|internal|graphql|rest|guest|service|tmfbsn|urm)[/]?[A-Za-z0-9\-_/]*)['"]`)
	matches = commonRoutePattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] && !isAssetPath(normalized) {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// Additional pattern: catch any path starting with /v followed by numbers
	vVersionPattern := regexp.MustCompile(`['"]([/]v[0-9]+[/]?[A-Za-z0-9\-_/]*)['"]`)
	matches = vVersionPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] && !isAssetPath(normalized) {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// Pattern for paths in object properties and assignments
	objectPathPattern := regexp.MustCompile(`(?:path|endpoint|route|url|uri|api|baseUrl|baseURL)\s*[:=]\s*['"]([/][A-Za-z0-9\-_/]+)['"]`)
	matches = objectPathPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			normalized := normalizeEndpoint(match[1])
			if normalized != "" && !seen[normalized] && !isAssetPath(normalized) {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	// Extract from URLs - more comprehensive pattern
	urlPattern := regexp.MustCompile(`https?://[^/'"\s]+([/][A-Za-z0-9\-_/.]+)`)
	matches = urlPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) > 1 {
			// Extract path from URL, remove query strings and fragments
			path := match[1]
			path = strings.Split(path, "?")[0]
			path = strings.Split(path, "#")[0]
			
			normalized := normalizeEndpoint(path)
			if normalized != "" && !seen[normalized] && !isAssetPath(normalized) {
				endpoints = append(endpoints, normalized)
				seen[normalized] = true
			}
		}
	}

	return endpoints
}

func (e *Extractor) extractImportantEndpoints(content string) []string {
	allEndpoints := e.extractEndpoints(content)
	var important []string
	seen := make(map[string]bool)

	for _, endpoint := range allEndpoints {
		if isImportantEndpoint(endpoint) && !seen[endpoint] {
			important = append(important, endpoint)
			seen[endpoint] = true
		}
	}

	return important
}

func (e *Extractor) extractURLs(content string) []string {
	var urls []string
	seen := make(map[string]bool)

	// Absolute URLs - be more permissive, extract all URLs first
	// Pattern matches http:// or https:// followed by valid URL characters
	urlPattern := regexp.MustCompile(`https?://[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+`)
	matches := urlPattern.FindAllString(content, -1)
	for _, match := range matches {
		// Remove trailing punctuation that might have been captured
		match = strings.TrimRight(match, ".,;:!?)")
		
		normalized := normalizeURL(match)
		if normalized != "" && !seen[normalized] {
			// Filter out common CDN/media URLs unless they look like APIs
			if !isExcludedURL(normalized) {
				urls = append(urls, normalized)
				seen[normalized] = true
			}
		}
	}

	return urls
}

func deduplicateSecrets(secrets []Secret) []Secret {
	seen := make(map[string]bool)
	var unique []Secret

	for _, secret := range secrets {
		key := secret.Type + ":" + secret.Value
		if !seen[key] {
			seen[key] = true
			unique = append(unique, secret)
		}
	}

	return unique
}
