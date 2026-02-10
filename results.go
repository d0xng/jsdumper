package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"
)

type AggregatedResults struct {
	Secrets            []Secret
	Endpoints          []string
	ImportantEndpoints []string
	URLs               []string
}

func aggregateResults(results []*Results) *AggregatedResults {
	aggregated := &AggregatedResults{
		Secrets:            []Secret{},
		Endpoints:          []string{},
		ImportantEndpoints: []string{},
		URLs:               []string{},
	}

	endpointSet := make(map[string]bool)
	importantEndpointSet := make(map[string]bool)
	urlSet := make(map[string]bool)
	secretSet := make(map[string]bool)

	for _, result := range results {
		// Aggregate secrets
		for _, secret := range result.Secrets {
			key := secret.Type + ":" + secret.Value
			if !secretSet[key] {
				aggregated.Secrets = append(aggregated.Secrets, secret)
				secretSet[key] = true
			}
		}

		// Aggregate endpoints
		for _, endpoint := range result.Endpoints {
			if !endpointSet[endpoint] {
				aggregated.Endpoints = append(aggregated.Endpoints, endpoint)
				endpointSet[endpoint] = true
			}
		}

		// Aggregate important endpoints
		for _, endpoint := range result.ImportantEndpoints {
			if !importantEndpointSet[endpoint] {
				aggregated.ImportantEndpoints = append(aggregated.ImportantEndpoints, endpoint)
				importantEndpointSet[endpoint] = true
			}
		}

		// Aggregate URLs
		for _, url := range result.URLs {
			if !urlSet[url] {
				aggregated.URLs = append(aggregated.URLs, url)
				urlSet[url] = true
			}
		}
	}

	// Sort results
	sort.Strings(aggregated.Endpoints)
	sort.Strings(aggregated.ImportantEndpoints)
	sort.Strings(aggregated.URLs)

	return aggregated
}

func (a *AggregatedResults) formatSecrets() []string {
	var lines []string
	for _, secret := range a.Secrets {
		lines = append(lines, fmt.Sprintf("%s | %s | %s", secret.Type, secret.File, secret.Value))
	}
	return lines
}

func (a *AggregatedResults) formatEndpoints() []string {
	return a.Endpoints
}

func (a *AggregatedResults) formatImportantEndpoints() []string {
	return a.ImportantEndpoints
}

func (a *AggregatedResults) formatURLs() []string {
	return a.URLs
}

func (a *AggregatedResults) writeJSON(filePath string) error {
	// Count secrets by type and severity
	byType := make(map[string]int)
	highCount := 0
	mediumCount := 0
	lowCount := 0

	for _, secret := range a.Secrets {
		byType[secret.Type]++
		switch secret.Severity {
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	summary := map[string]interface{}{
		"timestamp": time.Now().Format(time.RFC3339),
		"secrets": map[string]interface{}{
			"total": len(a.Secrets),
			"byType": byType,
			"bySeverity": map[string]int{
				"HIGH":   highCount,
				"MEDIUM": mediumCount,
				"LOW":    lowCount,
			},
		},
		"endpoints": map[string]int{
			"total":    len(a.Endpoints),
			"important": len(a.ImportantEndpoints),
		},
		"urls": map[string]int{
			"total": len(a.URLs),
		},
	}

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %w", err)
	}

	return nil
}
