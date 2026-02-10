package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type Config struct {
	OutputDir string
	Append    bool
	NoColor   bool
	JSON      bool
	Quiet     bool
}

type CLI struct {
	config     *Config
	extractor  *Extractor
	downloader *Downloader
}

func NewCLI(config *Config) *CLI {
	return &CLI{
		config:     config,
		extractor:  NewExtractor(),
		downloader: NewDownloader(),
	}
}

func (c *CLI) log(message string, color string) {
	if c.config.Quiet {
		return
	}
	if c.config.NoColor {
		fmt.Println(message)
	} else {
		fmt.Printf("%s%s%s\n", color, message, colorReset)
	}
}

func (c *CLI) ProcessFile(filePath string) error {
	c.log(fmt.Sprintf("Processing file: %s", filePath), colorCyan)

	content, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	return c.processContent(string(content), filepath.Base(filePath))
}

func (c *CLI) ProcessDirectory(dirPath string) error {
	c.log(fmt.Sprintf("Processing directory: %s", dirPath), colorCyan)

	var jsFiles []string
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "node_modules" || info.Name() == ".git" || strings.HasPrefix(info.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".js" || ext == ".mjs" || ext == ".cjs" {
			jsFiles = append(jsFiles, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	c.log(fmt.Sprintf("Found %d JavaScript file(s)", len(jsFiles)), colorCyan)

	var allResults []*Results
	for _, file := range jsFiles {
		c.log(fmt.Sprintf("Processing: %s", file), colorDim)
		content, err := os.ReadFile(file)
		if err != nil {
			c.log(fmt.Sprintf("Error reading %s: %v", file, err), colorRed)
			continue
		}

		results := c.extractor.ExtractAll(string(content), filepath.Base(file))
		allResults = append(allResults, results)
	}

	return c.writeResults(allResults)
}

func (c *CLI) ProcessURL(url string) error {
	c.log(fmt.Sprintf("Downloading: %s", url), colorCyan)

	tempDir := filepath.Join(".", ".jsdumper-downloads")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	fileName := filepath.Base(url)
	if fileName == "" || fileName == "/" {
		fileName = "downloaded.js"
	}
	localPath := filepath.Join(tempDir, fileName)

	if err := c.downloader.Download(url, localPath); err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}

	c.log(fmt.Sprintf("Downloaded successfully: %s", localPath), colorGreen)
	c.log(fmt.Sprintf("Processing: %s", localPath), colorCyan)

	content, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("failed to read downloaded file: %w", err)
	}

	return c.processContent(string(content), filepath.Base(localPath))
}

func (c *CLI) ProcessList(listFile string) error {
	c.log(fmt.Sprintf("Reading URLs from: %s", listFile), colorCyan)

	file, err := os.Open(listFile)
	if err != nil {
		return fmt.Errorf("failed to open list file: %w", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			urls = append(urls, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("failed to read list file: %w", err)
	}

	if len(urls) == 0 {
		c.log(fmt.Sprintf("No URLs found in %s", listFile), colorYellow)
		return nil
	}

	c.log(fmt.Sprintf("Downloading %d remote file(s)...", len(urls)), colorCyan)

	tempDir := filepath.Join(".", ".jsdumper-downloads")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	var allResults []*Results
	for i, url := range urls {
		fileName := filepath.Base(url)
		if fileName == "" || fileName == "/" {
			fileName = fmt.Sprintf("downloaded_%d.js", i+1)
		}
		localPath := filepath.Join(tempDir, fileName)

		c.log(fmt.Sprintf("Downloading: %s", url), colorDim)
		if err := c.downloader.Download(url, localPath); err != nil {
			c.log(fmt.Sprintf("Error downloading %s: %v", url, err), colorRed)
			continue
		}

		c.log(fmt.Sprintf("Processing: %s", localPath), colorDim)
		content, err := os.ReadFile(localPath)
		if err != nil {
			c.log(fmt.Sprintf("Error reading %s: %v", localPath, err), colorRed)
			continue
		}

		results := c.extractor.ExtractAll(string(content), filepath.Base(localPath))
		allResults = append(allResults, results)
	}

	c.log(fmt.Sprintf("Downloaded %d file(s)", len(allResults)), colorGreen)
	return c.writeResults(allResults)
}

func (c *CLI) ProcessStdin() error {
	c.log("Reading from stdin...", colorCyan)

	content, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read stdin: %w", err)
	}

	// Check if it's a list of URLs/file paths
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) > 0 {
		looksLikeList := true
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			// Check if line looks like a file path or URL
			if !strings.HasSuffix(trimmed, ".js") &&
				!strings.HasSuffix(trimmed, ".mjs") &&
				!strings.HasSuffix(trimmed, ".cjs") &&
				!strings.HasPrefix(trimmed, "/") &&
				!strings.HasPrefix(trimmed, "./") &&
				!strings.HasPrefix(trimmed, "http://") &&
				!strings.HasPrefix(trimmed, "https://") &&
				!isURL(trimmed) {
				looksLikeList = false
				break
			}
		}

		if looksLikeList && len(lines) > 0 {
			// Treat as list of URLs/files
			var urls []string
			var localFiles []string

			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				if isURL(trimmed) {
					urls = append(urls, trimmed)
				} else if _, err := os.Stat(trimmed); err == nil {
					localFiles = append(localFiles, trimmed)
				}
			}

			// Download URLs first
			if len(urls) > 0 {
				tempDir := filepath.Join(".", ".jsdumper-downloads")
				if err := os.MkdirAll(tempDir, 0755); err != nil {
					return fmt.Errorf("failed to create temp directory: %w", err)
				}

				for i, url := range urls {
					fileName := filepath.Base(url)
					if fileName == "" || fileName == "/" {
						fileName = fmt.Sprintf("downloaded_%d.js", i+1)
					}
					localPath := filepath.Join(tempDir, fileName)

					if err := c.downloader.Download(url, localPath); err != nil {
						c.log(fmt.Sprintf("Error downloading %s: %v", url, err), colorRed)
						continue
					}
					localFiles = append(localFiles, localPath)
				}
			}

			// Process all files
			var allResults []*Results
			for _, filePath := range localFiles {
				content, err := os.ReadFile(filePath)
				if err != nil {
					c.log(fmt.Sprintf("Error reading %s: %v", filePath, err), colorRed)
					continue
				}
				results := c.extractor.ExtractAll(string(content), filepath.Base(filePath))
				allResults = append(allResults, results)
			}

			return c.writeResults(allResults)
		}
	}

	// Process as JavaScript content
	return c.processContent(string(content), "stdin")
}

func (c *CLI) processContent(content, fileName string) error {
	// Check if file is empty
	if len(content) == 0 {
		c.log(fmt.Sprintf("Warning: File %s is empty", fileName), colorYellow)
		return nil
	}

	trimmed := strings.TrimSpace(content)
	
	// More precise HTML detection - only check the very beginning of the file
	// JavaScript files can contain "<html" in strings/comments, but real HTML files
	// will start with HTML tags
	isHTML := false
	firstChars := strings.ToLower(trimmed)
	if len(firstChars) > 0 {
		// Check for HTML document structure at the start
		if strings.HasPrefix(firstChars, "<!doctype") ||
			strings.HasPrefix(firstChars, "<html") ||
			strings.HasPrefix(firstChars, "<?xml") {
			isHTML = true
		}
		
		// Additional check: if first 500 chars contain multiple HTML tags, it's likely HTML
		if !isHTML && len(trimmed) > 500 {
			first500 := strings.ToLower(trimmed[:500])
			htmlTagCount := strings.Count(first500, "<html") +
				strings.Count(first500, "<head") +
				strings.Count(first500, "<body") +
				strings.Count(first500, "<div") +
				strings.Count(first500, "<script")
			// If we see many HTML tags at the start, it's likely HTML
			// But also check if it looks like JavaScript (has function, var, const, etc.)
			jsIndicators := strings.Count(first500, "function") +
				strings.Count(first500, "var ") +
				strings.Count(first500, "const ") +
				strings.Count(first500, "let ") +
				strings.Count(first500, "=>") +
				strings.Count(first500, "()")
			
			// If HTML tags outnumber JS indicators significantly, it's HTML
			if htmlTagCount > 3 && htmlTagCount > jsIndicators*2 {
				isHTML = true
			}
		}
	}
	
	if isHTML {
		c.log(fmt.Sprintf("Warning: File %s appears to be HTML, not JavaScript", fileName), colorYellow)
		c.log(fmt.Sprintf("First 200 chars: %s", trimmed[:min(200, len(trimmed))]), colorDim)
		// Some servers return HTML error pages instead of the JS file
		return nil
	}

	results := c.extractor.ExtractAll(content, fileName)
	return c.writeResults([]*Results{results})
}

func (c *CLI) writeResults(results []*Results) error {
	// Aggregate results
	aggregated := aggregateResults(results)

	// Ensure output directory exists
	if err := os.MkdirAll(c.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Write secrets
	if err := c.writeFile(filepath.Join(c.config.OutputDir, "keys.txt"), aggregated.formatSecrets(), c.config.Append); err != nil {
		return err
	}

	// Write all endpoints
	if err := c.writeFile(filepath.Join(c.config.OutputDir, "endpoints.txt"), aggregated.formatEndpoints(), c.config.Append); err != nil {
		return err
	}

	// Write important endpoints
	if err := c.writeFile(filepath.Join(c.config.OutputDir, "important-endpoints.txt"), aggregated.formatImportantEndpoints(), c.config.Append); err != nil {
		return err
	}

	// Write URLs
	if err := c.writeFile(filepath.Join(c.config.OutputDir, "urls.txt"), aggregated.formatURLs(), c.config.Append); err != nil {
		return err
	}

	// Write JSON summary if requested
	if c.config.JSON {
		if err := aggregated.writeJSON(filepath.Join(c.config.OutputDir, "summary.json")); err != nil {
			return err
		}
		c.log(fmt.Sprintf("Summary written to: %s", filepath.Join(c.config.OutputDir, "summary.json")), colorGreen)
	}

	// Print summary
	c.log("", "")
	c.log("=== Extraction Summary ===", colorGreen)
	c.log(fmt.Sprintf("Secrets found: %d", len(aggregated.Secrets)), colorCyan)
	highCount := 0
	mediumCount := 0
	lowCount := 0
	for _, s := range aggregated.Secrets {
		switch s.Severity {
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}
	c.log(fmt.Sprintf("  HIGH: %d", highCount), colorRed)
	c.log(fmt.Sprintf("  MEDIUM: %d", mediumCount), colorYellow)
	c.log(fmt.Sprintf("  LOW: %d", lowCount), colorDim)
	c.log(fmt.Sprintf("Endpoints found: %d", len(aggregated.Endpoints)), colorCyan)
	c.log(fmt.Sprintf("  Important: %d", len(aggregated.ImportantEndpoints)), colorGreen)
	c.log(fmt.Sprintf("URLs found: %d", len(aggregated.URLs)), colorCyan)
	c.log("", "")
	absOutput, _ := filepath.Abs(c.config.OutputDir)
	c.log(fmt.Sprintf("Results written to: %s", absOutput), colorGreen)
	c.log("  - endpoints.txt (all endpoints)", colorDim)
	c.log("  - important-endpoints.txt (API endpoints only)", colorDim)

	return nil
}

func (c *CLI) writeFile(filePath string, lines []string, append bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
	}

	file, err := os.OpenFile(filePath, flags, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	for _, line := range lines {
		if _, err := fmt.Fprintln(file, line); err != nil {
			return fmt.Errorf("failed to write to file %s: %w", filePath, err)
		}
	}

	return nil
}

func isURL(str string) bool {
	return strings.HasPrefix(str, "http://") || strings.HasPrefix(str, "https://")
}
