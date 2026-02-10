package main

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type Downloader struct {
	client *http.Client
}

func NewDownloader() *Downloader {
	return &Downloader{
		client: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return nil // Follow redirects
			},
		},
	}
}

func (d *Downloader) Download(url, outputPath string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set browser-like headers
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Cache-Control", "max-age=0")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Create output file
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	// Handle compression
	var reader io.Reader = resp.Body
	contentEncoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))

	if contentEncoding == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer gzReader.Close()
		reader = gzReader
	} else if contentEncoding == "deflate" {
		zlibReader, err := zlib.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to create zlib reader: %w", err)
		}
		defer zlibReader.Close()
		reader = zlibReader
	} else if contentEncoding == "br" || contentEncoding == "brotli" {
		// Brotli decompression would require a third-party library
		// For now, we'll try to detect it from magic bytes after download
		reader = resp.Body
	}

	// Copy to file
	_, err = io.Copy(file, reader)
	if err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	// Check if file needs decompression (magic bytes detection)
	if contentEncoding == "" || contentEncoding == "br" || contentEncoding == "brotli" {
		if err := d.checkAndDecompress(outputPath); err != nil {
			// If decompression fails, file might not be compressed
			// Continue anyway
		}
	}

	return nil
}

func (d *Downloader) checkAndDecompress(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read first few bytes to detect compression
	buffer := make([]byte, 4)
	n, err := file.Read(buffer)
	if err != nil && err != io.EOF {
		return err
	}
	if n < 2 {
		return nil // File too small
	}

	compressionType := detectCompressionFromBytes(buffer[:n])
	if compressionType == "" {
		return nil // No compression detected
	}

	// Read entire file
	file.Seek(0, 0)
	fileData, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	// Decompress
	var decompressed []byte
	if compressionType == "gzip" {
		reader, err := gzip.NewReader(bytes.NewReader(fileData))
		if err != nil {
			return err
		}
		defer reader.Close()
		decompressed, err = io.ReadAll(reader)
		if err != nil {
			return err
		}
	} else if compressionType == "deflate" {
		reader, err := zlib.NewReader(bytes.NewReader(fileData))
		if err != nil {
			return err
		}
		defer reader.Close()
		decompressed, err = io.ReadAll(reader)
		if err != nil {
			return err
		}
	} else {
		return nil // Unknown compression type
	}

	// Write decompressed content back
	if err := os.WriteFile(filePath, decompressed, 0644); err != nil {
		return err
	}

	return nil
}

func detectCompressionFromBytes(buffer []byte) string {
	if len(buffer) < 2 {
		return ""
	}

	// Gzip magic bytes: 1F 8B
	if buffer[0] == 0x1F && buffer[1] == 0x8B {
		return "gzip"
	}

	// Zlib/Deflate streams start with 78
	if buffer[0] == 0x78 {
		if len(buffer) >= 2 {
			secondByte := buffer[1]
			if secondByte == 0x9C || secondByte == 0x01 || secondByte == 0xDA ||
				secondByte == 0x5E || secondByte == 0xBB || secondByte == 0x94 {
				return "deflate"
			}
		}
	}

	return ""
}
