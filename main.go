package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	var (
		urlFlag      = flag.String("u", "", "Download and analyze a single URL")
		listFlag     = flag.String("l", "", "Read URLs from a text file (one per line)")
		outputFlag   = flag.String("o", "./", "Output directory")
		appendFlag   = flag.Bool("a", false, "Append to output files instead of overwriting")
		noColorFlag  = flag.Bool("no-color", false, "Disable colored output")
		jsonFlag     = flag.Bool("json", false, "Generate summary.json with statistics")
		quietFlag    = flag.Bool("q", false, "Suppress all output except errors")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] [input]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nExtract security-relevant artifacts from JavaScript files\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  %s file.js\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -u https://example.com/file.js\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -l urls.txt -o results\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  cat file.js | %s -\n", os.Args[0])
	}

	flag.Parse()

	args := flag.Args()
	input := ""
	if len(args) > 0 {
		input = args[0]
	}

	// Show help if no input, URL, or list file provided
	if *urlFlag == "" && *listFlag == "" && (input == "" || input == "-") {
		flag.Usage()
		return
	}

	// Initialize CLI
	cli := NewCLI(&Config{
		OutputDir: *outputFlag,
		Append:    *appendFlag,
		NoColor:   *noColorFlag,
		JSON:      *jsonFlag,
		Quiet:     *quietFlag,
	})

	// Handle different input types
	if *urlFlag != "" {
		// Single URL
		if err := cli.ProcessURL(*urlFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if *listFlag != "" {
		// List file
		if err := cli.ProcessList(*listFlag); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if input == "" || input == "-" {
		// Stdin
		if err := cli.ProcessStdin(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else {
		// File or directory
		info, err := os.Stat(input)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		if info.IsDir() {
			if err := cli.ProcessDirectory(input); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Check if it's a .txt file with URLs
			if strings.HasSuffix(strings.ToLower(input), ".txt") || strings.HasSuffix(strings.ToLower(input), ".list") {
				if err := cli.ProcessList(input); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			} else {
				// Regular file
				if err := cli.ProcessFile(input); err != nil {
					fmt.Fprintf(os.Stderr, "Error: %v\n", err)
					os.Exit(1)
				}
			}
		}
	}
}
