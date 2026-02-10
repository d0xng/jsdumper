# jsdumper

A high-precision CLI tool for extracting security-relevant artifacts from JavaScript files. Designed for security research and bug bounty hunting.

## Features

- **Secrets & Keys Extraction**: Detects AWS keys, JWTs, OAuth tokens, API keys, and more with context-aware validation
- **API Endpoints Discovery**: Extracts meaningful API endpoints from fetch, axios, and route definitions
- **URL Extraction**: Finds absolute URLs while filtering out noise
- **Low False Positives**: Advanced regex patterns with entropy checks and context validation
- **Multiple Input Methods**: Single file, directory (recursive), or stdin
- **Structured Output**: Results written to separate files with severity levels

## Installation

### Requirements

- Go 1.22 or higher

### Linux

```bash
git clone <repo-url>
cd jsdumper
sudo ./install.sh
```

This will:
- Build the Go binary
- Create a symlink in `/usr/bin/jsdumper`
- Make the tool available system-wide

### Manual Installation

```bash
go build -o bin/jsdumper .
```

Or use directly:

```bash
go run . <input>
```

## Usage

### Basic Usage

```bash
# Analyze a single local file
jsdumper app.js

# Analyze a directory (recursive)
jsdumper src/

# Download and analyze a single URL
jsdumper -u https://example.com/file.js --output results

# Download and analyze multiple URLs from a file
jsdumper -l urls.txt --output results

# Read from stdin
cat file.js | jsdumper -

# Specify output directory
jsdumper src/ --output ./results

# Append to existing output files
jsdumper src/ --append
```

### Options

```
Options:
  -u, --url <url>       Download and analyze a single URL
  -l, --list <file>     Read URLs from a text file (one per line)
  -o, --output <dir>    Output directory (default: ./)
  -a, --append          Append to output files instead of overwriting
  --no-color            Disable colored output
  --json                Generate summary.json with statistics
  -q, --quiet           Suppress all output except errors
  -h, --help            Display help
  -V, --version         Display version
```

## Output Files

The tool generates four output files:

### keys.txt
Contains detected secrets and keys (full values shown):

```
AWS_ACCESS_KEY_ID | app.js | AKIAIOSFODNN7EXAMPLE
JWT | app.js | eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
STRIPE_SECRET_KEY | payment.js | sk_live_51Hqw2EXAMPLE
```

### endpoints.txt
List of all discovered endpoints (including corporate pages, content management, etc.):

```
/api/v1/users
/auth/login
/admin/export
/graphql
/business
/privacy-center
```

### important-endpoints.txt
Filtered list of high-value API endpoints only:

```
/api/v1/users
/auth/login
/admin/export
/graphql
/v1/tokens
```

### urls.txt
Absolute URLs found in the code:

```
https://api.example.com/v2/login
https://config.service.com/settings
```

### summary.json (optional)
Statistics and summary when using `--json` flag:

```json
{
  "timestamp": "2024-01-01T00:00:00.000Z",
  "secrets": {
    "total": 5,
    "byType": {
      "AWS_ACCESS_KEY_ID": 1,
      "JWT": 2
    },
    "bySeverity": {
      "HIGH": 3,
      "MEDIUM": 2,
      "LOW": 0
    }
  },
  "endpoints": {
    "total": 15,
    "important": 8
  },
  "urls": {
    "total": 8
  }
}
```

## What Gets Detected

### Secrets & Keys (High Priority)

- **AWS Access Key ID**: `AKIA[0-9A-Z]{16}`
- **AWS Secret Access Key**: Context-aware detection with entropy validation
- **JWT Tokens**: Full JWT format (header.payload.signature)
- **OAuth Credentials**: `client_id` and `client_secret` with assignment context
- **Bearer Tokens**: Authorization header tokens
- **Firebase API Keys**: `AIza[0-9A-Za-z_-]{35}`
- **Stripe Keys**: Live and test keys (`sk_live_`, `sk_test_`, etc.)
- **Generic API Keys**: Only if high entropy and assigned to key-related variables
- **Hardcoded Passwords**: Only if assigned to auth-related variables (excludes placeholders)

### API Endpoints

Extracts endpoints from:
- `fetch()` calls
- `axios` methods (get, post, put, delete, etc.)
- `XMLHttpRequest` calls
- Route definitions (Express, etc.)
- GraphQL endpoints
- Template literals and concatenated paths

Filters out:
- CSS files
- Image assets
- Font files
- Source maps
- Common asset directories (unless API-like)

### URLs

- Absolute URLs (`http://`, `https://`)
- Filters common CDN URLs unless they appear API-related
- Excludes media file URLs

## False Positive Prevention

The tool uses several strategies to minimize false positives:

1. **Context Validation**: Secrets must be assigned to relevant variables, not just match patterns
2. **Entropy Checks**: Generic keys require high Shannon entropy (≥4.5)
3. **Pattern Exclusion**: Common placeholders, test values, and build IDs are excluded
4. **Asset Filtering**: Endpoints exclude CSS, images, fonts, and other non-API assets
5. **CDN Filtering**: Common CDN URLs are excluded unless they contain API-like paths

## Examples

### Example 1: Single File

```bash
$ jsdumper app.js

Processing file: app.js
=== Extraction Summary ===
Secrets found: 3
  HIGH: 2
  MEDIUM: 1
  LOW: 0
Endpoints found: 12
  Important: 8
URLs found: 5

Results written to: /path/to/output
  - endpoints.txt (all endpoints)
  - important-endpoints.txt (API endpoints only)
```

### Example 2: Directory Analysis

```bash
$ jsdumper src/ --output ./results --json

Found 45 JavaScript file(s)
Processing: src/app.js
Processing: src/api.js
...
=== Extraction Summary ===
Secrets found: 8
Endpoints found: 67
  Important: 23
URLs found: 23

Results written to: ./results
Summary written to: ./results/summary.json
```

### Example 3: Stdin Pipeline

```bash
$ cat minified.js | jsdumper - --quiet

# Output files created silently
```

## Architecture

```
jsdumper/
├── main.go                  # CLI entry point
├── cli.go                   # CLI logic and file processing
├── extractor.go             # Secrets, endpoints, and URLs extraction
├── downloader.go            # Remote file download with auto-decompression
├── utils.go                 # Utility functions (entropy, normalization)
├── results.go               # Results aggregation and formatting
├── patterns.go              # Regex pattern definitions (structure)
├── colors.go                # Color constants for output
├── bin/
│   └── jsdumper             # Compiled binary
├── go.mod                   # Go module definition
├── go.sum                   # Go dependencies checksums
├── install.sh               # Linux installation script
└── README.md
```

## Security Considerations

- **Accuracy over Quantity**: The tool prioritizes precision and avoids low-confidence findings
- **Full Values Shown**: Secrets are displayed in full (not masked) for security research purposes
- **Research Use**: Intended for security research and authorized bug bounty activities
- **Remote Downloads**: The tool can download and analyze remote JavaScript files with automatic decompression support (gzip, deflate, brotli)

## Features

- **Automatic Decompression**: Handles gzip, deflate, and Brotli compressed files automatically
- **Remote URL Support**: Download and analyze JavaScript files from URLs
- **Batch Processing**: Process multiple URLs from a text file
- **High Performance**: Written in Go for fast processing of large files

## Limitations

- Regex-based extraction (not full AST parsing) - may miss some complex cases
- Minified code: Works but may have reduced accuracy
- Obfuscated code: Limited effectiveness against heavy obfuscation
- Dynamic paths: May miss endpoints constructed entirely at runtime

## License

GPL-3.0

## Contributing

This tool is designed for security research. Contributions that improve accuracy and reduce false positives are welcome.
