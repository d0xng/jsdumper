#!/usr/bin/env node

/**
 * jsdumper CLI
 * 
 * Analyzes JavaScript files and extracts security-relevant artifacts:
 * - Secrets and keys
 * - API endpoints
 * - Absolute URLs
 */

const { program } = require('commander');
const fs = require('fs');
const path = require('path');
const { findJsFiles, readFile, readStdin, writeResults, ensureDir, isUrl, downloadFiles } = require('./utils');
const { extractAllSecrets, formatSecretFinding } = require('./extractors/secrets');
const { extractAllEndpoints } = require('./extractors/endpoints');
const { extractAllUrls } = require('./extractors/urls');

// Colors for output (can be disabled)
const colors = {
  reset: '\x1b[0m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m'
};

let useColors = true;

/**
 * Log message (respects --quiet and --no-color flags)
 */
function log(message, color = '') {
  if (program.opts().quiet) return;
  
  if (useColors && color) {
    console.log(`${colors[color]}${message}${colors.reset}`);
  } else {
    console.log(message);
  }
}

/**
 * Process a single JavaScript file
 * @param {string} filePath - Path to JavaScript file
 * @returns {Promise<Object>} Extraction results
 */
async function processFile(filePath) {
  try {
    const content = await readFile(filePath);
    const fileName = path.basename(filePath);
    
    const secrets = extractAllSecrets(content, fileName);
    const endpoints = extractAllEndpoints(content);
    const urls = extractAllUrls(content);
    
    return {
      file: filePath,
      secrets,
      endpoints,
      urls
    };
  } catch (error) {
    log(`Error processing ${filePath}: ${error.message}`, 'red');
    return null;
  }
}

/**
 * Process stdin input
 * Can be either:
 * - JavaScript code content (to analyze directly)
 * - List of file paths or URLs (one per line) to process multiple files
 * @returns {Promise<Object|Array>} Extraction results
 */
async function processStdin() {
  try {
    const content = await readStdin();
    
    // Check if stdin contains file paths or URLs (one per line)
    const lines = content.trim().split('\n').filter(line => line.trim().length > 0);
    
    // If all lines look like file paths or URLs, treat as file list
    const looksLikeFileList = lines.length > 0 && lines.every(line => {
      const trimmed = line.trim();
      return trimmed.endsWith('.js') || 
             trimmed.endsWith('.mjs') || 
             trimmed.endsWith('.cjs') ||
             trimmed.startsWith('/') ||
             trimmed.startsWith('./') ||
             trimmed.match(/^[A-Za-z]:\\/) || // Windows paths
             isUrl(trimmed) ||
             fs.existsSync(trimmed);
    });
    
    if (looksLikeFileList && lines.length > 0) {
      const results = [];
      
      // Check if all lines are URLs (most common case for .txt files)
      const allUrls = lines.every(line => isUrl(line.trim()));
      
      if (allUrls) {
        // All lines are URLs - download and process
        const urls = lines.map(line => line.trim()).filter(line => line.length > 0);
        
        log(`Downloading ${urls.length} remote file(s)...`, 'cyan');
        const tempDir = path.join(process.cwd(), '.jsdumper-downloads');
        ensureDir(tempDir);
        
        try {
          const downloaded = await downloadFiles(urls, tempDir);
          log(`Downloaded ${downloaded.length} file(s)`, 'green');
          
          // Process all downloaded files
          log(`Processing ${downloaded.length} file(s)...`, 'cyan');
          for (let file of downloaded) {
            log(`Processing: ${file.localPath}`, 'dim');
            const result = await processFile(file.localPath);
            if (result) {
              results.push(result);
            }
          }
        } catch (error) {
          log(`Error downloading/processing files: ${error.message}`, 'red');
        }
      } else {
        // Mix of URLs and local files (fallback)
        const urls = [];
        const localFiles = [];
        
        for (let line of lines) {
          line = line.trim();
          if (isUrl(line)) {
            urls.push(line);
          } else {
            localFiles.push(line);
          }
        }
        
        // Download remote files first
        if (urls.length > 0) {
          log(`Downloading ${urls.length} remote file(s)...`, 'cyan');
          const tempDir = path.join(process.cwd(), '.jsdumper-downloads');
          ensureDir(tempDir);
          
          try {
            const downloaded = await downloadFiles(urls, tempDir);
            log(`Downloaded ${downloaded.length} file(s)`, 'green');
            
            // Add downloaded files to local files list
            for (let file of downloaded) {
              localFiles.push(file.localPath);
            }
          } catch (error) {
            log(`Error downloading files: ${error.message}`, 'red');
          }
        }
        
        // Process all files (local + downloaded)
        log(`Processing ${localFiles.length} file(s)...`, 'cyan');
        for (let filePath of localFiles) {
          if (fs.existsSync(filePath)) {
            log(`Processing: ${filePath}`, 'dim');
            const result = await processFile(filePath);
            if (result) {
              results.push(result);
            }
          } else {
            log(`File not found: ${filePath}`, 'yellow');
          }
        }
      }
      
      return results; // Return array of results
    } else {
      // Process as JavaScript content
      const secrets = extractAllSecrets(content, 'stdin');
      const endpoints = extractAllEndpoints(content);
      const urls = extractAllUrls(content);
      
      return {
        file: 'stdin',
        secrets,
        endpoints,
        urls
      };
    }
  } catch (error) {
    log(`Error processing stdin: ${error.message}`, 'red');
    return null;
  }
}

/**
 * Process directory recursively
 * @param {string} dirPath - Directory path
 * @returns {Promise<Array>} Array of results
 */
async function processDirectory(dirPath) {
  const jsFiles = findJsFiles(dirPath);
  log(`Found ${jsFiles.length} JavaScript file(s)`, 'cyan');
  
  const results = [];
  
  for (let file of jsFiles) {
    log(`Processing: ${file}`, 'dim');
    const result = await processFile(file);
    if (result) {
      results.push(result);
    }
  }
  
  return results;
}

/**
 * Aggregate results from multiple files
 * @param {Array} results - Array of result objects
 * @returns {Object} Aggregated results
 */
function aggregateResults(results) {
  const aggregated = {
    secrets: [],
    endpoints: new Set(),
    importantEndpoints: new Set(),
    urls: new Set()
  };
  
  for (let result of results) {
    if (result) {
      aggregated.secrets.push(...result.secrets);
      
      // Handle new format: endpoints is now {all: [], important: []}
      if (result.endpoints && typeof result.endpoints === 'object' && result.endpoints.all) {
        for (let endpoint of result.endpoints.all) {
          aggregated.endpoints.add(endpoint);
        }
        for (let endpoint of result.endpoints.important) {
          aggregated.importantEndpoints.add(endpoint);
        }
      } else {
        // Fallback for old format (array)
        for (let endpoint of result.endpoints) {
          aggregated.endpoints.add(endpoint);
        }
      }
      
      for (let url of result.urls) {
        aggregated.urls.add(url);
      }
    }
  }
  
  return {
    secrets: aggregated.secrets,
    endpoints: Array.from(aggregated.endpoints).sort(),
    importantEndpoints: Array.from(aggregated.importantEndpoints).sort(),
    urls: Array.from(aggregated.urls).sort()
  };
}

/**
 * Write all results to output files
 * @param {Object} aggregated - Aggregated results
 * @param {string} outputDir - Output directory
 * @param {boolean} append - Whether to append
 */
async function writeOutputFiles(aggregated, outputDir, append) {
  ensureDir(outputDir);
  
  // Write secrets
  const secretLines = aggregated.secrets.map(formatSecretFinding);
  await writeResults(path.join(outputDir, 'keys.txt'), secretLines, append);
  
  // Write all endpoints
  await writeResults(path.join(outputDir, 'endpoints.txt'), aggregated.endpoints, append);
  
  // Write important endpoints only
  await writeResults(path.join(outputDir, 'important-endpoints.txt'), aggregated.importantEndpoints, append);
  
  // Write URLs
  await writeResults(path.join(outputDir, 'urls.txt'), aggregated.urls, append);
  
  // Write JSON summary if requested
  if (program.opts().json) {
    const summary = {
      timestamp: new Date().toISOString(),
      secrets: {
        total: aggregated.secrets.length,
        byType: {},
        bySeverity: {
          HIGH: aggregated.secrets.filter(s => s.severity === 'HIGH').length,
          MEDIUM: aggregated.secrets.filter(s => s.severity === 'MEDIUM').length,
          LOW: aggregated.secrets.filter(s => s.severity === 'LOW').length
        }
      },
      endpoints: {
        total: aggregated.endpoints.length,
        important: aggregated.importantEndpoints.length
      },
      urls: {
        total: aggregated.urls.length
      }
    };
    
    // Count by type
    for (let secret of aggregated.secrets) {
      summary.secrets.byType[secret.type] = (summary.secrets.byType[secret.type] || 0) + 1;
    }
    
    const jsonPath = path.join(outputDir, 'summary.json');
    fs.writeFileSync(jsonPath, JSON.stringify(summary, null, 2), 'utf8');
    log(`Summary written to: ${jsonPath}`, 'green');
  }
}

/**
 * Main CLI function
 */
async function main() {
  program
    .name('jsdumper')
    .description('Extract security-relevant artifacts from JavaScript files')
    .version('1.0.0')
    .argument('[input]', 'JavaScript file, directory, or "-" for stdin')
    .option('-u, --url <url>', 'Download and analyze a single URL')
    .option('-l, --list <file>', 'Read URLs from a text file (one per line)')
    .option('-o, --output <dir>', 'Output directory', './')
    .option('-a, --append', 'Append to output files instead of overwriting', false)
    .option('--no-color', 'Disable colored output')
    .option('--json', 'Generate summary.json with statistics', false)
    .option('-q, --quiet', 'Suppress all output except errors', false)
    .parse(process.argv);
  
  // Handle color flag (--no-color sets color to false)
  useColors = program.opts().color !== false;
  
  const input = program.args[0];
  const outputDir = program.opts().output;
  const append = program.opts().append;
  const url = program.opts().url;
  const listFile = program.opts().list;
  
  let results = [];
  
  try {
    // Handle single URL with -u flag
    if (url) {
      if (!isUrl(url)) {
        log(`Error: "${url}" is not a valid URL`, 'red');
        process.exit(1);
      }
      
      log(`Downloading: ${url}`, 'cyan');
      const tempDir = path.join(process.cwd(), '.jsdumper-downloads');
      ensureDir(tempDir);
      
      try {
        const downloaded = await downloadFiles([url], tempDir);
        if (downloaded.length > 0) {
          log(`Processing: ${downloaded[0].localPath}`, 'cyan');
          const result = await processFile(downloaded[0].localPath);
          if (result) {
            results = [result];
          }
        }
      } catch (error) {
        log(`Error downloading/processing URL: ${error.message}`, 'red');
        process.exit(1);
      }
    }
    // Handle list file with -l flag
    else if (listFile) {
      if (!fs.existsSync(listFile)) {
        log(`Error: File "${listFile}" not found`, 'red');
        process.exit(1);
      }
      
      log(`Reading URLs from: ${listFile}`, 'cyan');
      const fileContent = await readFile(listFile);
      const lines = fileContent.trim().split('\n').filter(line => line.trim().length > 0);
      
      const urls = lines.map(line => line.trim()).filter(line => line.length > 0);
      
      if (urls.length === 0) {
        log(`No URLs found in ${listFile}`, 'yellow');
      } else {
        log(`Downloading ${urls.length} remote file(s)...`, 'cyan');
        const tempDir = path.join(process.cwd(), '.jsdumper-downloads');
        ensureDir(tempDir);
        
        try {
          const downloaded = await downloadFiles(urls, tempDir);
          log(`Downloaded ${downloaded.length} file(s)`, 'green');
          
          log(`Processing ${downloaded.length} file(s)...`, 'cyan');
          for (let file of downloaded) {
            log(`Processing: ${file.localPath}`, 'dim');
            const result = await processFile(file.localPath);
            if (result) {
              results.push(result);
            }
          }
        } catch (error) {
          log(`Error downloading/processing files: ${error.message}`, 'red');
        }
      }
    }
    // Handle stdin
    else if (!input || input === '-') {
      log('Reading from stdin...', 'cyan');
      const result = await processStdin();
      if (result) {
        // processStdin can return either a single object or an array
        if (Array.isArray(result)) {
          results = result;
        } else {
          results = [result];
        }
      }
    }
    // Handle file
    else if (fs.existsSync(input)) {
      const stat = fs.statSync(input);
      
      if (stat.isFile()) {
        // Check if it's a text file with URLs
        if (input.endsWith('.txt') || input.endsWith('.list')) {
          log(`Reading URLs from: ${input}`, 'cyan');
          const fileContent = await readFile(input);
          const lines = fileContent.trim().split('\n').filter(line => line.trim().length > 0);
          
          // All lines should be URLs
          const urls = lines.map(line => line.trim()).filter(line => line.length > 0);
          
          if (urls.length === 0) {
            log(`No URLs found in ${input}`, 'yellow');
          } else {
            // Download all remote files
            log(`Downloading ${urls.length} remote file(s)...`, 'cyan');
            const tempDir = path.join(process.cwd(), '.jsdumper-downloads');
            ensureDir(tempDir);
            
            try {
              const downloaded = await downloadFiles(urls, tempDir);
              log(`Downloaded ${downloaded.length} file(s)`, 'green');
              
              // Process all downloaded files
              log(`Processing ${downloaded.length} file(s)...`, 'cyan');
              for (let file of downloaded) {
                log(`Processing: ${file.localPath}`, 'dim');
                const result = await processFile(file.localPath);
                if (result) {
                  results.push(result);
                }
              }
            } catch (error) {
              log(`Error downloading/processing files: ${error.message}`, 'red');
            }
          }
        } else {
          // Regular JavaScript file
          log(`Processing file: ${input}`, 'cyan');
          const result = await processFile(input);
          if (result) {
            results = [result];
          }
        }
      }
      // Handle directory
      else if (stat.isDirectory()) {
        log(`Processing directory: ${input}`, 'cyan');
        results = await processDirectory(input);
      }
    } else {
      log(`Error: Input "${input}" not found`, 'red');
      process.exit(1);
    }
    
    if (results.length === 0) {
      log('No results to process', 'yellow');
      return;
    }
    
    // Aggregate results
    const aggregated = aggregateResults(results);
    
    // Write output files
    await writeOutputFiles(aggregated, outputDir, append);
    
    // Print summary
    log('', '');
    log('=== Extraction Summary ===', 'green');
    log(`Secrets found: ${aggregated.secrets.length}`, 'cyan');
    log(`  HIGH: ${aggregated.secrets.filter(s => s.severity === 'HIGH').length}`, 'red');
    log(`  MEDIUM: ${aggregated.secrets.filter(s => s.severity === 'MEDIUM').length}`, 'yellow');
    log(`  LOW: ${aggregated.secrets.filter(s => s.severity === 'LOW').length}`, 'dim');
    log(`Endpoints found: ${aggregated.endpoints.length}`, 'cyan');
    log(`  Important: ${aggregated.importantEndpoints.length}`, 'green');
    log(`URLs found: ${aggregated.urls.length}`, 'cyan');
    log('', '');
    log(`Results written to: ${path.resolve(outputDir)}`, 'green');
    log(`  - endpoints.txt (all endpoints)`, 'dim');
    log(`  - important-endpoints.txt (API endpoints only)`, 'dim');
    
  } catch (error) {
    log(`Fatal error: ${error.message}`, 'red');
    if (!program.opts().quiet) {
      console.error(error);
    }
    process.exit(1);
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

module.exports = { main };
