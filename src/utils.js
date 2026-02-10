/**
 * Utility functions for jsdumper
 * Includes entropy calculation, normalization, and deduplication
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

/**
 * Calculate Shannon entropy of a string
 * Higher entropy indicates more randomness (likely to be a secret/key)
 * @param {string} str - String to calculate entropy for
 * @returns {number} Entropy value (0-8 typically)
 */
function calculateEntropy(str) {
  if (!str || str.length === 0) return 0;
  
  const freq = {};
  for (let char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  let entropy = 0;
  const len = str.length;
  
  for (let char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  
  return entropy;
}

/**
 * Check if a string has high entropy (likely to be a secret)
 * Threshold: 4.5 for generic keys (adjustable)
 * @param {string} str - String to check
 * @param {number} threshold - Minimum entropy threshold
 * @returns {boolean}
 */
function hasHighEntropy(str, threshold = 4.5) {
  return calculateEntropy(str) >= threshold;
}

/**
 * Mask sensitive values for output
 * Shows first 4 and last 4 characters, masks the middle
 * @param {string} value - Value to mask
 * @param {number} visibleStart - Characters to show at start
 * @param {number} visibleEnd - Characters to show at end
 * @returns {string} Masked value
 */
function maskValue(value, visibleStart = 4, visibleEnd = 4) {
  if (!value || value.length <= visibleStart + visibleEnd) {
    return value;
  }
  
  const start = value.substring(0, visibleStart);
  const end = value.substring(value.length - visibleEnd);
  const masked = '*'.repeat(Math.min(8, value.length - visibleStart - visibleEnd));
  
  return `${start}${masked}${end}`;
}

/**
 * Normalize endpoint path
 * Removes query strings, fragments, and normalizes slashes
 * @param {string} endpoint - Raw endpoint string
 * @returns {string} Normalized endpoint
 */
function normalizeEndpoint(endpoint) {
  if (!endpoint) return '';
  
  // Remove query strings and fragments
  endpoint = endpoint.split('?')[0].split('#')[0];
  
  // Ensure starts with /
  if (!endpoint.startsWith('/')) {
    endpoint = '/' + endpoint;
  }
  
  // Remove trailing slash unless it's the root
  if (endpoint.length > 1 && endpoint.endsWith('/')) {
    endpoint = endpoint.slice(0, -1);
  }
  
  return endpoint;
}

/**
 * Normalize URL
 * @param {string} url - Raw URL string
 * @returns {string} Normalized URL
 */
function normalizeUrl(url) {
  if (!url) return '';
  
  // Remove trailing slashes
  url = url.replace(/\/+$/, '');
  
  return url;
}

/**
 * Check if URL is likely an API endpoint or config
 * @param {string} url - URL to check
 * @returns {boolean}
 */
function isApiLikeUrl(url) {
  if (!url) return false;
  
  const lowerUrl = url.toLowerCase();
  
  // Contains API indicators
  const apiIndicators = [
    '/api/',
    '/v1/',
    '/v2/',
    '/v3/',
    '/graphql',
    '/rest/',
    '/auth/',
    '/oauth/',
    '/admin/',
    '/internal/',
    '/config',
    '/settings'
  ];
  
  if (apiIndicators.some(indicator => lowerUrl.includes(indicator))) {
    return true;
  }
  
  // Exclude common media/CDN patterns
  const excludePatterns = [
    /\.(jpg|jpeg|png|gif|svg|webp|ico|woff|woff2|ttf|eot|css|map)(\?|$|\/)/i,
    /cdnjs\.cloudflare\.com/i,
    /cdn\.jsdelivr\.net/i,
    /unpkg\.com/i,
    /gstatic\.com/i
  ];
  
  if (excludePatterns.some(pattern => pattern.test(url))) {
    return false;
  }
  
  // If it's a known CDN but has API-like path, include it
  return false;
}

/**
 * Deduplicate array of results
 * @param {Array} results - Array of result objects
 * @param {string} key - Key to use for deduplication (default: 'value')
 * @returns {Array} Deduplicated array
 */
function deduplicate(results, key = 'value') {
  const seen = new Set();
  const unique = [];
  
  for (let result of results) {
    const value = result[key];
    if (!seen.has(value)) {
      seen.add(value);
      unique.push(result);
    }
  }
  
  return unique;
}

/**
 * Recursively find all .js files in a directory
 * @param {string} dirPath - Directory path
 * @param {Array} fileList - Accumulator for file paths
 * @returns {Array} Array of file paths
 */
function findJsFiles(dirPath, fileList = []) {
  const files = fs.readdirSync(dirPath);
  
  for (let file of files) {
    const filePath = path.join(dirPath, file);
    const stat = fs.statSync(filePath);
    
    if (stat.isDirectory()) {
      // Skip node_modules and .git directories
      if (file !== 'node_modules' && file !== '.git' && !file.startsWith('.')) {
        findJsFiles(filePath, fileList);
      }
    } else if (file.endsWith('.js') || file.endsWith('.mjs') || file.endsWith('.cjs')) {
      fileList.push(filePath);
    }
  }
  
  return fileList;
}

/**
 * Read file content asynchronously
 * @param {string} filePath - Path to file
 * @returns {Promise<string>} File content
 */
function readFile(filePath) {
  return new Promise((resolve, reject) => {
    fs.readFile(filePath, 'utf8', (err, data) => {
      if (err) reject(err);
      else resolve(data);
    });
  });
}

/**
 * Read stdin content
 * @returns {Promise<string>} Stdin content
 */
function readStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    
    process.stdin.on('end', () => {
      resolve(data);
    });
    
    process.stdin.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Write results to file
 * @param {string} filePath - Path to output file
 * @param {Array} results - Array of result strings
 * @param {boolean} append - Whether to append or overwrite
 * @returns {Promise<void>}
 */
function writeResults(filePath, results, append = false) {
  return new Promise((resolve, reject) => {
    const content = results.join('\n') + (results.length > 0 ? '\n' : '');
    const flags = append ? 'a' : 'w';
    
    fs.writeFile(filePath, content, { encoding: 'utf8', flag: flags }, (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

/**
 * Ensure directory exists
 * @param {string} dirPath - Directory path
 */
function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

/**
 * Check if a string is a URL
 * @param {string} str - String to check
 * @returns {boolean}
 */
function isUrl(str) {
  try {
    const url = new URL(str);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Download a file from URL
 * @param {string} url - URL to download from
 * @param {string} outputPath - Local path to save the file
 * @returns {Promise<void>}
 */
function downloadFile(url, outputPath) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol === 'https:' ? https : http;
    
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
      },
      timeout: 30000 // 30 seconds timeout
    };
    
    const file = fs.createWriteStream(outputPath);
    
    const request = protocol.get(options, (response) => {
      // Handle redirects
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) {
        file.close();
        fs.unlinkSync(outputPath);
        return downloadFile(response.headers.location, outputPath)
          .then(resolve)
          .catch(reject);
      }
      
      if (response.statusCode !== 200) {
        file.close();
        fs.unlinkSync(outputPath);
        reject(new Error(`Failed to download: ${response.statusCode} ${response.statusMessage}`));
        return;
      }
      
      response.pipe(file);
      
      file.on('finish', () => {
        file.close();
        resolve();
      });
    });
    
    request.on('error', (err) => {
      file.close();
      if (fs.existsSync(outputPath)) {
        fs.unlinkSync(outputPath);
      }
      reject(err);
    });
    
    request.on('timeout', () => {
      request.destroy();
      file.close();
      if (fs.existsSync(outputPath)) {
        fs.unlinkSync(outputPath);
      }
      reject(new Error('Download timeout'));
    });
    
    request.setTimeout(30000);
  });
}

/**
 * Download multiple files from URLs
 * @param {Array<string>} urls - Array of URLs to download
 * @param {string} downloadDir - Directory to save downloaded files
 * @returns {Promise<Array<{url: string, localPath: string}>>} Array of downloaded file info
 */
async function downloadFiles(urls, downloadDir) {
  ensureDir(downloadDir);
  const downloaded = [];
  
  for (let url of urls) {
    try {
      const urlObj = new URL(url);
      const fileName = path.basename(urlObj.pathname) || 'downloaded.js';
      const localPath = path.join(downloadDir, fileName);
      
      // If file already exists with same name, add index
      let finalPath = localPath;
      let counter = 1;
      while (fs.existsSync(finalPath)) {
        const ext = path.extname(fileName);
        const base = path.basename(fileName, ext);
        finalPath = path.join(downloadDir, `${base}_${counter}${ext}`);
        counter++;
      }
      
      await downloadFile(url, finalPath);
      downloaded.push({ url, localPath: finalPath });
    } catch (error) {
      console.error(`Failed to download ${url}: ${error.message}`);
    }
  }
  
  return downloaded;
}

module.exports = {
  calculateEntropy,
  hasHighEntropy,
  maskValue,
  normalizeEndpoint,
  normalizeUrl,
  isApiLikeUrl,
  deduplicate,
  findJsFiles,
  readFile,
  readStdin,
  writeResults,
  ensureDir,
  isUrl,
  downloadFile,
  downloadFiles
};
