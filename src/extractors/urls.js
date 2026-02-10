/**
 * Absolute URLs extraction module
 * 
 * Extracts absolute URLs (http://, https://) from JavaScript code,
 * filtering out common CDN/media URLs unless they appear to be API endpoints.
 */

const patterns = require('../patterns');
const { normalizeUrl, isApiLikeUrl, deduplicate } = require('../utils');

/**
 * Extract all absolute URLs from content
 * @param {string} content - File content
 * @returns {Array} Array of unique URL strings
 */
function extractAllUrls(content) {
  const urls = [];
  const matches = content.matchAll(patterns.ABSOLUTE_URL.full);
  
  for (let match of matches) {
    let url = match[0];
    
    // Remove trailing punctuation that might be part of code syntax
    url = url.replace(/[.,;:!?)\]}>]+$/, '');
    
    // Skip if it matches excluded patterns (unless API-like)
    if (patterns.ABSOLUTE_URL.exclude.test(url)) {
      continue;
    }
    
    // Check if it's a common CDN
    const isCdn = patterns.CDN_PATTERNS.some(pattern => pattern.test(url));
    
    if (isCdn) {
      // Only include if it looks like an API or config endpoint
      if (isApiLikeUrl(url)) {
        urls.push(normalizeUrl(url));
      }
    } else {
      // Include all non-CDN URLs
      urls.push(normalizeUrl(url));
    }
  }
  
  // Deduplicate
  const unique = deduplicate(
    urls.filter(u => u && u.length > 0).map(u => ({ value: u })),
    'value'
  ).map(item => item.value);
  
  // Sort for consistent output
  return unique.sort();
}

module.exports = {
  extractAllUrls
};
