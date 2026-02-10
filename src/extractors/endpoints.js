/**
 * API endpoints extraction module
 * 
 * Extracts meaningful API endpoints from JavaScript code,
 * excluding asset files and low-value paths.
 */

const patterns = require('../patterns');
const { normalizeEndpoint, deduplicate } = require('../utils');

/**
 * Extract endpoints from fetch() calls
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractFromFetch(content) {
  const endpoints = [];
  const matches = content.matchAll(patterns.API_ENDPOINT.fetch);
  
  for (let match of matches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract endpoints from axios calls
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractFromAxios(content) {
  const endpoints = [];
  const matches = content.matchAll(patterns.API_ENDPOINT.axios);
  
  for (let match of matches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract endpoints from XMLHttpRequest calls
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractFromXHR(content) {
  const endpoints = [];
  const matches = content.matchAll(patterns.API_ENDPOINT.xhr);
  
  for (let match of matches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract endpoints from route definitions
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractFromRoutes(content) {
  const endpoints = [];
  const matches = content.matchAll(patterns.API_ENDPOINT.routes);
  
  for (let match of matches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract GraphQL endpoints
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractGraphQLEndpoints(content) {
  const endpoints = [];
  const matches = content.matchAll(patterns.API_ENDPOINT.graphql);
  
  for (let match of matches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract endpoints from template literals and concatenation
 * Attempts to extract static parts of dynamic paths
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractFromTemplateLiterals(content) {
  const endpoints = [];
  
  // Pattern: `/api/` + variable or `/api/${variable}`
  // Extract the static base path
  const templatePattern = /['"`]([/](?:api|v[0-9]+|auth|admin|internal|graphql|rest)[/][A-Za-z0-9\-_/]*?)(?:\$\{|['"`])/gi;
  const matches = content.matchAll(templatePattern);
  
  for (let match of matches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  // Pattern: baseUrl + '/api/users' or baseUrl + "/api/users"
  const concatPattern = /\+?\s*['"`]([/](?:api|v[0-9]+|auth|admin|internal|graphql|rest)[/][A-Za-z0-9\-_/]*?)['"`]/gi;
  const concatMatches = content.matchAll(concatPattern);
  
  for (let match of concatMatches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract endpoints from configuration objects
 * Detects paths in config objects like signInPath:"/signin/v2/"
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractFromConfigObjects(content) {
  const endpoints = [];
  const matches = content.matchAll(patterns.API_ENDPOINT.configPaths);
  
  for (let match of matches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract endpoints from path/endpoint/route assignments
 * Detects generic path assignments like path:"/something"
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractFromPathAssignments(content) {
  const endpoints = [];
  const matches = content.matchAll(patterns.API_ENDPOINT.pathAssignments);
  
  for (let match of matches) {
    const endpoint = match[1];
    // Only include if it looks like an API endpoint (not just any path)
    if (endpoint && 
        !isAssetPath(endpoint) && 
        (endpoint.match(/\/(?:api|v[0-9]+|auth|admin|internal|signin|signup|login|logout|register|graphql|rest)/i) || 
         endpoint.length > 3)) { // Include longer paths that might be endpoints
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract common API routes
 * Detects routes like /v1, /signin, /signup, /login, etc.
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractCommonRoutes(content) {
  const endpoints = [];
  const matches = content.matchAll(patterns.API_ENDPOINT.commonRoutes);
  
  for (let match of matches) {
    const endpoint = match[1];
    if (endpoint && !isAssetPath(endpoint)) {
      endpoints.push(normalizeEndpoint(endpoint));
    }
  }
  
  return endpoints;
}

/**
 * Extract endpoints from absolute URLs
 * Extracts the path portion from URLs that look like API endpoints
 * @param {string} content - File content
 * @returns {Array} Array of endpoint strings
 */
function extractEndpointsFromUrls(content) {
  const endpoints = [];
  // Match URLs with paths that look like API endpoints
  const urlPattern = /https?:\/\/[A-Za-z0-9\-._]+(?::[0-9]+)?([/][A-Za-z0-9\-_/]+)/g;
  const matches = content.matchAll(urlPattern);
  
  for (let match of matches) {
    const path = match[1];
    if (path && path.length > 1) {
      // Only include if it looks like an API endpoint
      // Check for API indicators or paths longer than typical asset paths
      if (path.match(/\/(?:api|v[0-9]+|auth|admin|internal|signin|signup|login|logout|register|graphql|rest|tmfbsn|urm|service)/i) ||
          (path.length > 10 && !isAssetPath(path))) {
        endpoints.push(normalizeEndpoint(path));
      }
    }
  }
  
  return endpoints;
}

/**
 * Check if a path is an asset file (should be excluded)
 * @param {string} path - Path to check
 * @returns {boolean}
 */
function isAssetPath(path) {
  if (!path) return true;
  
  // Check against asset extensions
  if (patterns.ASSET_EXTENSIONS.test(path)) {
    return true;
  }
  
  // Exclude common asset directories
  const assetDirs = ['/images/', '/img/', '/assets/', '/static/', '/public/', '/fonts/', '/css/', '/js/'];
  const lowerPath = path.toLowerCase();
  
  if (assetDirs.some(dir => lowerPath.includes(dir))) {
    // But allow if it's an API path in those directories
    return !lowerPath.includes('/api/') && !lowerPath.includes('/v1/') && !lowerPath.includes('/v2/');
  }
  
  // Exclude only truly irrelevant patterns (W3C namespaces, library docs)
  // Keep business pages, content management, coverage maps, etc. as user wants to see them
  const excludePatterns = [
    /^\/199[89]\/|^\/2000\/|^\/XML\//,  // W3C years
    /^\/w3\.org/,                        // W3C domains
    /^\/www\.w3\.org/,                   // W3C www
    /^\/Math\/MathML/,                  // MathML
    /^\/xhtml$/,                         // XHTML
    /^\/xlink$/,                         // XLink
    /^\/xmlns$/,                         // XMLNS
    /^\/namespace$/,                     // Namespace
    /^\/uuidjs\//,                       // UUID library docs
    /^\/best-practices\//                // General documentation
  ];
  
  if (excludePatterns.some(pattern => pattern.test(path))) {
    return true;
  }
  
  return false;
}

/**
 * Check if endpoint is "important" (API-related, high value)
 * @param {string} endpoint - Endpoint path
 * @returns {boolean}
 */
function isImportantEndpoint(endpoint) {
  if (!endpoint) return false;
  
  const lowerEndpoint = endpoint.toLowerCase();
  
  // API indicators
  const apiIndicators = [
    '/api/',
    '/v1/',
    '/v2/',
    '/v3/',
    '/v4/',
    '/auth/',
    '/signin',
    '/signup',
    '/login',
    '/logout',
    '/register',
    '/admin/',
    '/internal/',
    '/graphql',
    '/rest/',
    '/guest/',
    '/tokens',
    '/splunk/',
    '/event',
    '/tfb/',
    '/tmfbsn',
    '/urm/',
    '/service',
    '/recaptcha/',
    '/createaccount'
  ];
  
  // Check if it contains API indicators
  if (apiIndicators.some(indicator => lowerEndpoint.includes(indicator))) {
    return true;
  }
  
  // Check if it matches common API patterns
  if (/^\/[a-z0-9\-_]+\/v[0-9]/.test(endpoint)) {
    return true;
  }
  
  return false;
}

/**
 * Extract all endpoints from content
 * @param {string} content - File content
 * @returns {Object} Object with allEndpoints and importantEndpoints arrays
 */
function extractAllEndpoints(content) {
  const allEndpoints = [
    ...extractFromFetch(content),
    ...extractFromAxios(content),
    ...extractFromXHR(content),
    ...extractFromRoutes(content),
    ...extractGraphQLEndpoints(content),
    ...extractFromTemplateLiterals(content),
    ...extractFromConfigObjects(content),
    ...extractFromPathAssignments(content),
    ...extractCommonRoutes(content),
    ...extractEndpointsFromUrls(content)
  ];
  
  // Deduplicate and filter out empty strings
  const unique = deduplicate(
    allEndpoints.filter(e => e && e.length > 0).map(e => ({ value: e })),
    'value'
  ).map(item => item.value);
  
  // Sort for consistent output
  const sorted = unique.sort();
  
  // Separate important endpoints
  const important = sorted.filter(e => isImportantEndpoint(e));
  
  return {
    all: sorted,
    important: important
  };
}

module.exports = {
  extractAllEndpoints
};
