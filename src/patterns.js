/**
 * Advanced regex patterns for security artifact extraction
 * 
 * These patterns are context-aware and designed to minimize false positives
 * by requiring assignment context or high entropy values.
 */

module.exports = {
  // AWS Access Key ID: AKIA followed by 16 alphanumeric characters
  AWS_ACCESS_KEY_ID: /AKIA[0-9A-Z]{16}/g,
  
  // AWS Secret Access Key: Base64-like string, typically 40 chars
  // Context: must appear after assignment to AWS_SECRET, secret, etc.
  AWS_SECRET_ACCESS_KEY: {
    pattern: /[A-Za-z0-9/+=]{40,}/g,
    context: /(?:aws[_\s-]?secret|secret[_\s-]?access[_\s-]?key|aws[_\s-]?secret[_\s-]?key)\s*[:=]\s*['"`]([A-Za-z0-9/+=]{40,})['"`]/gi
  },
  
  // JWT: Three parts separated by dots (header.payload.signature)
  JWT: /eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_=]*/g,
  
  // OAuth client_id and client_secret with assignment context
  OAUTH_CLIENT_ID: {
    pattern: /client[_\s-]?id\s*[:=]\s*['"`]([A-Za-z0-9\-_]{20,})['"`]/gi
  },
  OAUTH_CLIENT_SECRET: {
    pattern: /client[_\s-]?secret\s*[:=]\s*['"`]([A-Za-z0-9\-_]{20,})['"`]/gi
  },
  
  // Bearer tokens in Authorization headers
  BEARER_TOKEN: /Bearer\s+([A-Za-z0-9\-._~+/]+=*)/gi,
  
  // Firebase API keys: AIza followed by 35 alphanumeric/dash/underscore
  FIREBASE_API_KEY: /AIza[0-9A-Za-z_-]{35}/g,
  
  // Stripe keys: sk_live_, sk_test_, pk_live_, pk_test_ prefixes
  STRIPE_KEY: /(sk|pk)_(live|test)_[A-Za-z0-9]{24,}/g,
  
  // Generic API keys: high entropy strings assigned to key-related variables
  // Context: must be assigned to variables containing "key", "api", "token", "auth"
  GENERIC_API_KEY: {
    pattern: /(?:api[_\s-]?key|access[_\s-]?token|auth[_\s-]?token|secret[_\s-]?key)\s*[:=]\s*['"`]([A-Za-z0-9\-_+/=]{20,})['"`]/gi
  },
  
  // Hardcoded passwords: only if assigned to password/auth-related variables
  HARDCODED_PASSWORD: {
    pattern: /(?:password|pwd|pass|auth[_\s-]?password)\s*[:=]\s*['"`]([^\s'"`]{8,})['"`]/gi,
    exclude: /(?:example|test|demo|sample|placeholder|changeme|password123)/i
  },
  
  // API endpoints: /api/*, /v1, /v2, /v3, /auth/*, /admin/*, etc.
  // Context: inside fetch(), axios calls, or route definitions
  API_ENDPOINT: {
    // fetch("/api/users") or fetch(`/api/users`)
    fetch: /fetch\s*\(\s*['"`]([/](?:api|v[0-9]+|auth|admin|internal|graphql|rest)[/]?[A-Za-z0-9\-_/]*?)['"`]/gi,
    // axios.get("/api/users") or axios.post("/api/users")
    axios: /axios\.(?:get|post|put|delete|patch|request)\s*\(\s*['"`]([/](?:api|v[0-9]+|auth|admin|internal|graphql|rest)[/]?[A-Za-z0-9\-_/]*?)['"`]/gi,
    // XMLHttpRequest.open("GET", "/api/users")
    xhr: /\.open\s*\(\s*['"`][A-Z]+\s*['"`]\s*,\s*['"`]([/](?:api|v[0-9]+|auth|admin|internal|graphql|rest)[/]?[A-Za-z0-9\-_/]*?)['"`]/gi,
    // Route definitions: app.get("/api/users")
    routes: /\.(?:get|post|put|delete|patch|all)\s*\(\s*['"`]([/](?:api|v[0-9]+|auth|admin|internal|graphql|rest)[/]?[A-Za-z0-9\-_/]*?)['"`]/gi,
    // GraphQL endpoints
    graphql: /(?:graphql|gql)\s*[:=]\s*['"`]([/]?[A-Za-z0-9\-_/]*graphql[A-Za-z0-9\-_/]*)['"`]/gi,
    // Configuration objects: signInPath:"/signin/v2/", apiPath:"/api/v1"
    configPaths: /(?:signIn|signUp|signOut|api|auth|endpoint|route|path|basePath|baseUrl|baseURL)[Pp]ath?\s*[:=]\s*['"`]([/][A-Za-z0-9\-_/]+)['"`]/gi,
    // Generic path assignments: path:"/something", endpoint:"/something"
    pathAssignments: /(?:path|endpoint|route|url|uri)\s*[:=]\s*['"`]([/][A-Za-z0-9\-_/]+)['"`]/gi,
    // Routes starting with /v[0-9], /signin, /signup, /login, /logout, /register, etc.
    commonRoutes: /['"`]([/](?:v[0-9]+|signin|signup|sign-out|login|logout|register|auth|api|admin|internal|graphql|rest)[/]?[A-Za-z0-9\-_/]*)['"`]/gi
  },
  
  // Absolute URLs: http:// or https://
  ABSOLUTE_URL: {
    // Full URL pattern
    full: /https?:\/\/[A-Za-z0-9\-._~:/?#[\]@!$&'()*+,;=%]+/g,
    // Exclude common CDN/media URLs unless they look like API endpoints
    exclude: /\.(?:jpg|jpeg|png|gif|svg|webp|ico|woff|woff2|ttf|eot|css|map|js)(?:\?|$|\/)/i
  },
  
  // Common CDN patterns to filter (unless API-like)
  CDN_PATTERNS: [
    /cdnjs\.cloudflare\.com/i,
    /cdn\.jsdelivr\.net/i,
    /unpkg\.com/i,
    /googleapis\.com\/.*\.(?:js|css)/i,
    /gstatic\.com/i
  ],
  
  // Asset file extensions to exclude
  ASSET_EXTENSIONS: /\.(?:jpg|jpeg|png|gif|svg|webp|ico|woff|woff2|ttf|eot|css|map)(?:\?|$|\/)/i
};
