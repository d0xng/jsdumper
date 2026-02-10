/**
 * Secrets and keys extraction module
 * 
 * Extracts high-signal security artifacts with context validation
 * to minimize false positives.
 */

const patterns = require('../patterns');
const { hasHighEntropy, maskValue, deduplicate } = require('../utils');

/**
 * Extract AWS Access Key IDs
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractAwsAccessKeyIds(content, fileName) {
  const findings = [];
  const matches = content.match(patterns.AWS_ACCESS_KEY_ID);
  
  if (matches) {
    for (let match of matches) {
      findings.push({
        type: 'AWS_ACCESS_KEY_ID',
        severity: 'HIGH',
        value: match,
        masked: maskValue(match, 4, 4),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract AWS Secret Access Keys
 * Requires context: must be assigned to AWS secret-related variables
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractAwsSecretKeys(content, fileName) {
  const findings = [];
  const contextMatches = content.matchAll(patterns.AWS_SECRET_ACCESS_KEY.context);
  
  for (let match of contextMatches) {
    const value = match[1];
    // Additional validation: should be base64-like and have reasonable length
    if (value && value.length >= 40 && hasHighEntropy(value, 4.0)) {
      findings.push({
        type: 'AWS_SECRET_ACCESS_KEY',
        severity: 'HIGH',
        value: value,
        masked: maskValue(value, 4, 4),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract JWTs (JSON Web Tokens)
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractJwts(content, fileName) {
  const findings = [];
  const matches = content.match(patterns.JWT);
  
  if (matches) {
    for (let match of matches) {
      // JWT should have at least header and payload (two dots minimum)
      const parts = match.split('.');
      if (parts.length >= 2) {
        findings.push({
          type: 'JWT',
          severity: 'MEDIUM',
          value: match,
          masked: maskValue(match, 10, 10),
          file: fileName
        });
      }
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract client IDs (OAuth, API, etc.)
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractOAuthClientIds(content, fileName) {
  const findings = [];
  const matches = content.matchAll(patterns.OAUTH_CLIENT_ID.pattern);
  
  for (let match of matches) {
    const value = match[1];
    if (value && value.length >= 20) {
      findings.push({
        type: 'CLIENT_ID',
        severity: 'MEDIUM',
        value: value,
        masked: maskValue(value, 6, 6),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract client secrets (OAuth, API, etc.)
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractOAuthClientSecrets(content, fileName) {
  const findings = [];
  const matches = content.matchAll(patterns.OAUTH_CLIENT_SECRET.pattern);
  
  for (let match of matches) {
    const value = match[1];
    // Client secrets should have high entropy
    if (value && value.length >= 20 && hasHighEntropy(value, 4.0)) {
      findings.push({
        type: 'CLIENT_SECRET',
        severity: 'HIGH',
        value: value,
        masked: maskValue(value, 6, 6),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract Bearer tokens
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractBearerTokens(content, fileName) {
  const findings = [];
  const matches = content.matchAll(patterns.BEARER_TOKEN);
  
  for (let match of matches) {
    const value = match[1];
    if (value && value.length >= 10) {
      findings.push({
        type: 'BEARER_TOKEN',
        severity: 'MEDIUM',
        value: value,
        masked: maskValue(value, 6, 6),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract Firebase API keys
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractFirebaseKeys(content, fileName) {
  const findings = [];
  const matches = content.match(patterns.FIREBASE_API_KEY);
  
  if (matches) {
    for (let match of matches) {
      findings.push({
        type: 'FIREBASE_API_KEY',
        severity: 'MEDIUM',
        value: match,
        masked: maskValue(match, 4, 4),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract Stripe keys
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractStripeKeys(content, fileName) {
  const findings = [];
  const matches = content.match(patterns.STRIPE_KEY);
  
  if (matches) {
    for (let match of matches) {
      const severity = match.includes('live') ? 'HIGH' : 'MEDIUM';
      findings.push({
        type: 'STRIPE_KEY',
        severity: severity,
        value: match,
        masked: maskValue(match, 8, 8),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract generic API keys
 * Only if high entropy and assigned to key-related variables
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractGenericApiKeys(content, fileName) {
  const findings = [];
  const matches = content.matchAll(patterns.GENERIC_API_KEY.pattern);
  
  for (let match of matches) {
    const value = match[1];
    // Require high entropy to avoid false positives
    if (value && value.length >= 20 && hasHighEntropy(value, 4.5)) {
      findings.push({
        type: 'GENERIC_API_KEY',
        severity: 'MEDIUM',
        value: value,
        masked: maskValue(value, 6, 6),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract hardcoded passwords
 * Only if assigned to password/auth-related variables
 * Excludes common placeholder values
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of findings
 */
function extractHardcodedPasswords(content, fileName) {
  const findings = [];
  const matches = content.matchAll(patterns.HARDCODED_PASSWORD.pattern);
  
  for (let match of matches) {
    const value = match[1];
    // Exclude common placeholder/test passwords
    if (value && 
        value.length >= 8 && 
        !patterns.HARDCODED_PASSWORD.exclude.test(value) &&
        hasHighEntropy(value, 3.0)) {
      findings.push({
        type: 'HARDCODED_PASSWORD',
        severity: 'HIGH',
        value: value,
        masked: maskValue(value, 2, 2),
        file: fileName
      });
    }
  }
  
  return deduplicate(findings, 'value');
}

/**
 * Extract all secrets from content
 * @param {string} content - File content
 * @param {string} fileName - Source file name
 * @returns {Array} Array of all findings
 */
function extractAllSecrets(content, fileName) {
  const allFindings = [
    ...extractAwsAccessKeyIds(content, fileName),
    ...extractAwsSecretKeys(content, fileName),
    ...extractJwts(content, fileName),
    ...extractOAuthClientIds(content, fileName),
    ...extractOAuthClientSecrets(content, fileName),
    ...extractBearerTokens(content, fileName),
    ...extractFirebaseKeys(content, fileName),
    ...extractStripeKeys(content, fileName),
    ...extractGenericApiKeys(content, fileName),
    ...extractHardcodedPasswords(content, fileName)
  ];
  
  return allFindings;
}

/**
 * Format secret finding for output
 * @param {Object} finding - Finding object
 * @returns {string} Formatted string
 */
function formatSecretFinding(finding) {
  // Show full value without severity
  return `${finding.type} | ${finding.value} | file: ${finding.file}`;
}

module.exports = {
  extractAllSecrets,
  formatSecretFinding
};
