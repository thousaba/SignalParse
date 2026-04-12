/**
 * Path traversal / Local File Inclusion (LFI) signatures.
 *
 * Detects attempts to access files outside the webroot via:
 *   - Classic ../ and ..\ sequences
 *   - URL-encoded variants (..%2f, ..%5c)
 *   - Double-encoded variants (%252e%252e%252f) for WAF bypass
 *   - Direct references to known sensitive files (/etc/passwd, etc.)
 *
 * Why these patterns matter:
 *   Path traversal can lead to credential disclosure (passwd, shadow),
 *   source code leaks, or server fingerprinting (proc filesystem).
 *   It's OWASP A01:2021 (Broken Access Control).
 */

import type { Signature } from '../types/threat.types';

/**
 * Classic ../ or ..\ traversal sequence.
 *
 * Requires AT LEAST TWO consecutive ../ groups to reduce false
 * positives — single ../ might appear in legitimate relative paths
 * (rare but possible). Two in a row is almost always malicious.
 */
const TRAVERSAL_LITERAL: Signature = {
  id: 'path-traversal-literal-01',
  name: 'Path traversal: literal ../ or ..\\ sequence',
  type: 'PATH_TRAVERSAL',
  pattern: /(?:\.\.[\/\\]){2,}/,
  fields: ['path', 'queryString'],
  confidence: 90,
  severity: 'HIGH',
  description: 'Classic directory traversal sequence (../../ or ..\\..\\)',
  mitreTechnique: 'T1083',
  owaspCategory: 'A01:2021',
};

/**
 * URL-encoded traversal sequence.
 *
 * %2f = /, %5c = \. Matches ..%2f, ..%5c, %2e%2e%2f, %2e%2e%5c
 * and combinations. Requires at least 2 occurrences.
 */
const TRAVERSAL_ENCODED: Signature = {
  id: 'path-traversal-encoded-01',
  name: 'Path traversal: URL-encoded ..%2f or ..%5c',
  type: 'PATH_TRAVERSAL',
  pattern: /(?:(?:\.\.|%2[eE]%2[eE])(?:%2[fF]|%5[cC])){2,}/i,
  fields: ['path', 'queryString'],
  confidence: 92,
  severity: 'HIGH',
  description: 'URL-encoded directory traversal sequence',
  mitreTechnique: 'T1083',
  owaspCategory: 'A01:2021',
};

/**
 * Double URL-encoded traversal — WAF bypass technique.
 *
 * Some WAFs decode the URL once and check for `..`, but if the attacker
 * sends %252e%252e%252f, the WAF sees %2e%2e%2f after one decode (no
 * traversal) and passes it through. The application server then decodes
 * AGAIN and sees ../. Bypass complete.
 *
 * %25 = %, so %252e is the URL-encoded form of %2e (which is .).
 */
const TRAVERSAL_DOUBLE_ENCODED: Signature = {
  id: 'path-traversal-double-encoded-01',
  name: 'Path traversal: double URL-encoded sequence',
  type: 'PATH_TRAVERSAL',
  pattern: /(?:%252[eE]%252[eE](?:%252[fF]|%255[cC])){2,}/i,
  fields: ['path', 'queryString'],
  confidence: 98,
  severity: 'CRITICAL',
  description: 'Double URL-encoded path traversal — WAF bypass technique',
  mitreTechnique: 'T1083',
  owaspCategory: 'A01:2021',
};

/**
 * Direct reference to known-sensitive files.
 *
 * Even without traversal sequences, a request for `/etc/passwd` or
 * `c:\windows\win.ini` is highly suspicious. These files have no
 * legitimate reason to appear in a URL parameter.
 */
const TRAVERSAL_SENSITIVE_FILES: Signature = {
  id: 'path-traversal-sensitive-files-01',
  name: 'Path traversal: reference to sensitive system file',
  type: 'PATH_TRAVERSAL',
  pattern:
    /(?:\/etc\/(?:passwd|shadow|hosts|group|fstab)|\/proc\/self\/(?:environ|cmdline|status)|[a-zA-Z]:[\\\/]windows[\\\/](?:win\.ini|system32))/i,
  fields: ['path', 'queryString'],
  confidence: 95,
  severity: 'CRITICAL',
  description: 'Direct reference to a known-sensitive system file',
  mitreTechnique: 'T1083',
  owaspCategory: 'A01:2021',
};

export const PATH_TRAVERSAL_SIGNATURES: readonly Signature[] = [
  TRAVERSAL_LITERAL,
  TRAVERSAL_ENCODED,
  TRAVERSAL_DOUBLE_ENCODED,
  TRAVERSAL_SENSITIVE_FILES,
];