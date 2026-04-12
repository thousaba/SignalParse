/**
 * Cross-Site Scripting (XSS) signatures.
 *
 * Detects reflected XSS attempts in URL query strings and paths.
 * Stored XSS in POST bodies is out of scope (we don't parse bodies).
 *
 * Design principles:
 *   1. CONTEXT-AWARE: only target queryString and path. User-Agent
 *      containing "<script>" is suspicious but NOT XSS — XSS requires
 *      the payload to land in a rendered context.
 *
 *   2. ENCODING-AWARE: literal AND URL-encoded variants in the same
 *      pattern. Attackers mix encodings to evade WAFs.
 *
 *   3. REQUIRE STRUCTURE: don't match the bare word "script" — require
 *      the surrounding angle brackets (literal or encoded). Otherwise
 *      every legitimate mention of "script" triggers an alert.
 */

import type { Signature } from '../types/threat.types';

/**
 * Reusable: an "open angle bracket" character class — literal `<` or
 * URL-encoded `%3C`.
 */
const LT = '(?:<|%3[cC])';

/**
 * Reusable: a "close angle bracket" — literal `>` or URL-encoded `%3E`.
 */
const GT = '(?:>|%3[eE])';

/**
 * Reusable: optional whitespace, including URL-encoded forms.
 */
const WS = '(?:\\s|%20|%09|%0[aA]|\\+)';

/**
 * Reusable: a colon — literal `:` or URL-encoded `%3A`.
 */
const COLON = '(?::|%3[aA])';

/**
 * <script> tag injection.
 *
 * Matches:
 *   <script>alert(1)</script>      (literal)
 *   <ScRiPt>...</sCrIpT>           (case-insensitive via /i)
 *   %3Cscript%3E                   (URL-encoded brackets)
 *   <script src=//evil.com>        (with attributes)
 *
 * Does NOT match:
 *   "I love the new script for the movie"   (no angle brackets)
 *   "javascript-tutorials"                  (no angle brackets)
 */
const XSS_SCRIPT_TAG: Signature = {
  id: 'xss-script-tag-01',
  name: 'XSS: <script> tag injection',
  type: 'XSS',
  pattern: new RegExp(`${LT}${WS}*script(?:${WS}+(?:(?!${GT}).)*)?${GT}`, 'i'),
  fields: ['queryString', 'path'],
  confidence: 95,
  severity: 'CRITICAL',
  description: 'HTML script tag injection attempt — classic XSS payload',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

/**
 * HTML event handler injection.
 *
 * Matches things like:
 *   onerror=alert(1)
 *   onload=...
 *   onclick=...
 *   onmouseover=...
 *
 * The `\b` word boundary ensures we match `onerror=` but not
 * `nononerror=` or similar.
 *
 * We require an `=` sign after the handler name. Bare "onload" in a
 * URL is meaningless without the `=`, so requiring it cuts false
 * positives sharply.
 */
const XSS_EVENT_HANDLER: Signature = {
  id: 'xss-event-handler-01',
  name: 'XSS: HTML event handler injection',
  type: 'XSS',
  pattern:
    /\bon(?:error|load|click|mouseover|mouseout|focus|blur|submit|change|keydown|keyup|keypress)\s*=/i,
  fields: ['queryString', 'path'],
  confidence: 90,
  severity: 'HIGH',
  description: 'HTML event handler attribute (onerror, onload, etc.) used for XSS',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

/**
 * javascript: protocol injection.
 *
 * Used in href, src, or any URL-accepting context:
 *   <a href="javascript:alert(1)">
 *   <iframe src="javascript:alert(1)">
 *
 * Matches both literal and URL-encoded colon. We require it to be
 * preceded by `=` or `:` or `(` to reduce false positives — bare
 * "javascript" in a URL (like /tag/javascript) doesn't trigger.
 */
const XSS_JAVASCRIPT_PROTOCOL: Signature = {
  id: 'xss-javascript-protocol-01',
  name: 'XSS: javascript: protocol',
  type: 'XSS',
  pattern: new RegExp(`(?:=|${COLON}|\\()${WS}*javascript${COLON}`, 'i'),
  fields: ['queryString', 'path'],
  confidence: 85,
  severity: 'HIGH',
  description: 'javascript: protocol used in a URL parameter — XSS or open redirect',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

/**
 * <iframe> injection.
 *
 * Iframes loaded from attacker-controlled domains can host malicious
 * content (phishing pages, drive-by downloads, etc.).
 */
const XSS_IFRAME: Signature = {
  id: 'xss-iframe-01',
  name: 'XSS: <iframe> injection',
  type: 'XSS',
  pattern: new RegExp(`${LT}${WS}*iframe\\b`, 'i'),
  fields: ['queryString', 'path'],
  confidence: 88,
  severity: 'HIGH',
  description: 'HTML iframe tag injection — used for clickjacking or phishing',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

/**
 * <object>, <embed>, <svg> tag injection.
 *
 * Less common but valid XSS vectors. Modern browsers block much of
 * this but it still appears in scanner output and old browser exploits.
 */
const XSS_DANGEROUS_TAGS: Signature = {
  id: 'xss-dangerous-tags-01',
  name: 'XSS: dangerous HTML tags',
  type: 'XSS',
  pattern: new RegExp(`${LT}${WS}*(?:object|embed|svg|applet|meta)\\b`, 'i'),
  fields: ['queryString', 'path'],
  confidence: 80,
  severity: 'MEDIUM',
  description: 'Injection of HTML tags often used for XSS (object, embed, svg, etc.)',
  mitreTechnique: 'T1059',
  owaspCategory: 'A03:2021',
};

export const XSS_SIGNATURES: readonly Signature[] = [
  XSS_SCRIPT_TAG,
  XSS_EVENT_HANDLER,
  XSS_JAVASCRIPT_PROTOCOL,
  XSS_IFRAME,
  XSS_DANGEROUS_TAGS,
];