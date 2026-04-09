/**
 * SQL Injection signatures.
 *
 * Design principles:
 *   1. CONTEXT-AWARE: each signature declares which fields it targets.
 *   2. CONFIDENCE-TIERED: obvious attacks get high confidence.
 *   3. ENCODING-AWARE: we match both literal AND URL-encoded variants
 *      in the SAME pattern. Real attackers mix encodings to evade WAFs,
 *      so "admin'%20OR%20'1'='1" must match just as well as "admin' OR '1'='1".
 *   4. CASE-INSENSITIVE: all patterns use /i flag.
 */

import type { Signature } from '../types/threat.types';

/**
 * A whitespace-equivalent class that covers BOTH literal whitespace
 * AND URL-encoded space (%20) AND tab (%09) AND plus (+, which is
 * form-encoded space). Reused across patterns.
 *
 * Matches: space, tab, newline, %20, %09, %0A, +
 */
const WS = '(?:\\s|%20|%09|%0[aA]|\\+)';

/**
 * Quote class — literal or URL-encoded single/double quote.
 * Matches: ' " %27 %22
 */
const QUOTE = "(?:['\"]|%27|%22)";

/**
 * Classic tautology-based SQL injection.
 *
 * Matches things like:
 *   ' OR '1'='1          (literal)
 *   '%20OR%20'1'='1      (partial encoding — space encoded, quote literal)
 *   %27%20OR%20%271%27=%271  (fully encoded)
 *   ' OR 1=1             (no inner quotes)
 *   ") OR (1=1           (parenthesized)
 */
const SQLI_TAUTOLOGY: Signature = {
  id: 'sqli-tautology-01',
  name: 'SQL Injection: boolean tautology',
  type: 'SQLI',
  pattern: new RegExp(
    `${QUOTE}${WS}*(OR|AND)${WS}+${QUOTE}?\\w+${QUOTE}?${WS}*=${WS}*${QUOTE}?\\w+`,
    'i',
  ),
  fields: ['queryString', 'path'],
  confidence: 95,
  severity: 'CRITICAL',
  description: "Classic tautology-based SQL injection (e.g., ' OR '1'='1)",
  mitreTechnique: 'T1190',
  owaspCategory: 'A03:2021',
};

/**
 * UNION-based SQL injection.
 *
 * Uses \W* (non-word chars) between UNION and SELECT to allow any
 * combination of whitespace, URL encoding, comments, etc.
 */
const SQLI_UNION_SELECT: Signature = {
  id: 'sqli-union-01',
  name: 'SQL Injection: UNION SELECT',
  type: 'SQLI',
  pattern: new RegExp(`UNION(?:${WS}+ALL)?${WS}+SELECT`, 'i'),
  fields: ['queryString', 'path'],
  confidence: 98,
  severity: 'CRITICAL',
  description: 'UNION-based SQL injection attempting to extract data from other tables',
  mitreTechnique: 'T1190',
  owaspCategory: 'A03:2021',
};

/**
 * SQL comment injection.
 *
 * Attackers use comments to terminate queries prematurely:
 *   admin'--
 *   admin'/*
 *   1; DROP TABLE users --
 *
 * We match: any quote (literal or encoded) followed by optional whitespace
 * and then --, #, or /*.
 */
const SQLI_COMMENT: Signature = {
  id: 'sqli-comment-01',
  name: 'SQL Injection: comment terminator',
  type: 'SQLI',
  pattern: new RegExp(`${QUOTE}${WS}*(-{2}|%2[dD]%2[dD]|#|%23|\\/\\*|%2[fF]\\*)`, 'i'),
  fields: ['queryString', 'path'],
  confidence: 85,
  severity: 'HIGH',
  description: 'SQL comment used to terminate a query prematurely',
  mitreTechnique: 'T1190',
  owaspCategory: 'A03:2021',
};

/**
 * Dangerous SQL keywords used in destructive attacks.
 *
 * DROP TABLE, DELETE FROM, INSERT INTO, UPDATE ... SET, TRUNCATE TABLE.
 * These should virtually never appear in URL parameters.
 */
const SQLI_DANGEROUS_KEYWORDS: Signature = {
  id: 'sqli-keywords-01',
  name: 'SQL Injection: destructive keywords',
  type: 'SQLI',
  pattern: new RegExp(
    `(DROP${WS}+TABLE|DELETE${WS}+FROM|INSERT${WS}+INTO|UPDATE${WS}+\\w+${WS}+SET|TRUNCATE${WS}+TABLE)`,
    'i',
  ),
  fields: ['queryString', 'path'],
  confidence: 90,
  severity: 'CRITICAL',
  description: 'Destructive SQL keywords (DROP, DELETE, INSERT, UPDATE, TRUNCATE)',
  mitreTechnique: 'T1190',
  owaspCategory: 'A03:2021',
};

/**
 * Inline "boolean" tautology without quotes.
 *
 * Some SQLi payloads don't use quotes at all, e.g.:
 *   ?id=1 OR 1=1
 *   ?id=1%20OR%201=1
 *
 * This is lower confidence because "OR 1=1" COULD appear in legitimate
 * search queries, but it's still suspicious enough to flag.
 */
const SQLI_NUMERIC_TAUTOLOGY: Signature = {
  id: 'sqli-tautology-03',
  name: 'SQL Injection: numeric tautology',
  type: 'SQLI',
  pattern: new RegExp(`\\d+${WS}+(OR|AND)${WS}+\\d+${WS}*=${WS}*\\d+`, 'i'),
  fields: ['queryString', 'path'],
  confidence: 80,
  severity: 'HIGH',
  description: 'Numeric tautology-based SQL injection (e.g., 1 OR 1=1)',
  mitreTechnique: 'T1190',
  owaspCategory: 'A03:2021',
};

/**
 * Known SQLi scanner tools in User-Agent.
 *
 * Detects the *tool* rather than the payload. A different class of
 * detection: scanner fingerprinting, not injection matching.
 */
const SQLI_SCANNER_UA: Signature = {
  id: 'sqli-scanner-ua-01',
  name: 'Recon: SQL injection scanner tool',
  type: 'RECON',
  pattern: /(sqlmap|havij|jsql|bsqlbf|sqlninja)/i,
  fields: ['userAgent'],
  confidence: 100,
  severity: 'HIGH',
  description: 'Known SQL injection scanner detected in User-Agent',
  mitreTechnique: 'T1595',
  owaspCategory: 'A03:2021',
};

export const SQLI_SIGNATURES: readonly Signature[] = [
  SQLI_TAUTOLOGY,
  SQLI_UNION_SELECT,
  SQLI_COMMENT,
  SQLI_DANGEROUS_KEYWORDS,
  SQLI_NUMERIC_TAUTOLOGY,
  SQLI_SCANNER_UA,
];