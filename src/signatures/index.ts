/**
 * Signature registry — collects all signatures from the individual
 * files and exposes them as a single array for the detector.
 *
 * To add a new signature category (e.g., XSS, path traversal):
 *   1. Create the file (signatures/xss.ts)
 *   2. Export an array (XSS_SIGNATURES)
 *   3. Import and spread it here
 *
 * That's it. No engine changes. No detector changes. Pure data.
 */

import type { Signature } from '../types/threat.types';
import { SQLI_SIGNATURES } from './sqli';
import { XSS_SIGNATURES } from './xss';
import { PATH_TRAVERSAL_SIGNATURES } from './path-traversal';
import { COMMAND_INJECTION_SIGNATURES } from './command-injection';

/**
 * The complete set of signatures, flattened into one array.
 *
 * The detector will iterate this array for every LogEntry.
 * For performance, we sort by confidence DESC so high-confidence
 * matches are reported first (useful when callers take only the top N).
 */
export const ALL_SIGNATURES: readonly Signature[] = [
  ...SQLI_SIGNATURES,
  ...XSS_SIGNATURES,
  ...PATH_TRAVERSAL_SIGNATURES,
  ...COMMAND_INJECTION_SIGNATURES,
].slice().sort((a, b) => b.confidence - a.confidence);

/**
 * Count of registered signatures. Useful for CLI banner and tests.
 */
export const SIGNATURE_COUNT = ALL_SIGNATURES.length;
