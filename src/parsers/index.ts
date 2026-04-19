/**
 * Parser registry — maps format names to their parser implementations.
 *
 * This is the single entry point for "give me a parser for format X".
 * When we add Nginx, IIS, or custom parsers, they get registered here.
 */

import type { LogFormat } from '../types/log.types';
import type { LogParser } from './types';
import { apacheParser } from './apache';
import { nginxParser } from './nginx';
// import { iisParser } from './iis';  // coming soon


/**
 * Registry of all available parsers, keyed by format name.
 *
 * `Partial<Record<...>>` because not every LogFormat has a parser yet
 * (we haven't written Nginx or IIS). This makes the registry honest
 * about which formats are actually supported.
 */
const PARSERS: Partial<Record<LogFormat, LogParser>> = {
  apache: apacheParser,
  nginx: nginxParser,  
  // iis: iisParser,      // coming soon
};

/**
 * Look up a parser by format name.
 *
 * Returns undefined if the format is not supported — caller should
 * handle this gracefully (e.g., print available formats and exit).
 */
export function getParser(format: LogFormat): LogParser | undefined {
  return PARSERS[format];
}

/**
 * List all currently supported formats.
 * Useful for CLI --help output and error messages.
 */
export function getSupportedFormats(): LogFormat[] {
  return Object.keys(PARSERS) as LogFormat[];
}
