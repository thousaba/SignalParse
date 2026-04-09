/**
 * LogParser interface — every format parser (Apache, Nginx, IIS, etc.)
 * implements this. This is the strategy pattern in action: the streamer
 * doesn't care which format it's processing, it just calls parser.parse(line).
 *
 * Adding a new log format = creating a new file that implements this interface.
 * No changes needed in the streamer, detector, or anywhere else.
 */

import type { LogFormat, ParseResult } from '../types/log.types';

/**
 * The contract every format parser must fulfill.
 *
 * Implementations should be STATELESS: the same input line should always
 * produce the same output. No shared state between calls. This makes
 * parsers trivially parallelizable in the future (worker threads, etc.).
 */
export interface LogParser {
  /**
   * The format this parser handles. Used by the registry for lookup.
   */
  readonly format: LogFormat;

  /**
   * Human-readable name, e.g. "Apache Combined Log Format".
   * Shown in CLI help and error messages.
   */
  readonly name: string;

  /**
   * Parse a single log line.
   *
   * MUST NOT throw on malformed input. Return { ok: false, error, raw }
   * instead. Throwing in a stream kills the pipeline on the first bad line.
   *
   * @param line  The raw log line, WITHOUT the trailing newline.
   * @returns     A ParseResult (success with LogEntry, or failure with error).
   */
  parse(line: string): ParseResult;
}
