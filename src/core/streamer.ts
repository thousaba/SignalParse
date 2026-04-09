/**
 * File streamer — reads log files line-by-line using Node's readline
 * over createReadStream, keeping memory usage constant regardless of
 * file size.
 *
 * Why streaming matters:
 *   fs.readFileSync('/var/log/nginx/access.log')
 *     → loads the ENTIRE file into RAM. Dies on 2GB+ files.
 *
 *   createReadStream(path) + readline
 *     → reads in chunks (default 64KB), emits lines as they come in.
 *       Memory usage stays flat regardless of file size.
 *
 * Design notes:
 *   - Returns an async iterable (AsyncIterable<ParseResult>).
 *     This lets callers use `for await (const result of stream)` syntax,
 *     which is clean, cancellable, and backpressure-aware.
 *   - Errors during parsing do NOT stop the stream. Each line is
 *     independent. A malformed line yields { ok: false, ... } and
 *     the stream keeps going.
 *   - File-level errors (not found, permission denied) DO throw,
 *     because they're not recoverable mid-stream.
 */

import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import type { ParseResult } from '../types/log.types';
import type { LogParser } from '../parsers/types';

/**
 * Options for the streamer.
 */
export interface StreamOptions {
  /** Absolute or relative path to the log file. */
  readonly filePath: string;

  /** The parser to run against each line. */
  readonly parser: LogParser;

  /**
   * Character encoding of the log file. Defaults to 'utf8'.
   * Apache/Nginx logs are almost always UTF-8, but some Windows
   * environments produce logs in other encodings.
   */
  readonly encoding?: BufferEncoding;
}

/**
 * Stream a log file, yielding one ParseResult per line.
 *
 * Usage:
 *   for await (const result of streamLogFile({ filePath, parser })) {
 *     if (result.ok) { ... }
 *     else { console.error(result.error); }
 *   }
 *
 * Memory usage: O(max line length), NOT O(file size).
 * On a typical web access log, this means < 10MB RAM regardless of
 * whether the file is 1MB or 100GB.
 */
export async function* streamLogFile(
  options: StreamOptions,
): AsyncGenerator<ParseResult, void, void> {
  const { filePath, parser, encoding = 'utf8' } = options;

  // createReadStream opens the file lazily. If the file doesn't exist,
  // the error fires as a stream event, not immediately — so we wrap it.
  const fileStream = createReadStream(filePath, { encoding });

  // readline on top of the stream emits one 'line' event per logical line.
  // crlfDelay: Infinity handles Windows-style CRLF line endings correctly
  // (without this, you get phantom \r characters at end of lines).
  const lineReader = createInterface({
    input: fileStream,
    crlfDelay: Infinity,
  });

  try {
    for await (const line of lineReader) {
      yield parser.parse(line);
    }
  } finally {
    // Ensure the file descriptor is closed even if the consumer
    // breaks out of the loop early (e.g., `break` or `throw`).
    lineReader.close();
    fileStream.destroy();
  }
}

/**
 * Aggregate counters for a completed stream run.
 *
 * Returned by streamAndCount() for consumers that want a summary
 * rather than per-line processing.
 */
export interface StreamStats {
  /** Total lines read from the file. */
  readonly totalLines: number;

  /** Lines that parsed successfully. */
  readonly parsed: number;

  /** Lines that failed to parse. */
  readonly failed: number;

  /** How long the stream took, in milliseconds. */
  readonly elapsedMs: number;

  /** Lines parsed per second (rounded). */
  readonly linesPerSecond: number;
}

/**
 * Convenience wrapper: runs a stream to completion and returns stats.
 *
 * Useful for benchmarks, smoke tests, and the CLI's summary line.
 * NOT useful if you actually want to process each result — for that,
 * use streamLogFile() directly with for-await-of.
 */
export async function streamAndCount(options: StreamOptions): Promise<StreamStats> {
  const start = Date.now();
  let totalLines = 0;
  let parsed = 0;
  let failed = 0;

  for await (const result of streamLogFile(options)) {
    totalLines++;
    if (result.ok) {
      parsed++;
    } else {
      failed++;
    }
  }

  const elapsedMs = Date.now() - start;
  const linesPerSecond = elapsedMs > 0 ? Math.round((totalLines / elapsedMs) * 1000) : 0;

  return { totalLines, parsed, failed, elapsedMs, linesPerSecond };
}