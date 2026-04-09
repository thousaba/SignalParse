/**
 * Core log entry types.
 *
 * A LogEntry is a pure, parsed representation of a single log line.
 * It does NOT contain any threat/severity information — detection is
 * a separate layer (see threat.types.ts).
 *
 * Design principles:
 *   - LogEntry is format-agnostic: Apache, Nginx, IIS all produce the same shape
 *   - Optional fields are truly optional (some formats don't include referrer, etc.)
 *   - The raw line is always preserved for forensic replay and debugging
 */

/**
 * HTTP methods recognized by SignalParse.
 *
 * We include the standard RFC 7231 methods plus a fallback `string` type
 * for non-standard or malformed methods (attackers fuzz with garbage like
 * "FOO" or "GET\x00" — we want to capture these, not reject them).
 */
export type HttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'DELETE'
  | 'PATCH'
  | 'HEAD'
  | 'OPTIONS'
  | 'CONNECT'
  | 'TRACE'
  | (string & {}); // The `& {}` trick preserves autocomplete while allowing any string

/**
 * Source format of a log entry — useful for downstream consumers who
 * want to apply format-specific logic (e.g., "only IIS logs have this field").
 */
export type LogFormat = 'apache' | 'nginx' | 'iis' | 'unknown';

/**
 * A single parsed log entry.
 *
 * This is the output of a LogParser and the input to the Detector.
 * It is intentionally "dumb" — no severity, no threat info, just facts.
 */
export interface LogEntry {
  /** When the request occurred, in UTC. */
  readonly timestamp: Date;

  /** Client IP address (IPv4 or IPv6). */
  readonly ip: string;

  /** HTTP method. See HttpMethod for standard values. */
  readonly method: HttpMethod;

  /** Request path WITHOUT the query string. e.g. "/api/users" */
  readonly path: string;

  /**
   * Query string WITHOUT the leading "?". Undefined if no query string.
   * Kept separate from `path` because most SQLi/XSS attacks land here,
   * and signatures need to target this field specifically.
   */
  readonly queryString?: string;

  /** HTTP protocol version, e.g. "HTTP/1.1" */
  readonly protocol?: string;

  /** HTTP response status code (e.g. 200, 404, 500). */
  readonly statusCode: number;

  /** Bytes sent in the response body. Undefined if the log format doesn't report it. */
  readonly bytesSent?: number;

  /** Referrer header, if present. */
  readonly referrer?: string;

  /** User-Agent header, if present. */
  readonly userAgent?: string;

  /** Remote user from HTTP auth, if present. */
  readonly remoteUser?: string;

  /** Which log format this entry was parsed from. */
  readonly format: LogFormat;

  /**
   * The original, untouched log line.
   * Critical for forensic purposes — if we miss something during parsing,
   * analysts can still see what came in.
   */
  readonly raw: string;
}

/**
 * The result of attempting to parse a single log line.
 *
 * Parsing can fail (malformed lines, encoding issues, etc.), and we want
 * to surface those failures without throwing — throwing in a stream would
 * kill the entire pipeline on the first bad line.
 *
 * This is a discriminated union: check `.ok` to narrow the type.
 */
export type ParseResult =
  | { readonly ok: true; readonly entry: LogEntry }
  | { readonly ok: false; readonly error: string; readonly raw: string };
