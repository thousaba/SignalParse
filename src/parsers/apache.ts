/**
 * Apache Combined Log Format parser.
 *
 * Format:
 *   %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
 *
 * Example line:
 *   127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08 [en] (Win98; I ;Nav)"
 *
 * Fields, in order:
 *   1. %h              Remote host (IP)
 *   2. %l              Remote logname (almost always "-")
 *   3. %u              Remote user (from HTTP auth, or "-")
 *   4. %t              Time in [DD/Mon/YYYY:HH:MM:SS +ZZZZ] format
 *   5. "%r"            Request line ("METHOD PATH PROTOCOL")
 *   6. %>s             Final HTTP status code
 *   7. %b              Response size in bytes (or "-" if 0)
 *   8. "%{Referer}i"   Referer header
 *   9. "%{User-Agent}i" User-Agent header
 */

import type { LogEntry, ParseResult } from '../types/log.types';
import type { LogParser } from './types';

/**
 * The master regex for Apache Combined Log Format.
 *
 * Design notes:
 *   - We use NAMED CAPTURE GROUPS (?<name>...) for readability and safety.
 *     This avoids bugs where someone renumbers a group and breaks everything.
 *   - The request line is captured as a whole, then split separately.
 *     Why? Because malformed requests (fuzzing, attacks) may have weird
 *     content inside the quotes, and trying to parse it inline with one
 *     giant regex becomes a nightmare.
 *   - We are DELIBERATELY permissive: we'd rather parse a weird line
 *     partially than reject it entirely. Forensic data > clean data.
 */
const APACHE_COMBINED_REGEX =
  /^(?<ip>\S+) (?<ident>\S+) (?<user>\S+) \[(?<time>[^\]]+)\] "(?<request>[^"]*)" (?<status>\d{3}) (?<size>\d+|-) "(?<referrer>[^"]*)" "(?<userAgent>[^"]*)"/;

/**
 * Apache time format: "10/Oct/2000:13:55:36 -0700"
 *
 * JavaScript's Date constructor can't parse this natively, so we parse
 * it manually. The format is always the same: DD/MMM/YYYY:HH:MM:SS ±HHMM.
 */
const APACHE_TIME_REGEX =
  /^(?<day>\d{2})\/(?<mon>\w{3})\/(?<year>\d{4}):(?<hour>\d{2}):(?<min>\d{2}):(?<sec>\d{2}) (?<tzSign>[+-])(?<tzH>\d{2})(?<tzM>\d{2})$/;

const MONTH_MAP: Readonly<Record<string, number>> = {
  Jan: 0,
  Feb: 1,
  Mar: 2,
  Apr: 3,
  May: 4,
  Jun: 5,
  Jul: 6,
  Aug: 7,
  Sep: 8,
  Oct: 9,
  Nov: 10,
  Dec: 11,
};

/**
 * Parse an Apache-format timestamp into a Date (UTC).
 *
 * Returns null on any failure — caller handles the error.
 */
function parseApacheTime(timeStr: string): Date | null {
  const match = APACHE_TIME_REGEX.exec(timeStr);
  if (!match?.groups) return null;

  const { day, mon, year, hour, min, sec, tzSign, tzH, tzM } = match.groups;

  // noUncheckedIndexedAccess means all destructured values are `string | undefined`.
  // Guard against missing groups (shouldn't happen if regex matched, but TS doesn't know).
  if (!day || !mon || !year || !hour || !min || !sec || !tzSign || !tzH || !tzM) {
    return null;
  }

  const monthIdx = MONTH_MAP[mon];
  if (monthIdx === undefined) return null;

  // Build a UTC date, then adjust for the timezone offset from the log.
  const utcMs = Date.UTC(
    parseInt(year, 10),
    monthIdx,
    parseInt(day, 10),
    parseInt(hour, 10),
    parseInt(min, 10),
    parseInt(sec, 10),
  );

  // Offset from UTC in minutes. If the log says "+0300", the actual UTC
  // time is 3 hours EARLIER than the local time shown.
  const offsetMin = (parseInt(tzH, 10) * 60 + parseInt(tzM, 10)) * (tzSign === '+' ? 1 : -1);
  const adjustedMs = utcMs - offsetMin * 60 * 1000;

  return new Date(adjustedMs);
}

/**
 * Split the request line "METHOD PATH PROTOCOL" into its components.
 *
 * Returns null if the line is too malformed to extract anything useful.
 * Separates PATH from QUERY STRING (everything after the first '?').
 */
function parseRequestLine(request: string): {
  method: string;
  path: string;
  queryString: string | undefined;
  protocol: string | undefined;
} | null {
  // A typical request: "GET /foo?bar=1 HTTP/1.1"
  // But attackers may send garbage. Be lenient.
  const parts = request.split(' ');
  if (parts.length < 2) return null;

  const method = parts[0];
  const rawPath = parts[1];
  const protocol = parts.length >= 3 ? parts.slice(2).join(' ') : undefined;

  if (!method || !rawPath) return null;

  // Split path and query string at the first '?'.
  const qIdx = rawPath.indexOf('?');
  const path = qIdx === -1 ? rawPath : rawPath.substring(0, qIdx);
  const queryString = qIdx === -1 ? undefined : rawPath.substring(qIdx + 1);

  return { method, path, queryString, protocol };
}

/**
 * The Apache Combined Log Format parser instance.
 *
 * Exported as an object (not a class) because it's stateless and singleton —
 * there's no reason to `new ApacheParser()` a hundred times.
 */
export const apacheParser: LogParser = {
  format: 'apache',
  name: 'Apache Combined Log Format',

  parse(line: string): ParseResult {
    // Empty or whitespace-only lines are not parse errors, they're just skipped.
    // But LogParser contract doesn't have a "skip" variant, so we report it
    // as an error and let the caller decide.
    if (!line.trim()) {
      return { ok: false, error: 'empty line', raw: line };
    }

    const match = APACHE_COMBINED_REGEX.exec(line);
    if (!match?.groups) {
      return { ok: false, error: 'line does not match Apache Combined format', raw: line };
    }

    const { ip, user, time, request, status, size, referrer, userAgent } = match.groups;

    // TypeScript strict mode: all destructured groups are `string | undefined`.
    // Check each required field even though the regex would have failed without them.
    if (!ip || !time || request === undefined || !status) {
      return { ok: false, error: 'missing required fields after regex match', raw: line };
    }

    const timestamp = parseApacheTime(time);
    if (!timestamp) {
      return { ok: false, error: `invalid timestamp: ${time}`, raw: line };
    }

    const reqParts = parseRequestLine(request);
    if (!reqParts) {
      return { ok: false, error: `malformed request line: ${request}`, raw: line };
    }

    const statusCode = parseInt(status, 10);
    if (Number.isNaN(statusCode)) {
      return { ok: false, error: `invalid status code: ${status}`, raw: line };
    }

    // Size is "-" when the server sent zero bytes, otherwise a number.
    const bytesSent = size === '-' || size === undefined ? undefined : parseInt(size, 10);

    const entry: LogEntry = {
      timestamp,
      ip,
      method: reqParts.method,
      path: reqParts.path,
      queryString: reqParts.queryString,
      protocol: reqParts.protocol,
      statusCode,
      bytesSent,
      referrer: referrer && referrer !== '-' ? referrer : undefined,
      userAgent: userAgent && userAgent !== '-' ? userAgent : undefined,
      remoteUser: user && user !== '-' ? user : undefined,
      format: 'apache',
      raw: line,
    };

    return { ok: true, entry };
  },
};
