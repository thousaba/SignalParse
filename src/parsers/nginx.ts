/**
 * Nginx default access log format parser.
 *
 * Format (nginx default "combined" log_format directive):
 *   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
 *
 * Example line:
 *   203.0.113.5 - - [15/Jun/2024:08:30:00 +0000] "GET /api HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
 *
 * Structurally this is nearly identical to Apache Combined — the byte
 * stream often matches both grammars. What makes this parser "nginx"
 * rather than "apache" is the `format` field it emits: downstream
 * consumers (SIEMs, analysts) rely on this to apply format-specific
 * rules and enrichment later.
 *
 * This parser shares internal helpers with the Apache parser. In a
 * larger project you'd extract those into a common module; for now
 * we keep them local to avoid cross-file coupling this early.
 */

import type { LogEntry, ParseResult } from '../types/log.types';
import type { LogParser } from './types';

/**
 * Regex for Nginx default combined format.
 *
 * Note: this regex is identical in STRUCTURE to the Apache one because
 * the byte grammars are identical. The difference is purely in the
 * `format` field emitted by this parser.
 */
const NGINX_COMBINED_REGEX =
  /^(?<ip>\S+) (?<ident>\S+) (?<user>\S+) \[(?<time>[^\]]+)\] "(?<request>[^"]*)" (?<status>\d{3}) (?<size>\d+|-) "(?<referrer>[^"]*)" "(?<userAgent>[^"]*)"/;

/**
 * Time regex: "15/Jun/2024:08:30:00 +0000" or "15/Jun/2024:08:30:00 -0700"
 */
const NGINX_TIME_REGEX =
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

function parseNginxTime(timeStr: string): Date | null {
  const match = NGINX_TIME_REGEX.exec(timeStr);
  if (!match?.groups) return null;

  const { day, mon, year, hour, min, sec, tzSign, tzH, tzM } = match.groups;

  if (!day || !mon || !year || !hour || !min || !sec || !tzSign || !tzH || !tzM) {
    return null;
  }

  const monthIdx = MONTH_MAP[mon];
  if (monthIdx === undefined) return null;

  const utcMs = Date.UTC(
    parseInt(year, 10),
    monthIdx,
    parseInt(day, 10),
    parseInt(hour, 10),
    parseInt(min, 10),
    parseInt(sec, 10),
  );

  const offsetMin =
    (parseInt(tzH, 10) * 60 + parseInt(tzM, 10)) * (tzSign === '+' ? 1 : -1);
  const adjustedMs = utcMs - offsetMin * 60 * 1000;

  return new Date(adjustedMs);
}

function parseRequestLine(request: string): {
  method: string;
  path: string;
  queryString: string | undefined;
  protocol: string | undefined;
} | null {
  const parts = request.split(' ');
  if (parts.length < 2) return null;

  const method = parts[0];
  const rawPath = parts[1];
  const protocol = parts.length >= 3 ? parts.slice(2).join(' ') : undefined;

  if (!method || !rawPath) return null;

  const qIdx = rawPath.indexOf('?');
  const path = qIdx === -1 ? rawPath : rawPath.substring(0, qIdx);
  const queryString = qIdx === -1 ? undefined : rawPath.substring(qIdx + 1);

  return { method, path, queryString, protocol };
}

export const nginxParser: LogParser = {
  format: 'nginx',
  name: 'Nginx default access log (combined)',

  parse(line: string): ParseResult {
    if (!line.trim()) {
      return { ok: false, error: 'empty line', raw: line };
    }

    const match = NGINX_COMBINED_REGEX.exec(line);
    if (!match?.groups) {
      return {
        ok: false,
        error: 'line does not match Nginx combined format',
        raw: line,
      };
    }

    const { ip, user, time, request, status, size, referrer, userAgent } = match.groups;

    if (!ip || !time || request === undefined || !status) {
      return {
        ok: false,
        error: 'missing required fields after regex match',
        raw: line,
      };
    }

    const timestamp = parseNginxTime(time);
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

    const bytesSent =
      size === '-' || size === undefined ? undefined : parseInt(size, 10);

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
      format: 'nginx', // ← the one thing that matters!
      raw: line,
    };

    return { ok: true, entry };
  },
};