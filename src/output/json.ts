/**
 * JSON output formatter — serializes DetectionResult objects to
 * newline-delimited JSON (NDJSON), one object per line.
 *
 * Why NDJSON instead of a single big JSON array?
 *   - Streaming-friendly: you can write and read line-by-line
 *   - Pipe-friendly: `signalparse scan | jq 'select(.severity == "CRITICAL")'`
 *   - Tail-friendly: `tail -f threats.json` shows new threats in real time
 *   - Elasticsearch/Splunk/Logstash all consume NDJSON natively
 *
 * The alternative (a JSON array) would require loading the entire output
 * in memory to parse, defeating the whole "streaming" purpose of this tool.
 */

import type { DetectionResult } from '../types/threat.types';

/**
 * Options for JSON serialization.
 */
export interface JsonFormatterOptions {
  /**
   * If true, pretty-print each JSON object with indentation.
   * Makes output human-readable but breaks NDJSON compatibility.
   * Default: false (compact NDJSON).
   */
  readonly pretty?: boolean;

  /**
   * If true, only include entries that have at least one threat.
   * Clean entries are dropped from the output.
   * Default: false (include everything — downstream tools can filter).
   */
  readonly threatsOnly?: boolean;
}

/**
 * Serialize a single DetectionResult to a JSON string.
 *
 * Returns the string WITHOUT a trailing newline — the caller is
 * responsible for adding it when writing to a stream. This avoids
 * double-newlines and gives the caller full control over line endings.
 *
 * Dates are serialized as ISO 8601 strings (via Date.prototype.toJSON),
 * which is standard and parseable everywhere.
 */
export function formatJson(
  result: DetectionResult,
  options: JsonFormatterOptions = {},
): string {
  const { pretty = false } = options;

  // Build a plain object for serialization. We explicitly list fields
  // to ensure the output schema is stable and documented — avoids
  // accidentally leaking internal fields if we ever add them to the types.
  const serializable = {
    timestamp: result.entry.timestamp.toISOString(),
    ip: result.entry.ip,
    method: result.entry.method,
    path: result.entry.path,
    queryString: result.entry.queryString ?? null,
    statusCode: result.entry.statusCode,
    bytesSent: result.entry.bytesSent ?? null,
    referrer: result.entry.referrer ?? null,
    userAgent: result.entry.userAgent ?? null,
    remoteUser: result.entry.remoteUser ?? null,
    format: result.entry.format,
    severity: result.severity,
    threats: result.threats.map((t) => ({
      signatureId: t.signatureId,
      type: t.type,
      field: t.field,
      matchedString: t.matchedString,
      confidence: t.confidence,
      severity: t.severity,
      mitreTechnique: t.mitreTechnique,
    })),
  };

  return pretty ? JSON.stringify(serializable, null, 2) : JSON.stringify(serializable);
}

/**
 * Determine whether a result should be included in the output given
 * the formatter options. Centralized so the CLI doesn't have to
 * duplicate this logic.
 */
export function shouldEmit(
  result: DetectionResult,
  options: JsonFormatterOptions = {},
): boolean {
  if (options.threatsOnly && result.threats.length === 0) return false;
  return true;
}