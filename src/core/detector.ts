/**
 * Detection engine — takes a LogEntry and runs all registered
 * signatures against the relevant fields, returning a DetectionResult.
 *
 * This is the heart of SignalParse. It's deliberately small and
 * dumb: it doesn't know what SQLi is, it doesn't know what XSS is,
 * it just reads signatures (data) and matches regex against fields.
 *
 * All the "intelligence" lives in the signature files. The engine
 * is a generic pattern-matching loop.
 */

import type { LogEntry } from '../types/log.types';
import type {
  DetectionResult,
  LogField,
  Severity,
  Signature,
  Threat,
} from '../types/threat.types';
import { ALL_SIGNATURES } from '../signatures';

/**
 * Severity ranking — used to compute the overall severity of a
 * DetectionResult as the MAX of all its threats' severities.
 *
 * Higher number = more critical.
 */
const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * Reverse lookup: rank → severity name.
 * Used to convert the computed max rank back to a Severity value.
 */
const RANK_TO_SEVERITY: readonly Severity[] = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

/**
 * Extract the value of a specific field from a LogEntry.
 *
 * Returns undefined if the field is not present (e.g., no query string).
 * The detector uses this to check each field a signature targets.
 */
function getFieldValue(entry: LogEntry, field: LogField): string | undefined {
  switch (field) {
    case 'path':
      return entry.path;
    case 'queryString':
      return entry.queryString;
    case 'userAgent':
      return entry.userAgent;
    case 'referrer':
      return entry.referrer;
    case 'remoteUser':
      return entry.remoteUser;
  }
}

/**
 * Try to match a single signature against a LogEntry.
 *
 * Iterates each field the signature targets, and returns the FIRST
 * match found (we don't care if the same signature matches multiple
 * fields — one match is enough to raise the alert).
 *
 * Returns null if no field matched.
 */
function matchSignature(entry: LogEntry, signature: Signature): Threat | null {
  for (const field of signature.fields) {
    const value = getFieldValue(entry, field);
    if (value === undefined) continue;

    const match = signature.pattern.exec(value);
    if (!match) continue;

    // Match found. Build a Threat object from the signature + match details.
    const threat: Threat = {
      signatureId: signature.id,
      type: signature.type,
      field,
      matchedString: match[0],
      confidence: signature.confidence,
      severity: signature.severity,
      mitreTechnique: signature.mitreTechnique,
    };
    return threat;
  }
  return null;
}

/**
 * Compute the overall severity of a set of threats.
 *
 * Rule: take the highest severity across all threats.
 * If there are no threats, return 'INFO'.
 */
function computeOverallSeverity(threats: readonly Threat[]): Severity {
  if (threats.length === 0) return 'INFO';

  let maxRank = 0;
  for (const threat of threats) {
    const rank = SEVERITY_RANK[threat.severity];
    if (rank > maxRank) maxRank = rank;
  }

  // noUncheckedIndexedAccess means this lookup is `Severity | undefined`.
  // Guard against it, though maxRank is always in bounds by construction.
  return RANK_TO_SEVERITY[maxRank] ?? 'INFO';
}

/**
 * Run all registered signatures against a LogEntry.
 *
 * Returns a DetectionResult with:
 *   - the original entry (unchanged)
 *   - all matched threats (possibly empty)
 *   - the computed overall severity
 *
 * This function is PURE: same input → same output, no side effects,
 * no I/O. Trivially testable, trivially parallelizable.
 */
export function detect(entry: LogEntry): DetectionResult {
  const threats: Threat[] = [];

  for (const signature of ALL_SIGNATURES) {
    const threat = matchSignature(entry, signature);
    if (threat) {
      threats.push(threat);
    }
  }

  const severity = computeOverallSeverity(threats);

  return {
    entry,
    threats,
    severity,
  };
}

/**
 * Custom-registry variant: run a specific list of signatures instead
 * of the global set. Useful for tests, benchmarks, and future rule
 * profiles (e.g., "only run CRITICAL signatures").
 */
export function detectWith(
  entry: LogEntry,
  signatures: readonly Signature[],
): DetectionResult {
  const threats: Threat[] = [];

  for (const signature of signatures) {
    const threat = matchSignature(entry, signature);
    if (threat) {
      threats.push(threat);
    }
  }

  return {
    entry,
    threats,
    severity: computeOverallSeverity(threats),
  };
}