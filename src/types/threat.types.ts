/**
 * Threat detection types.
 *
 * Core concepts:
 *   - Signature: a detection rule (pattern + metadata). Data, not code.
 *   - Threat: a single match of a signature against a LogEntry field.
 *   - DetectionResult: wraps a LogEntry with its detected threats + severity.
 *
 * The "signatures as data" principle is critical: engine code doesn't
 * change when new signatures are added. New threats = new data, not
 * new code paths. This is how Suricata, YARA, Snort, and Wazuh all work.
 */

import type { LogEntry } from './log.types';

/**
 * Threat categories. Each category corresponds roughly to a MITRE ATT&CK
 * technique and OWASP Top 10 entry.
 */
export type ThreatType =
  | 'SQLI' //            SQL Injection            — OWASP A03, MITRE T1190
  | 'XSS' //             Cross-Site Scripting     — OWASP A03, MITRE T1059
  | 'PATH_TRAVERSAL' //  Directory Traversal / LFI — OWASP A01, MITRE T1083
  | 'RCE' //             Remote Code Execution    — OWASP A03, MITRE T1059
  | 'BRUTE_FORCE' //     Credential Stuffing      — OWASP A07, MITRE T1110
  | 'RECON' //           Scanner / fingerprinter  — MITRE T1595
  | 'COMMAND_INJECTION'; // OS Command Injection  — OWASP A03, MITRE T1059

/**
 * Which field of a LogEntry a signature examines.
 *
 * This is the heart of "context-aware matching": a signature for SQLi
 * should ONLY look at `queryString` and `path`, never at `userAgent`,
 * because a Mozilla UA string containing the word "SELECT" is not SQLi.
 */
export type LogField =
  | 'path'
  | 'queryString'
  | 'userAgent'
  | 'referrer'
  | 'remoteUser';

/**
 * Severity levels, ordered from least to most critical.
 */
export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

/**
 * A detection signature — pure data, no logic.
 *
 * Engine reads these and runs them against LogEntries. Adding a new
 * signature is as simple as adding a new object to a file.
 */
export interface Signature {
  /** Stable unique identifier, e.g. "sqli-tautology-01". Used in output. */
  readonly id: string;

  /** Human-readable name, e.g. "SQL Injection: classic tautology". */
  readonly name: string;

  /** Category of threat this signature detects. */
  readonly type: ThreatType;

  /** The regex pattern to match. */
  readonly pattern: RegExp;

  /**
   * Which LogEntry fields to run this pattern against.
   * At least one field must be specified.
   */
  readonly fields: readonly LogField[];

  /**
   * Base confidence score (0–100) for a match of this signature.
   * Higher = more certain this is a real attack, not a false positive.
   */
  readonly confidence: number;

  /** Base severity if this signature matches. */
  readonly severity: Severity;

  /** Short description, shown in CLI output and reports. */
  readonly description: string;

  /** Optional MITRE ATT&CK technique ID, e.g. "T1190". */
  readonly mitreTechnique?: string;

  /** Optional OWASP Top 10 category, e.g. "A03:2021". */
  readonly owaspCategory?: string;
}

/**
 * A single detected threat — the result of running one signature
 * against one LogEntry field and finding a match.
 */
export interface Threat {
  /** ID of the signature that matched. */
  readonly signatureId: string;

  /** Category of threat. */
  readonly type: ThreatType;

  /** Which field contained the matching content. */
  readonly field: LogField;

  /** The exact substring that matched the pattern. */
  readonly matchedString: string;

  /** Confidence score for THIS specific match. */
  readonly confidence: number;

  /** Severity for THIS specific match. */
  readonly severity: Severity;

  /** Optional MITRE ATT&CK technique ID. */
  readonly mitreTechnique?: string;
}

/**
 * The output of running the detector on a single LogEntry.
 *
 * Note: this is produced for EVERY log entry, even ones with no threats.
 * Consumers can filter by `threats.length > 0` or by severity.
 */
export interface DetectionResult {
  /** The original parsed log entry. */
  readonly entry: LogEntry;

  /** All threats detected in this entry (may be empty). */
  readonly threats: readonly Threat[];

  /**
   * The overall severity of this entry: the maximum severity across
   * all detected threats, or 'INFO' if no threats were found.
   */
  readonly severity: Severity;
}
