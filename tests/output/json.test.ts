/**
 * Tests for the JSON output formatter.
 *
 * Strategy:
 *   - Test the OUTPUT SHAPE explicitly. The JSON schema is part of
 *     the public contract — downstream tools (jq, Splunk, ELK) depend
 *     on field names and types. A "small refactor" that renames a field
 *     would silently break consumers without these tests.
 *
 *   - Test BOTH formatJson (serialization) AND shouldEmit (filtering).
 *
 *   - Round-trip test: serialized → JSON.parse → assert structure.
 *     This catches subtle bugs like Date not serializing correctly or
 *     fields containing non-JSON-safe characters.
 */

import { formatJson, shouldEmit } from '../../src/output/json';
import type { DetectionResult, Threat } from '../../src/types/threat.types';
import type { LogEntry } from '../../src/types/log.types';

/**
 * Helper: a basic clean LogEntry.
 */
function makeEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: new Date('2024-06-15T12:34:56.789Z'),
    ip: '192.0.2.1',
    method: 'GET',
    path: '/api/users',
    statusCode: 200,
    format: 'apache',
    raw: 'fake raw line',
    ...overrides,
  };
}

/**
 * Helper: a basic threat object.
 */
function makeThreat(overrides: Partial<Threat> = {}): Threat {
  return {
    signatureId: 'test-sig-01',
    type: 'SQLI',
    field: 'queryString',
    matchedString: "' OR '1'='1",
    confidence: 95,
    severity: 'CRITICAL',
    mitreTechnique: 'T1190',
    ...overrides,
  };
}

/**
 * Helper: a complete DetectionResult.
 */
function makeResult(
  entry: LogEntry = makeEntry(),
  threats: readonly Threat[] = [],
  severity: DetectionResult['severity'] = 'INFO',
): DetectionResult {
  return { entry, threats, severity };
}

describe('formatJson', () => {
  describe('output shape', () => {
    it('produces valid JSON that can be round-tripped', () => {
      const result = makeResult();
      const json = formatJson(result);

      // If JSON.parse throws, the formatter produced invalid output.
      expect(() => JSON.parse(json)).not.toThrow();
    });

    it('serializes timestamp as an ISO 8601 string', () => {
      const result = makeResult(
        makeEntry({ timestamp: new Date('2024-06-15T12:34:56.789Z') }),
      );

      const parsed = JSON.parse(formatJson(result));

      expect(parsed.timestamp).toBe('2024-06-15T12:34:56.789Z');
      expect(typeof parsed.timestamp).toBe('string');
    });

    it('includes all expected top-level fields', () => {
      const entry = makeEntry({
        queryString: 'q=test',
        bytesSent: 1024,
        referrer: 'https://example.com',
        userAgent: 'Mozilla/5.0',
        remoteUser: 'frank',
      });
      const result = makeResult(entry, [], 'INFO');

      const parsed = JSON.parse(formatJson(result));

      // Expected fields from the LogEntry side
      expect(parsed).toHaveProperty('timestamp');
      expect(parsed).toHaveProperty('ip');
      expect(parsed).toHaveProperty('method');
      expect(parsed).toHaveProperty('path');
      expect(parsed).toHaveProperty('queryString');
      expect(parsed).toHaveProperty('statusCode');
      expect(parsed).toHaveProperty('bytesSent');
      expect(parsed).toHaveProperty('referrer');
      expect(parsed).toHaveProperty('userAgent');
      expect(parsed).toHaveProperty('remoteUser');
      expect(parsed).toHaveProperty('format');
      // Expected fields from the DetectionResult side
      expect(parsed).toHaveProperty('severity');
      expect(parsed).toHaveProperty('threats');
    });

    it('serializes threats as an array of objects with the expected shape', () => {
      const threat = makeThreat({
        signatureId: 'sqli-tautology-01',
        type: 'SQLI',
        field: 'queryString',
        matchedString: "' OR '1'='1",
        confidence: 95,
        severity: 'CRITICAL',
        mitreTechnique: 'T1190',
      });
      const result = makeResult(makeEntry(), [threat], 'CRITICAL');

      const parsed = JSON.parse(formatJson(result));

      expect(Array.isArray(parsed.threats)).toBe(true);
      expect(parsed.threats).toHaveLength(1);
      expect(parsed.threats[0]).toEqual({
        signatureId: 'sqli-tautology-01',
        type: 'SQLI',
        field: 'queryString',
        matchedString: "' OR '1'='1",
        confidence: 95,
        severity: 'CRITICAL',
        mitreTechnique: 'T1190',
      });
    });

    it('serializes an empty threats array when none are detected', () => {
      const result = makeResult(makeEntry(), [], 'INFO');

      const parsed = JSON.parse(formatJson(result));

      expect(parsed.threats).toEqual([]);
      expect(parsed.severity).toBe('INFO');
    });

    it('serializes multiple threats in the order they were given', () => {
      const t1 = makeThreat({ signatureId: 'sig-a' });
      const t2 = makeThreat({ signatureId: 'sig-b' });
      const t3 = makeThreat({ signatureId: 'sig-c' });
      const result = makeResult(makeEntry(), [t1, t2, t3], 'HIGH');

      const parsed = JSON.parse(formatJson(result));

      expect(parsed.threats.map((t: { signatureId: string }) => t.signatureId)).toEqual([
        'sig-a',
        'sig-b',
        'sig-c',
      ]);
    });

    it('omits MITRE technique from a threat when it was undefined', () => {
      const threat = makeThreat({ mitreTechnique: undefined });
      const result = makeResult(makeEntry(), [threat], 'HIGH');

      const parsed = JSON.parse(formatJson(result));

      // JSON.stringify drops undefined fields entirely.
      expect(parsed.threats[0]).not.toHaveProperty('mitreTechnique');
    });

    it('preserves URL-encoded characters in the matched string', () => {
      // No double-encoding, no transformation — what's matched is what's emitted.
      const threat = makeThreat({ matchedString: '%27%20OR%20%271%27=%271' });
      const result = makeResult(makeEntry(), [threat], 'CRITICAL');

      const parsed = JSON.parse(formatJson(result));

      expect(parsed.threats[0].matchedString).toBe('%27%20OR%20%271%27=%271');
    });
  });

  describe('compact vs pretty output', () => {
    it('produces compact NDJSON-friendly output by default (no newlines inside)', () => {
      const result = makeResult(makeEntry(), [makeThreat()], 'CRITICAL');

      const json = formatJson(result);

      // The compact form has no internal newlines — critical for NDJSON.
      expect(json).not.toContain('\n');
    });

    it('produces multi-line output when pretty is true', () => {
      const result = makeResult(makeEntry(), [makeThreat()], 'CRITICAL');

      const json = formatJson(result, { pretty: true });

      // Pretty output wraps and indents.
      expect(json).toContain('\n');
      expect(json).toContain('  '); // 2-space indent
    });

    it('round-trips identically regardless of pretty mode', () => {
      const result = makeResult(makeEntry(), [makeThreat()], 'CRITICAL');

      const compact = JSON.parse(formatJson(result, { pretty: false }));
      const pretty = JSON.parse(formatJson(result, { pretty: true }));

      // The data should be IDENTICAL — only whitespace differs.
      expect(compact).toEqual(pretty);
    });
  });

  describe('schema stability', () => {
    // These tests guard against accidental schema changes. If a future
    // refactor renames or removes a field, these tests fail loudly.
    it('does not leak the raw log line into the output', () => {
      // The raw line is in LogEntry for forensic purposes, but the
      // JSON output should be normalized — raw doesn't belong in
      // structured downstream data.
      const result = makeResult(
        makeEntry({ raw: 'this should NOT appear in output' }),
      );

      const json = formatJson(result);

      expect(json).not.toContain('this should NOT appear');
    });

    it('does not include unexpected top-level fields', () => {
      const result = makeResult(makeEntry(), [makeThreat()], 'CRITICAL');

      const parsed = JSON.parse(formatJson(result));
      const keys = Object.keys(parsed).sort();

      // Pin the schema. If someone adds a field to the formatter,
      // this test will fail and force them to update the schema.
      expect(keys).toEqual(
        [
          'bytesSent',
          'format',
          'ip',
          'method',
          'path',
          'queryString',
          'referrer',
          'remoteUser',
          'severity',
          'statusCode',
          'threats',
          'timestamp',
          'userAgent',
        ].sort(),
      );
    });
  });
});

describe('shouldEmit', () => {
  it('emits everything by default (no options)', () => {
    const clean = makeResult(makeEntry(), [], 'INFO');
    const threatened = makeResult(makeEntry(), [makeThreat()], 'CRITICAL');

    expect(shouldEmit(clean)).toBe(true);
    expect(shouldEmit(threatened)).toBe(true);
  });

  it('emits everything when threatsOnly is false', () => {
    const clean = makeResult(makeEntry(), [], 'INFO');

    expect(shouldEmit(clean, { threatsOnly: false })).toBe(true);
  });

  it('drops clean entries when threatsOnly is true', () => {
    const clean = makeResult(makeEntry(), [], 'INFO');

    expect(shouldEmit(clean, { threatsOnly: true })).toBe(false);
  });

  it('keeps threatened entries when threatsOnly is true', () => {
    const threatened = makeResult(makeEntry(), [makeThreat()], 'CRITICAL');

    expect(shouldEmit(threatened, { threatsOnly: true })).toBe(true);
  });
});