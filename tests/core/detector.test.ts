/**
 * Tests for the detection engine.
 *
 * Strategy:
 *   - Test the engine WITH custom signatures (detectWith), not the global
 *     ALL_SIGNATURES. Why? Because using ALL_SIGNATURES makes tests
 *     fragile: adding a new signature later could change test outcomes.
 *     With custom signature lists, each test is hermetic.
 *
 *   - Cover both detection (positive) AND non-detection (negative) cases.
 *     False positives are as bad as false negatives.
 *
 *   - Test the engine logic itself (severity computation, field targeting,
 *     multi-match), not specific signature patterns. Pattern correctness
 *     is the responsibility of the signature tests.
 */

import { detect, detectWith } from '../../src/core/detector';
import type { LogEntry } from '../../src/types/log.types';
import type { Signature } from '../../src/types/threat.types';

/**
 * Helper: build a LogEntry with reasonable defaults.
 * Tests can override only the fields they care about.
 */
function makeEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: new Date('2024-01-01T00:00:00Z'),
    ip: '127.0.0.1',
    method: 'GET',
    path: '/',
    statusCode: 200,
    format: 'apache',
    raw: 'fake raw line',
    ...overrides,
  };
}

/**
 * A simple signature factory for tests.
 */
function makeSignature(overrides: Partial<Signature> = {}): Signature {
  return {
    id: 'test-sig-01',
    name: 'Test signature',
    type: 'SQLI',
    pattern: /attack/i,
    fields: ['queryString'],
    confidence: 80,
    severity: 'HIGH',
    description: 'A test signature',
    ...overrides,
  };
}

describe('detector', () => {
  describe('clean entries', () => {
    it('returns INFO severity and empty threats for clean traffic', () => {
      const entry = makeEntry({ path: '/index.html', queryString: 'page=2' });
      const sig = makeSignature();

      const result = detectWith(entry, [sig]);

      expect(result.threats).toHaveLength(0);
      expect(result.severity).toBe('INFO');
    });

    it('preserves the original entry unchanged in the result', () => {
      const entry = makeEntry({ path: '/about' });
      const result = detectWith(entry, []);

      expect(result.entry).toBe(entry); // same reference
    });
  });

  describe('field targeting (context-aware matching)', () => {
    it('matches when the targeted field contains the pattern', () => {
      const entry = makeEntry({ queryString: 'id=attack' });
      const sig = makeSignature({ fields: ['queryString'] });

      const result = detectWith(entry, [sig]);

      expect(result.threats).toHaveLength(1);
      expect(result.threats[0]?.field).toBe('queryString');
    });

    it('does NOT match when pattern is in an untargeted field', () => {
      // Pattern targets queryString only, but "attack" is in userAgent.
      // This is the false-positive prevention test.
      const entry = makeEntry({
        queryString: 'page=2',
        userAgent: 'attack-browser/1.0',
      });
      const sig = makeSignature({ fields: ['queryString'] });

      const result = detectWith(entry, [sig]);

      expect(result.threats).toHaveLength(0);
    });

    it('checks all targeted fields when multiple are specified', () => {
      const entry = makeEntry({
        path: '/foo',
        queryString: 'bar=baz',
        userAgent: 'contains-attack-keyword',
      });
      const sig = makeSignature({ fields: ['queryString', 'userAgent'] });

      const result = detectWith(entry, [sig]);

      expect(result.threats).toHaveLength(1);
      expect(result.threats[0]?.field).toBe('userAgent');
    });

    it('skips fields that are undefined on the entry', () => {
      // Entry has no queryString. Signature targeting queryString
      // should simply skip it, not throw.
      const entry = makeEntry({ queryString: undefined });
      const sig = makeSignature({ fields: ['queryString'] });

      expect(() => detectWith(entry, [sig])).not.toThrow();
      const result = detectWith(entry, [sig]);
      expect(result.threats).toHaveLength(0);
    });
  });

  describe('multi-signature matching', () => {
    it('reports all matching signatures, not just the first one', () => {
      const entry = makeEntry({ queryString: 'id=attack' });
      const sigA = makeSignature({ id: 'sig-a', pattern: /attack/i });
      const sigB = makeSignature({ id: 'sig-b', pattern: /id=/i });

      const result = detectWith(entry, [sigA, sigB]);

      expect(result.threats).toHaveLength(2);
      const ids = result.threats.map((t) => t.signatureId);
      expect(ids).toContain('sig-a');
      expect(ids).toContain('sig-b');
    });

    it('produces only one threat per signature, even if signature targets multiple matching fields', () => {
      // Both queryString and path contain "attack", but the signature
      // should report only the FIRST matching field — not duplicate.
      const entry = makeEntry({
        path: '/attack',
        queryString: 'q=attack',
      });
      const sig = makeSignature({ fields: ['path', 'queryString'] });

      const result = detectWith(entry, [sig]);

      expect(result.threats).toHaveLength(1);
    });
  });

  describe('severity computation', () => {
    it('returns INFO when no threats are detected', () => {
      const result = detectWith(makeEntry(), []);
      expect(result.severity).toBe('INFO');
    });

    it('returns the severity of the single matching signature', () => {
      const entry = makeEntry({ queryString: 'attack' });
      const sig = makeSignature({ severity: 'MEDIUM' });

      const result = detectWith(entry, [sig]);

      expect(result.severity).toBe('MEDIUM');
    });

    it('returns the MAXIMUM severity across multiple matches', () => {
      const entry = makeEntry({ queryString: 'attack-low attack-high' });
      const sigLow = makeSignature({
        id: 'sig-low',
        pattern: /attack-low/,
        severity: 'LOW',
      });
      const sigHigh = makeSignature({
        id: 'sig-high',
        pattern: /attack-high/,
        severity: 'CRITICAL',
      });

      const result = detectWith(entry, [sigLow, sigHigh]);

      expect(result.threats).toHaveLength(2);
      expect(result.severity).toBe('CRITICAL');
    });

    it('correctly orders all five severity levels', () => {
      // Build five signatures, each matching, each with a different severity.
      // Result should be CRITICAL (the highest).
      const entry = makeEntry({ queryString: 'a b c d e' });
      const sigs: Signature[] = [
        makeSignature({ id: 's1', pattern: /a/, severity: 'INFO' }),
        makeSignature({ id: 's2', pattern: /b/, severity: 'LOW' }),
        makeSignature({ id: 's3', pattern: /c/, severity: 'MEDIUM' }),
        makeSignature({ id: 's4', pattern: /d/, severity: 'HIGH' }),
        makeSignature({ id: 's5', pattern: /e/, severity: 'CRITICAL' }),
      ];

      const result = detectWith(entry, sigs);

      expect(result.threats).toHaveLength(5);
      expect(result.severity).toBe('CRITICAL');
    });
  });

  describe('threat metadata', () => {
    it('includes the matched substring in the threat', () => {
      const entry = makeEntry({ queryString: 'before-DROP TABLE-after' });
      const sig = makeSignature({ pattern: /DROP TABLE/ });

      const result = detectWith(entry, [sig]);

      expect(result.threats[0]?.matchedString).toBe('DROP TABLE');
    });

    it('propagates signature confidence to the threat', () => {
      const entry = makeEntry({ queryString: 'attack' });
      const sig = makeSignature({ confidence: 73 });

      const result = detectWith(entry, [sig]);

      expect(result.threats[0]?.confidence).toBe(73);
    });

    it('propagates the MITRE technique when present', () => {
      const entry = makeEntry({ queryString: 'attack' });
      const sig = makeSignature({ mitreTechnique: 'T9999' });

      const result = detectWith(entry, [sig]);

      expect(result.threats[0]?.mitreTechnique).toBe('T9999');
    });

    it('omits MITRE technique when not specified on the signature', () => {
      const entry = makeEntry({ queryString: 'attack' });
      const sig = makeSignature({ mitreTechnique: undefined });

      const result = detectWith(entry, [sig]);

      expect(result.threats[0]?.mitreTechnique).toBeUndefined();
    });

    it('uses the signature ID, type, and severity in the threat', () => {
      const entry = makeEntry({ userAgent: 'attack' });
      const sig = makeSignature({
        id: 'custom-id',
        type: 'XSS',
        severity: 'MEDIUM',
        fields: ['userAgent'],
      });

      const result = detectWith(entry, [sig]);

      expect(result.threats[0]?.signatureId).toBe('custom-id');
      expect(result.threats[0]?.type).toBe('XSS');
      expect(result.threats[0]?.severity).toBe('MEDIUM');
    });
  });

  describe('global detect()', () => {
    // detect() uses ALL_SIGNATURES, so we verify it RUNS without
    // making assertions about specific signatures matching. This test
    // exists to confirm the wiring works, not to validate signatures.
    it('runs against the global signature registry without throwing', () => {
      const entry = makeEntry({
        queryString: "user=admin' OR '1'='1",
        userAgent: 'sqlmap/1.7.2',
      });

      expect(() => detect(entry)).not.toThrow();

      const result = detect(entry);
      expect(result.entry).toBe(entry);
      // We expect SOMETHING to match here (tautology + scanner UA),
      // but the exact count depends on the registry.
      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('returns INFO for entries with no threats against the global registry', () => {
      const entry = makeEntry({
        path: '/index.html',
        queryString: 'page=1',
        userAgent: 'Mozilla/5.0',
      });

      const result = detect(entry);

      expect(result.threats).toHaveLength(0);
      expect(result.severity).toBe('INFO');
    });
  });

  describe('purity (no side effects)', () => {
    it('does not mutate the input entry', () => {
      const entry = makeEntry({ queryString: 'attack' });
      const snapshot = JSON.stringify(entry);

      detectWith(entry, [makeSignature()]);

      expect(JSON.stringify(entry)).toBe(snapshot);
    });

    it('returns the same result for the same input (deterministic)', () => {
      const entry = makeEntry({ queryString: 'attack' });
      const sig = makeSignature();

      const r1 = detectWith(entry, [sig]);
      const r2 = detectWith(entry, [sig]);

      expect(r1.threats).toEqual(r2.threats);
      expect(r1.severity).toBe(r2.severity);
    });
  });
});