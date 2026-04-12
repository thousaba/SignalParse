/**
 * Tests for XSS signatures.
 *
 * Strategy:
 *   - Each test pairs a real-world XSS payload with its expected match.
 *   - Negative tests ensure innocent strings don't trigger false positives
 *     (e.g., user comment containing the word "script" should not alarm).
 *   - We use detectWith() to test signatures in isolation, without
 *     depending on the global registry.
 */

import { detectWith } from '../../src/core/detector';
import { XSS_SIGNATURES } from '../../src/signatures/xss';
import type { LogEntry } from '../../src/types/log.types';

function makeEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: new Date('2024-01-01T00:00:00Z'),
    ip: '127.0.0.1',
    method: 'GET',
    path: '/',
    statusCode: 200,
    format: 'apache',
    raw: 'fake',
    ...overrides,
  };
}

describe('XSS signatures', () => {
  describe('script tag injection', () => {
    it('detects literal <script> tag in query string', () => {
      const entry = makeEntry({ queryString: 'q=<script>alert(1)</script>' });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0]?.type).toBe('XSS');
    });

    it('detects URL-encoded <script> tag', () => {
      const entry = makeEntry({
        queryString: 'q=%3Cscript%3Ealert(1)%3C%2Fscript%3E',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0]?.type).toBe('XSS');
    });

    it('detects script tag with attributes (e.g., src=)', () => {
      const entry = makeEntry({
        queryString: 'q=<script src=//evil.com/x.js>',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects mixed-case script tags (case insensitive)', () => {
      const entry = makeEntry({ queryString: 'q=<ScRiPt>alert(1)</sCrIpT>' });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('event handler injection', () => {
    it('detects onerror handler', () => {
      const entry = makeEntry({
        queryString: 'q=<img src=x onerror=alert(1)>',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects onload handler', () => {
      const entry = makeEntry({
        queryString: 'q=<body onload=alert(1)>',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects onclick handler', () => {
      const entry = makeEntry({
        queryString: 'q=<a onclick=alert(1)>click</a>',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('javascript: protocol injection', () => {
    it('detects javascript: protocol in query string', () => {
      const entry = makeEntry({
        queryString: 'redirect=javascript:alert(1)',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects URL-encoded javascript: protocol', () => {
      const entry = makeEntry({
        queryString: 'redirect=javascript%3Aalert(1)',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('iframe and object injection', () => {
    it('detects iframe injection', () => {
      const entry = makeEntry({
        queryString: 'q=<iframe src=//evil.com></iframe>',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('false positive prevention', () => {
    it('does NOT trigger on the word "script" in a sentence', () => {
      // Imagine a legitimate forum post containing the word "script"
      const entry = makeEntry({
        queryString: 'comment=I+love+the+new+script+for+the+movie',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on a normal URL with javascript-related text', () => {
      const entry = makeEntry({
        queryString: 'category=javascript-tutorials',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on userAgent (XSS targets queryString/path, not UA)', () => {
      const entry = makeEntry({
        queryString: 'q=hello',
        userAgent: 'Mozilla/5.0 <script>',
      });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on innocent path like /about', () => {
      const entry = makeEntry({ path: '/about' });
      const result = detectWith(entry, XSS_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });
  });

  describe('signature metadata', () => {
    it('all XSS signatures have type XSS', () => {
      for (const sig of XSS_SIGNATURES) {
        expect(sig.type).toBe('XSS');
      }
    });

    it('all XSS signatures target queryString or path (not userAgent)', () => {
      for (const sig of XSS_SIGNATURES) {
        const allowed: ReadonlyArray<string> = ['queryString', 'path'];
        for (const f of sig.fields) {
          expect(allowed).toContain(f);
        }
      }
    });

    it('all XSS signatures have OWASP A03:2021 mapping', () => {
      for (const sig of XSS_SIGNATURES) {
        expect(sig.owaspCategory).toBe('A03:2021');
      }
    });

    it('all XSS signatures have a non-empty description', () => {
      for (const sig of XSS_SIGNATURES) {
        expect(sig.description.length).toBeGreaterThan(10);
      }
    });
  });
});