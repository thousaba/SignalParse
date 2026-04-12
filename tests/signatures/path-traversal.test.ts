/**
 * Tests for path traversal / LFI signatures.
 *
 * Covers classic ../, encoded variants, double-encoding, alt separators,
 * and well-known target files (passwd, win.ini, etc.).
 */

import { detectWith } from '../../src/core/detector';
import { PATH_TRAVERSAL_SIGNATURES } from '../../src/signatures/path-traversal';
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

describe('path traversal signatures', () => {
  describe('directory traversal sequences', () => {
    it('detects literal ../ in path', () => {
      const entry = makeEntry({ path: '/files/../../../etc/passwd' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0]?.type).toBe('PATH_TRAVERSAL');
    });

    it('detects literal ..\\ in path (Windows-style)', () => {
      const entry = makeEntry({ path: '/files/..\\..\\..\\windows\\system32' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects URL-encoded ..%2f', () => {
      const entry = makeEntry({ queryString: 'file=..%2f..%2f..%2fetc%2fpasswd' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects URL-encoded ..%5c (Windows-style)', () => {
      const entry = makeEntry({ queryString: 'file=..%5c..%5cwindows' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects double URL-encoded %252e%252e%252f', () => {
      // Some WAFs decode once but not twice — attackers exploit this.
      const entry = makeEntry({ queryString: 'file=%252e%252e%252f%252e%252e%252fetc' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects detection in queryString (not just path)', () => {
      const entry = makeEntry({
        path: '/download',
        queryString: 'filename=../../../etc/passwd',
      });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0]?.field).toBe('queryString');
    });
  });

  describe('sensitive target files', () => {
    it('detects /etc/passwd reference', () => {
      const entry = makeEntry({ queryString: 'file=/etc/passwd' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects /etc/shadow reference', () => {
      const entry = makeEntry({ queryString: 'file=/etc/shadow' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects Windows win.ini reference', () => {
      const entry = makeEntry({ queryString: 'file=c:\\windows\\win.ini' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects /proc/self/environ reference (server-side info disclosure)', () => {
      const entry = makeEntry({ queryString: 'file=/proc/self/environ' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('false positive prevention', () => {
    it('does NOT trigger on a normal path with two dots in a filename', () => {
      // "my.file.name.txt" has dots but no traversal sequence
      const entry = makeEntry({ path: '/files/my.file.name.txt' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on a single dot path component (./)', () => {
      // "./" is current dir, not traversal
      const entry = makeEntry({ path: '/api/./users' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on userAgent (path traversal targets path/queryString)', () => {
      const entry = makeEntry({
        path: '/api',
        userAgent: 'Mozilla/5.0 ../../../',
      });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on a normal file extension lookup', () => {
      const entry = makeEntry({ queryString: 'ext=.txt' });
      const result = detectWith(entry, PATH_TRAVERSAL_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });
  });

  describe('signature metadata', () => {
    it('all path traversal signatures have type PATH_TRAVERSAL', () => {
      for (const sig of PATH_TRAVERSAL_SIGNATURES) {
        expect(sig.type).toBe('PATH_TRAVERSAL');
      }
    });

    it('all path traversal signatures target path or queryString', () => {
      for (const sig of PATH_TRAVERSAL_SIGNATURES) {
        const allowed: ReadonlyArray<string> = ['path', 'queryString'];
        for (const f of sig.fields) {
          expect(allowed).toContain(f);
        }
      }
    });

    it('all path traversal signatures have OWASP A01:2021 mapping', () => {
      // OWASP A01:2021 = Broken Access Control, which path traversal falls under
      for (const sig of PATH_TRAVERSAL_SIGNATURES) {
        expect(sig.owaspCategory).toBe('A01:2021');
      }
    });
  });
});