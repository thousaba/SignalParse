/**
 * Tests for the Apache Combined Log Format parser.
 *
 * Strategy:
 *   - Each test focuses on ONE behavior (single quote, query string parsing, etc.)
 *   - Use real-world log lines as fixtures, not contrived ones
 *   - Test both happy path AND failure modes (malformed input)
 *   - Use describe blocks to group related tests for readable output
 *
 * Why this matters: when a test fails, the failure message should
 * tell you EXACTLY what broke without needing to read the test code.
 */

import { apacheParser } from '../../src/parsers/apache';

describe('apacheParser', () => {
  describe('format metadata', () => {
    it('declares its format as "apache"', () => {
      expect(apacheParser.format).toBe('apache');
    });

    it('has a human-readable name', () => {
      expect(apacheParser.name).toBe('Apache Combined Log Format');
    });
  });

  describe('parsing valid lines', () => {
    it('parses a minimal valid Apache Combined log line', () => {
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "-" "Mozilla/5.0"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return; // type narrowing for TS

      expect(result.entry.ip).toBe('127.0.0.1');
      expect(result.entry.method).toBe('GET');
      expect(result.entry.path).toBe('/index.html');
      expect(result.entry.statusCode).toBe(200);
      expect(result.entry.bytesSent).toBe(2326);
      expect(result.entry.userAgent).toBe('Mozilla/5.0');
      expect(result.entry.format).toBe('apache');
    });

    it('preserves the raw line in the entry', () => {
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.raw).toBe(line);
    });

    it('separates path and query string at the first ?', () => {
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /search?q=test&page=2 HTTP/1.1" 200 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.path).toBe('/search');
      expect(result.entry.queryString).toBe('q=test&page=2');
    });

    it('returns undefined queryString when no ? is present', () => {
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /about HTTP/1.1" 200 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.queryString).toBeUndefined();
    });

    it('converts "-" placeholder to undefined for optional fields', () => {
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.referrer).toBeUndefined();
      expect(result.entry.userAgent).toBeUndefined();
      expect(result.entry.remoteUser).toBeUndefined();
    });

    it('preserves the remote user when authenticated', () => {
      const line =
        '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.remoteUser).toBe('frank');
    });

    it('handles "-" as bytesSent (zero-byte response)', () => {
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 304 - "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.bytesSent).toBeUndefined();
    });

    it('parses different HTTP methods correctly', () => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

      for (const method of methods) {
        const line = `127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "${method} /api HTTP/1.1" 200 100 "-" "-"`;
        const result = apacheParser.parse(line);

        expect(result.ok).toBe(true);
        if (!result.ok) continue;
        expect(result.entry.method).toBe(method);
      }
    });

    it('preserves non-standard HTTP methods (attacker fuzzing)', () => {
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "FOOBAR /api HTTP/1.1" 405 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.method).toBe('FOOBAR');
    });
  });

  describe('timestamp parsing', () => {
    it('correctly converts Apache timestamp with negative timezone to UTC', () => {
      // 13:55:36 -0700 means UTC is 7 hours LATER → 20:55:36 UTC
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET / HTTP/1.0" 200 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.timestamp.toISOString()).toBe('2000-10-10T20:55:36.000Z');
    });

    it('correctly converts Apache timestamp with positive timezone to UTC', () => {
      // 13:55:36 +0300 means UTC is 3 hours EARLIER → 10:55:36 UTC
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0300] "GET / HTTP/1.0" 200 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.timestamp.toISOString()).toBe('2000-10-10T10:55:36.000Z');
    });

    it('handles UTC timezone (+0000)', () => {
      const line =
        '127.0.0.1 - - [10/Oct/2000:13:55:36 +0000] "GET / HTTP/1.0" 200 100 "-" "-"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.timestamp.toISOString()).toBe('2000-10-10T13:55:36.000Z');
    });
  });

  describe('error handling', () => {
    it('returns ok:false on empty line, not throw', () => {
      const result = apacheParser.parse('');
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error).toBe('empty line');
    });

    it('returns ok:false on whitespace-only line', () => {
      const result = apacheParser.parse('   \t  ');
      expect(result.ok).toBe(false);
    });

    it('returns ok:false on completely malformed line, not throw', () => {
      const result = apacheParser.parse('this is not an apache log line');
      expect(result.ok).toBe(false);
      if (result.ok) return;
      expect(result.error).toContain('does not match');
      expect(result.raw).toBe('this is not an apache log line');
    });

    it('returns ok:false on invalid timestamp format', () => {
      // Completely garbage timestamp that won't even match the time regex
      const line =
        '127.0.0.1 - - [not-a-real-date] "GET / HTTP/1.0" 200 100 "-" "-"';

      const result = apacheParser.parse(line);
      expect(result.ok).toBe(false);
    });

    it('never throws on adversarial input', () => {
      const adversarialInputs = [
        '\x00\x00\x00\x00',
        '"""""""""""',
        '[[[[[[[[[[',
        '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "',
        '"GET',
      ];

      for (const input of adversarialInputs) {
        expect(() => apacheParser.parse(input)).not.toThrow();
      }
    });
  });

  describe('SQLi payload preservation', () => {
    it('keeps URL-encoded SQLi payload intact in queryString for downstream detection', () => {
      const line =
        '203.0.113.5 - - [10/Oct/2000:13:55:37 -0700] "GET /login?user=admin%27%20OR%20%271%27=%271 HTTP/1.1" 200 512 "-" "Mozilla/5.0"';

      const result = apacheParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.path).toBe('/login');
      expect(result.entry.queryString).toBe("user=admin%27%20OR%20%271%27=%271");
    });
  });
});