/**
 * Tests for the Nginx default access log format parser.
 *
 * Nginx default format:
 *   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
 *
 * Time format ($time_local):
 *   10/Oct/2000:13:55:36 +0000
 *
 * This is VERY similar to Apache Combined but semantically distinct:
 * Apache has an extra "ident" field (usually -), Nginx does not.
 * The raw byte stream may look identical, but the `format` field in
 * the output must correctly say 'nginx' so downstream consumers
 * know which grammar produced it.
 */

import { nginxParser } from '../../src/parsers/nginx';

describe('nginxParser', () => {
  describe('format metadata', () => {
    it('declares its format as "nginx"', () => {
      expect(nginxParser.format).toBe('nginx');
    });

    it('has a human-readable name', () => {
      expect(nginxParser.name).toContain('Nginx');
    });
  });

  describe('parsing valid lines', () => {
    it('parses a minimal valid Nginx default log line', () => {
      const line =
        '203.0.113.5 - - [15/Jun/2024:08:30:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;

      expect(result.entry.ip).toBe('203.0.113.5');
      expect(result.entry.method).toBe('GET');
      expect(result.entry.path).toBe('/index.html');
      expect(result.entry.statusCode).toBe(200);
      expect(result.entry.bytesSent).toBe(1234);
      expect(result.entry.userAgent).toBe('Mozilla/5.0');
      expect(result.entry.format).toBe('nginx');
    });

    it('sets format to "nginx" (not "apache") even on near-identical input', () => {
      // This is the whole point: Nginx and Apache default formats look
      // the same byte-for-byte in many cases, but the downstream format
      // field must correctly identify the source.
      const line =
        '127.0.0.1 - - [15/Jun/2024:08:30:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.format).toBe('nginx');
    });

    it('separates path and query string', () => {
      const line =
        '127.0.0.1 - - [15/Jun/2024:08:30:00 +0000] "GET /search?q=test&page=2 HTTP/1.1" 200 100 "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.path).toBe('/search');
      expect(result.entry.queryString).toBe('q=test&page=2');
    });

    it('preserves the raw line', () => {
      const line =
        '127.0.0.1 - - [15/Jun/2024:08:30:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.raw).toBe(line);
    });

    it('converts "-" placeholder to undefined for optional fields', () => {
      const line =
        '127.0.0.1 - - [15/Jun/2024:08:30:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.referrer).toBeUndefined();
      expect(result.entry.userAgent).toBeUndefined();
      expect(result.entry.remoteUser).toBeUndefined();
    });

    it('preserves authenticated remote_user', () => {
      const line =
        '127.0.0.1 - alice [15/Jun/2024:08:30:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.remoteUser).toBe('alice');
    });

    it('handles "-" as bytesSent', () => {
      const line =
        '127.0.0.1 - - [15/Jun/2024:08:30:00 +0000] "GET / HTTP/1.1" 304 - "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.bytesSent).toBeUndefined();
    });

    it('parses different HTTP methods', () => {
      const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'];
      for (const m of methods) {
        const line = `127.0.0.1 - - [15/Jun/2024:08:30:00 +0000] "${m} /api HTTP/1.1" 200 100 "-" "-"`;
        const result = nginxParser.parse(line);

        expect(result.ok).toBe(true);
        if (!result.ok) continue;
        expect(result.entry.method).toBe(m);
      }
    });

    it('preserves IPv6 addresses', () => {
      const line =
        '2001:db8::1 - - [15/Jun/2024:08:30:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.ip).toBe('2001:db8::1');
    });
  });

  describe('timestamp parsing', () => {
    it('converts Nginx timestamp with UTC to ISO', () => {
      const line =
        '127.0.0.1 - - [15/Jun/2024:08:30:00 +0000] "GET / HTTP/1.1" 200 100 "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.timestamp.toISOString()).toBe('2024-06-15T08:30:00.000Z');
    });

    it('converts Nginx timestamp with positive offset', () => {
      // 08:30 +0300 → 05:30 UTC
      const line =
        '127.0.0.1 - - [15/Jun/2024:08:30:00 +0300] "GET / HTTP/1.1" 200 100 "-" "-"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.timestamp.toISOString()).toBe('2024-06-15T05:30:00.000Z');
    });
  });

  describe('error handling', () => {
    it('returns ok:false on empty line', () => {
      const result = nginxParser.parse('');
      expect(result.ok).toBe(false);
    });

    it('returns ok:false on completely malformed line', () => {
      const result = nginxParser.parse('this is not an nginx log');
      expect(result.ok).toBe(false);
    });

    it('never throws on adversarial input', () => {
      const inputs = ['\x00\x00', '"""""', '[[[[', '"GET', '127.0.0.1 - -'];
      for (const input of inputs) {
        expect(() => nginxParser.parse(input)).not.toThrow();
      }
    });
  });

  describe('SQLi payload preservation', () => {
    it('keeps URL-encoded payload intact in queryString', () => {
      const line =
        '203.0.113.5 - - [15/Jun/2024:08:30:00 +0000] "GET /login?user=admin%27%20OR%20%271%27=%271 HTTP/1.1" 200 512 "-" "Mozilla/5.0"';

      const result = nginxParser.parse(line);

      expect(result.ok).toBe(true);
      if (!result.ok) return;
      expect(result.entry.queryString).toBe("user=admin%27%20OR%20%271%27=%271");
    });
  });
});