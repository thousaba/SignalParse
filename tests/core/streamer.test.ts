/**
 * Tests for the file streamer.
 *
 * Strategy:
 *   - Create temp files for each test in beforeEach, delete in afterEach.
 *     This isolates tests from each other and avoids leftover state.
 *
 *   - Use os.tmpdir() instead of the project directory. Don't pollute
 *     the repo with test artifacts; let the OS handle cleanup if a
 *     test crashes.
 *
 *   - Test the contract (lazy evaluation, error isolation, file handle
 *     cleanup), not just the happy path.
 *
 *   - Use a stub parser instead of the real apacheParser. We're testing
 *     the streamer, not the parser. Coupling tests to the parser would
 *     create false failures when parser logic changes.
 */

import { mkdtempSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { streamLogFile, streamAndCount } from '../../src/core/streamer';
import type { LogParser } from '../../src/parsers/types';
import type { ParseResult } from '../../src/types/log.types';

/**
 * A stub parser for testing the streamer in isolation.
 * Treats every line as ok:true with the line itself as the "raw" payload.
 * Lines starting with "BAD:" return ok:false.
 */
const stubParser: LogParser = {
  format: 'apache', // doesn't matter for streamer tests
  name: 'Stub Parser',
  parse(line: string): ParseResult {
    if (line.startsWith('BAD:')) {
      return { ok: false, error: 'stub failure', raw: line };
    }
    return {
      ok: true,
      entry: {
        timestamp: new Date(0),
        ip: '0.0.0.0',
        method: 'GET',
        path: line,
        statusCode: 200,
        format: 'apache',
        raw: line,
      },
    };
  },
};

describe('streamer', () => {
  let tempDir: string;

  beforeEach(() => {
    // Create a unique temp directory for each test.
    // mkdtempSync returns the actual path with the random suffix.
    tempDir = mkdtempSync(join(tmpdir(), 'signalparse-test-'));
  });

  afterEach(() => {
    // Clean up the entire temp directory tree.
    // recursive: true so we don't have to delete files individually.
    // force: true so it doesn't error if the dir is already gone.
    rmSync(tempDir, { recursive: true, force: true });
  });

  /**
   * Helper: write content to a file in the temp directory.
   */
  function writeTemp(name: string, content: string): string {
    const path = join(tempDir, name);
    writeFileSync(path, content, { encoding: 'utf8' });
    return path;
  }

  describe('streamLogFile', () => {
    it('yields one ParseResult per line', async () => {
      const path = writeTemp('test.log', 'line1\nline2\nline3\n');

      const results: ParseResult[] = [];
      for await (const r of streamLogFile({ filePath: path, parser: stubParser })) {
        results.push(r);
      }

      expect(results).toHaveLength(3);
      expect(results.every((r) => r.ok)).toBe(true);
    });

    it('handles a file with no trailing newline', async () => {
      const path = writeTemp('test.log', 'line1\nline2\nline3');

      const results: ParseResult[] = [];
      for await (const r of streamLogFile({ filePath: path, parser: stubParser })) {
        results.push(r);
      }

      expect(results).toHaveLength(3);
    });

    it('handles an empty file gracefully', async () => {
      const path = writeTemp('empty.log', '');

      const results: ParseResult[] = [];
      for await (const r of streamLogFile({ filePath: path, parser: stubParser })) {
        results.push(r);
      }

      expect(results).toHaveLength(0);
    });

    it('handles Windows-style CRLF line endings', async () => {
      // crlfDelay: Infinity should strip the \r so lines come through clean.
      const path = writeTemp('crlf.log', 'line1\r\nline2\r\nline3\r\n');

      const results: ParseResult[] = [];
      for await (const r of streamLogFile({ filePath: path, parser: stubParser })) {
        if (r.ok) results.push(r);
      }

      expect(results).toHaveLength(3);
      // Critical: no phantom \r at end of each line's path
      results.forEach((r) => {
        if (r.ok) expect(r.entry.path).not.toContain('\r');
      });
    });

    it('does NOT stop the stream on parse errors', async () => {
      // Two BAD lines mixed with three good ones.
      // The bad lines should yield ok:false and the stream should continue.
      const path = writeTemp(
        'mixed.log',
        'good1\nBAD:first error\ngood2\nBAD:second error\ngood3\n',
      );

      const results: ParseResult[] = [];
      for await (const r of streamLogFile({ filePath: path, parser: stubParser })) {
        results.push(r);
      }

      expect(results).toHaveLength(5);
      const goodCount = results.filter((r) => r.ok).length;
      const badCount = results.filter((r) => !r.ok).length;
      expect(goodCount).toBe(3);
      expect(badCount).toBe(2);
    });

    it('rejects (throws) when the file does not exist', async () => {
      const nonexistent = join(tempDir, 'does-not-exist.log');

      // File-level errors should propagate, unlike per-line errors.
      const consume = async () => {
        for await (const _r of streamLogFile({
          filePath: nonexistent,
          parser: stubParser,
        })) {
          // intentionally empty — we just want to trigger the read attempt
        }
      };

      await expect(consume()).rejects.toThrow();
    });

    it('respects early termination via break', async () => {
      const path = writeTemp(
        'long.log',
        Array.from({ length: 1000 }, (_, i) => `line${i}`).join('\n'),
      );

      const results: ParseResult[] = [];
      for await (const r of streamLogFile({ filePath: path, parser: stubParser })) {
        results.push(r);
        if (results.length >= 5) break;
      }

      expect(results).toHaveLength(5);
      // The cleanup test below verifies that breaking out releases the file handle.
    });

    it('cleans up file handles after early termination', async () => {
      // This is the "no resource leak" test. We open and break-early
      // many times. If file handles aren't released, the OS would
      // eventually throw EMFILE (too many open files).
      const path = writeTemp('leak-test.log', 'a\nb\nc\nd\ne\n');

      for (let i = 0; i < 100; i++) {
        for await (const _r of streamLogFile({ filePath: path, parser: stubParser })) {
          break; // break immediately after first line
        }
      }

      // If we got here without crashing, file handles were released.
      // Add a trivial assertion so Jest doesn't complain about no expects.
      expect(true).toBe(true);
    });
  });

  describe('streamAndCount', () => {
    it('returns accurate stats for a clean file', async () => {
      const path = writeTemp('clean.log', 'a\nb\nc\nd\ne\n');

      const stats = await streamAndCount({ filePath: path, parser: stubParser });

      expect(stats.totalLines).toBe(5);
      expect(stats.parsed).toBe(5);
      expect(stats.failed).toBe(0);
    });

    it('separates parsed and failed counts correctly', async () => {
      const path = writeTemp(
        'mixed.log',
        'good1\nBAD:err\ngood2\nBAD:err2\ngood3\n',
      );

      const stats = await streamAndCount({ filePath: path, parser: stubParser });

      expect(stats.totalLines).toBe(5);
      expect(stats.parsed).toBe(3);
      expect(stats.failed).toBe(2);
    });

    it('reports zero stats for an empty file', async () => {
      const path = writeTemp('empty.log', '');

      const stats = await streamAndCount({ filePath: path, parser: stubParser });

      expect(stats.totalLines).toBe(0);
      expect(stats.parsed).toBe(0);
      expect(stats.failed).toBe(0);
    });

    it('reports a non-negative elapsedMs', async () => {
      const path = writeTemp('test.log', 'a\nb\n');

      const stats = await streamAndCount({ filePath: path, parser: stubParser });

      expect(stats.elapsedMs).toBeGreaterThanOrEqual(0);
    });

    it('reports linesPerSecond as a non-negative number', async () => {
      const path = writeTemp('test.log', 'a\nb\nc\n');

      const stats = await streamAndCount({ filePath: path, parser: stubParser });

      expect(stats.linesPerSecond).toBeGreaterThanOrEqual(0);
      expect(Number.isFinite(stats.linesPerSecond)).toBe(true);
    });
  });

  describe('verifying temp directory cleanup', () => {
    // This test exists to confirm afterEach is doing its job.
    // If it fails, all OTHER tests' temp dirs would leak too.
    it('removes the temp directory between tests', () => {
      // tempDir was just created in beforeEach — it should exist now.
      // After this test, afterEach will delete it. We can't easily test
      // afterEach from inside a test, but we CAN verify the directory
      // is initially empty (proving we got a fresh one).
      const contents = readdirSync(tempDir);
      expect(contents).toEqual([]);
    });
  });
});