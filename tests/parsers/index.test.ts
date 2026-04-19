/**
 * Tests for the parser registry.
 *
 * The registry is small but critical — it's the single point of
 * lookup for "give me a parser for format X". Bugs here cascade
 * everywhere.
 */

import { getParser, getSupportedFormats } from '../../src/parsers';
import { apacheParser } from '../../src/parsers/apache';
import { nginxParser } from '../../src/parsers/nginx';

describe('parser registry', () => {
  describe('getParser', () => {
    it('returns the apache parser for "apache"', () => {
      const parser = getParser('apache');
      expect(parser).toBe(apacheParser);
    });

    it('returns the nginx parser for "nginx"', () => {
      const parser = getParser('nginx');
      expect(parser).toBe(nginxParser);
    });

    it('returns undefined for unknown formats', () => {
      // 'iis' is a valid LogFormat type but we haven't registered a parser yet.
      expect(getParser('iis')).toBeUndefined();
    });

    it('returns undefined for the "unknown" format', () => {
      expect(getParser('unknown')).toBeUndefined();
    });
  });

  describe('getSupportedFormats', () => {
    it('returns a non-empty list', () => {
      const formats = getSupportedFormats();
      expect(formats.length).toBeGreaterThan(0);
    });

    it('includes "apache" in the supported list', () => {
      const formats = getSupportedFormats();
      expect(formats).toContain('apache');
    });

    it('only lists formats that have actual parsers registered', () => {
      // Every format in the list must return a parser via getParser.
      const formats = getSupportedFormats();
      for (const f of formats) {
        expect(getParser(f)).toBeDefined();
      }
    });
  });
});