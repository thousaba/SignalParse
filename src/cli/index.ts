#!/usr/bin/env node
/**
 * SignalParse CLI entry point.
 *
 * Usage:
 *   signalparse scan --format apache --file access.log
 *   signalparse scan --format apache --file access.log --min-severity HIGH
 *   signalparse scan --format apache --file access.log --output threats.json
 *   signalparse scan --format apache --file access.log --threats-only
 *   signalparse formats
 *
 * Exit codes:
 *   0 — success, no threats detected
 *   1 — success, threats detected (useful for CI/CD gates)
 *   2 — usage error (bad arguments)
 *   3 — runtime error (file not found, parse error, etc.)
 */

import { createWriteStream } from 'node:fs';
import { Command } from 'commander';
import type { LogFormat } from '../types/log.types';
import type { Severity } from '../types/threat.types';
import { getParser, getSupportedFormats } from '../parsers';
import { streamLogFile } from '../core/streamer';
import { detect } from '../core/detector';
import { SIGNATURE_COUNT } from '../signatures';
import { formatJson, shouldEmit } from '../output/json';

/**
 * Severity rank for --min-severity filtering.
 * Must match the order in src/core/detector.ts.
 */
const SEVERITY_RANK: Readonly<Record<Severity, number>> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * Exit codes as named constants — easier to grep and reason about.
 */
const EXIT_CLEAN = 0;
const EXIT_THREATS_FOUND = 1;
const EXIT_USAGE = 2;
const EXIT_RUNTIME = 3;

/**
 * Validate and normalize the --format argument.
 * Exits with EXIT_USAGE if the format is unknown.
 */
function validateFormat(raw: string): LogFormat {
  const supported = getSupportedFormats();
  if (!supported.includes(raw as LogFormat)) {
    process.stderr.write(
      `Error: unknown format "${raw}". Supported formats: ${supported.join(', ')}\n`,
    );
    process.exit(EXIT_USAGE);
  }
  return raw as LogFormat;
}

/**
 * Validate --min-severity. Exits on invalid input.
 */
function validateMinSeverity(raw: string): Severity {
  const upper = raw.toUpperCase() as Severity;
  if (!(upper in SEVERITY_RANK)) {
    process.stderr.write(
      `Error: unknown severity "${raw}". Valid values: ${Object.keys(SEVERITY_RANK).join(', ')}\n`,
    );
    process.exit(EXIT_USAGE);
  }
  return upper;
}

/**
 * The `scan` subcommand — the main event.
 */
interface ScanOptions {
  format: string;
  file: string;
  output?: string;
  minSeverity?: string;
  threatsOnly?: boolean;
  pretty?: boolean;
  quiet?: boolean;
}

async function runScan(options: ScanOptions): Promise<void> {
  const format = validateFormat(options.format);
  const minSeverity = options.minSeverity ? validateMinSeverity(options.minSeverity) : 'INFO';
  const minRank = SEVERITY_RANK[minSeverity];

  const parser = getParser(format);
  if (!parser) {
    // Shouldn't happen since validateFormat checked, but TS doesn't know that.
    process.stderr.write(`Error: no parser registered for format "${format}"\n`);
    process.exit(EXIT_RUNTIME);
  }

  // Output destination: file stream or stdout.
  const outStream = options.output
    ? createWriteStream(options.output, { encoding: 'utf8' })
    : process.stdout;

  // Banner on stderr so it doesn't pollute piped JSON output.
  if (!options.quiet) {
    process.stderr.write(
      `SignalParse — ${SIGNATURE_COUNT} signatures loaded | format: ${format} | file: ${options.file}\n`,
    );
  }

  const start = Date.now();
  let totalLines = 0;
  let parseErrors = 0;
  let threatsFound = 0;

  try {
    for await (const parseResult of streamLogFile({ filePath: options.file, parser })) {
      totalLines++;

      if (!parseResult.ok) {
        parseErrors++;
        continue;
      }

      const result = detect(parseResult.entry);

      // Filter by minimum severity.
      if (SEVERITY_RANK[result.severity] < minRank) continue;

      // Filter by threats-only.
      if (!shouldEmit(result, { threatsOnly: options.threatsOnly })) continue;

      if (result.threats.length > 0) threatsFound++;

      const json = formatJson(result, { pretty: options.pretty });
      outStream.write(json + '\n');
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    process.stderr.write(`Runtime error: ${msg}\n`);
    process.exit(EXIT_RUNTIME);
  }

  // Close file stream if we opened one.
  if (options.output && outStream !== process.stdout) {
    (outStream as ReturnType<typeof createWriteStream>).end();
  }

  // Summary to stderr.
  const elapsedMs = Date.now() - start;
  const lps = elapsedMs > 0 ? Math.round((totalLines / elapsedMs) * 1000) : 0;

  if (!options.quiet) {
    process.stderr.write(
      `\nProcessed ${totalLines} lines in ${elapsedMs}ms (${lps.toLocaleString()} lines/sec)\n` +
        `  Parse errors: ${parseErrors}\n` +
        `  Threats found: ${threatsFound}\n`,
    );
  }

  process.exit(threatsFound > 0 ? EXIT_THREATS_FOUND : EXIT_CLEAN);
}

/**
 * The `formats` subcommand — lists supported log formats.
 */
function runFormats(): void {
  const formats = getSupportedFormats();
  process.stdout.write('Supported log formats:\n');
  for (const f of formats) {
    process.stdout.write(`  - ${f}\n`);
  }
}

/**
 * Build and run the CLI.
 */
function main(): void {
  const program = new Command();

  program
    .name('signalparse')
    .description('High-performance, type-safe log analysis engine for detecting security threats.')
    .version('0.1.0');

  program
    .command('scan')
    .description('Scan a log file for security threats.')
    .requiredOption('-f, --format <format>', 'log format (e.g., apache)')
    .requiredOption('-i, --file <path>', 'path to log file')
    .option('-o, --output <path>', 'write JSON output to a file instead of stdout')
    .option('-s, --min-severity <level>', 'minimum severity to report (INFO|LOW|MEDIUM|HIGH|CRITICAL)')
    .option('-t, --threats-only', 'only emit entries that contain at least one threat')
    .option('-p, --pretty', 'pretty-print JSON output (breaks NDJSON compatibility)')
    .option('-q, --quiet', 'suppress banner and summary output')
    .action((opts: ScanOptions) => {
      runScan(opts).catch((err) => {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`Fatal: ${msg}\n`);
        process.exit(EXIT_RUNTIME);
      });
    });

  program
    .command('formats')
    .description('List all supported log formats.')
    .action(() => {
      runFormats();
    });

  program.parse(process.argv);
}

main();