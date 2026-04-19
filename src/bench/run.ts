/**
 * Benchmark runner for SignalParse.
 *
 * Runs the full pipeline (stream → parse → detect) on the generated
 * log file and reports performance metrics.
 *
 * Usage:
 *   npx ts-node bench/generate-logs.ts 500000
 *   npx ts-node bench/run.ts
 */

import { statSync } from 'node:fs';
import { streamLogFile } from '../core/streamer';
import { apacheParser } from '../parsers/apache';
import { detect } from '../core/detector';
import { SIGNATURE_COUNT } from '../signatures';

const LOG_FILE = './bench/sample.log';

async function main(): Promise<void> {
  const fileStats = statSync(LOG_FILE);
  const fileSizeMB = (fileStats.size / (1024 * 1024)).toFixed(1);

  console.log('╔══════════════════════════════════════════════╗');
  console.log('║         SignalParse Benchmark                ║');
  console.log('╠══════════════════════════════════════════════╣');
  console.log(`║  File:        ${LOG_FILE.padEnd(30)}║`);
  console.log(`║  Size:        ${(fileSizeMB + ' MB').padEnd(30)}║`);
  console.log(`║  Signatures:  ${String(SIGNATURE_COUNT).padEnd(30)}║`);
  console.log('╚══════════════════════════════════════════════╝');
  console.log();

  // Warm-up run (JIT compilation, cache warming)
  console.log('Warm-up run...');
  let warmupCount = 0;
  for await (const r of streamLogFile({ filePath: LOG_FILE, parser: apacheParser })) {
    if (r.ok) detect(r.entry);
    warmupCount++;
    if (warmupCount >= 10000) break;
  }
  console.log(`  Warmed up on ${warmupCount.toLocaleString()} lines.\n`);

  // Actual benchmark
  console.log('Benchmark run (full file)...');

  const memBefore = process.memoryUsage();
  const start = Date.now();

  let totalLines = 0;
  let parseErrors = 0;
  let threatsFound = 0;
  let entriesWithThreats = 0;
  let peakHeapUsed = memBefore.heapUsed;

  for await (const r of streamLogFile({ filePath: LOG_FILE, parser: apacheParser })) {
    totalLines++;

    if (!r.ok) {
      parseErrors++;
      continue;
    }

    const result = detect(r.entry);
    if (result.threats.length > 0) {
      entriesWithThreats++;
      threatsFound += result.threats.length;
    }

    // Sample memory every 50k lines
    if (totalLines % 50000 === 0) {
      const mem = process.memoryUsage();
      if (mem.heapUsed > peakHeapUsed) peakHeapUsed = mem.heapUsed;
    }
  }

  const elapsed = Date.now() - start;
  const memAfter = process.memoryUsage();
  if (memAfter.heapUsed > peakHeapUsed) peakHeapUsed = memAfter.heapUsed;

  const linesPerSec = elapsed > 0 ? Math.round((totalLines / elapsed) * 1000) : 0;
  const peakHeapMB = (peakHeapUsed / (1024 * 1024)).toFixed(1);
  const rssAfterMB = (memAfter.rss / (1024 * 1024)).toFixed(1);

  console.log();
  console.log('╔══════════════════════════════════════════════╗');
  console.log('║               Results                       ║');
  console.log('╠══════════════════════════════════════════════╣');
  console.log(`║  Total lines:       ${totalLines.toLocaleString().padEnd(24)}║`);
  console.log(`║  Parse errors:      ${parseErrors.toLocaleString().padEnd(24)}║`);
  console.log(`║  Entries w/ threats: ${entriesWithThreats.toLocaleString().padEnd(24)}║`);
  console.log(`║  Total threats:     ${threatsFound.toLocaleString().padEnd(24)}║`);
  console.log('╠══════════════════════════════════════════════╣');
  console.log(`║  Elapsed:           ${(elapsed.toLocaleString() + ' ms').padEnd(24)}║`);
  console.log(`║  Throughput:        ${(linesPerSec.toLocaleString() + ' lines/sec').padEnd(24)}║`);
  console.log(`║  Peak heap:         ${(peakHeapMB + ' MB').padEnd(24)}║`);
  console.log(`║  RSS after:         ${(rssAfterMB + ' MB').padEnd(24)}║`);
  console.log('╚══════════════════════════════════════════════╝');
  console.log();

  // Summary for README copy-paste
  console.log('--- README snippet ---');
  console.log(`Processes ${linesPerSec.toLocaleString()} log lines/second on a single thread`);
  console.log(`Peak memory: ${peakHeapMB} MB heap (${rssAfterMB} MB RSS) on a ${fileSizeMB} MB file`);
  console.log(`Detected ${threatsFound.toLocaleString()} threats in ${entriesWithThreats.toLocaleString()} entries out of ${totalLines.toLocaleString()} total lines`);
}

main().catch(console.error);