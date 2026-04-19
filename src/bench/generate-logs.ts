/**
 * Log file generator for benchmarking.
 *
 * Generates a large Apache Combined log file with a realistic mix of:
 *   - 90% clean traffic (various paths, methods, status codes)
 *   - 10% attack traffic (SQLi, XSS, path traversal, command injection)
 *
 * Usage:
 *   npx ts-node bench/generate-logs.ts [lineCount]
 *   npx ts-node bench/generate-logs.ts 1000000
 *
 * Default: 500,000 lines (~60-80 MB)
 */

import { createWriteStream } from 'node:fs';

const LINE_COUNT = parseInt(process.argv[2] || '500000', 10);
const OUTPUT_FILE = './bench/sample.log';

// === Clean traffic templates ===
const CLEAN_PATHS = [
  '/index.html',
  '/about',
  '/contact',
  '/api/users',
  '/api/products',
  '/api/orders',
  '/api/auth/login',
  '/api/auth/logout',
  '/static/css/main.css',
  '/static/js/app.js',
  '/static/images/logo.png',
  '/favicon.ico',
  '/robots.txt',
  '/sitemap.xml',
  '/blog/post-1',
  '/blog/post-2',
  '/docs/getting-started',
  '/docs/api-reference',
  '/health',
  '/metrics',
];

const CLEAN_QUERY_STRINGS = [
  '',
  '?page=1',
  '?page=2&limit=20',
  '?sort=name&order=asc',
  '?q=hello+world',
  '?category=electronics',
  '?id=42',
  '?token=abc123',
  '?lang=en',
  '?ref=homepage',
];

const USER_AGENTS = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/17.0',
  'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148',
  'curl/7.68.0',
  'PostmanRuntime/7.32.3',
  'python-requests/2.31.0',
  'Go-http-client/1.1',
];

const METHODS = ['GET', 'GET', 'GET', 'GET', 'POST', 'PUT', 'DELETE']; // weighted toward GET
const STATUS_CODES = [200, 200, 200, 200, 201, 301, 304, 400, 401, 403, 404, 500];

// === Attack traffic templates ===
const ATTACK_PAYLOADS = [
  // SQLi
  { path: '/login', qs: "?user=admin'%20OR%20'1'='1", ua: 'Mozilla/5.0' },
  { path: '/products', qs: '?id=1%20UNION%20SELECT%20username,password%20FROM%20users', ua: 'Mozilla/5.0' },
  { path: '/search', qs: "?q=test'--", ua: 'Mozilla/5.0' },
  { path: '/api/users', qs: '?id=1;%20DROP%20TABLE%20users', ua: 'Mozilla/5.0' },
  { path: '/search', qs: '?q=test', ua: 'sqlmap/1.7.2#stable (http://sqlmap.org)' },

  // XSS
  { path: '/comment', qs: '?msg=%3Cscript%3Ealert(1)%3C/script%3E', ua: 'Mozilla/5.0' },
  { path: '/search', qs: '?q=%3Cimg%20src=x%20onerror=alert(1)%3E', ua: 'Mozilla/5.0' },
  { path: '/redirect', qs: '?url=javascript%3Aalert(document.cookie)', ua: 'Mozilla/5.0' },
  { path: '/page', qs: '?content=%3Ciframe%20src=//evil.com%3E', ua: 'Mozilla/5.0' },

  // Path traversal
  { path: '/download', qs: '?file=../../../etc/passwd', ua: 'Mozilla/5.0' },
  { path: '/view', qs: '?doc=..%2f..%2f..%2fetc%2fshadow', ua: 'curl/7.68.0' },
  { path: '/include', qs: '?page=....//....//etc/passwd', ua: 'Mozilla/5.0' },
  { path: '/api/files', qs: '?path=/proc/self/environ', ua: 'python-requests/2.31.0' },

  // Command injection
  { path: '/ping', qs: '?host=example.com%3Bwhoami', ua: 'Mozilla/5.0' },
  { path: '/exec', qs: '?cmd=test%7Cid', ua: 'curl/7.68.0' },
  { path: '/api/run', qs: '?input=test%60cat%20/etc/passwd%60', ua: 'Mozilla/5.0' },
  { path: '/lookup', qs: '?name=test$(whoami)', ua: 'Mozilla/5.0' },
];

// === Random helpers ===
function pick<T>(arr: readonly T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]!;
}

function randomIp(): string {
  return `${10 + Math.floor(Math.random() * 220)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

function randomTimestamp(lineIndex: number): string {
  // Start from a base date and add seconds per line for realistic ordering
  const base = new Date('2024-06-15T00:00:00Z');
  base.setSeconds(base.getSeconds() + lineIndex);

  const day = String(base.getUTCDate()).padStart(2, '0');
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const mon = months[base.getUTCMonth()]!;
  const year = base.getUTCFullYear();
  const hour = String(base.getUTCHours()).padStart(2, '0');
  const min = String(base.getUTCMinutes()).padStart(2, '0');
  const sec = String(base.getUTCSeconds()).padStart(2, '0');

  return `${day}/${mon}/${year}:${hour}:${min}:${sec} +0000`;
}

function generateCleanLine(i: number): string {
  const ip = randomIp();
  const ts = randomTimestamp(i);
  const method = pick(METHODS);
  const path = pick(CLEAN_PATHS);
  const qs = pick(CLEAN_QUERY_STRINGS);
  const status = pick(STATUS_CODES);
  const size = 100 + Math.floor(Math.random() * 50000);
  const ua = pick(USER_AGENTS);
  const ref = Math.random() > 0.7 ? 'https://example.com/' : '-';

  return `${ip} - - [${ts}] "${method} ${path}${qs} HTTP/1.1" ${status} ${size} "${ref}" "${ua}"`;
}

function generateAttackLine(i: number): string {
  const ip = `203.0.113.${Math.floor(Math.random() * 256)}`;
  const ts = randomTimestamp(i);
  const payload = pick(ATTACK_PAYLOADS);
  const status = pick([200, 400, 403, 500]);
  const size = 64 + Math.floor(Math.random() * 2000);

  return `${ip} - - [${ts}] "GET ${payload.path}${payload.qs} HTTP/1.1" ${status} ${size} "-" "${payload.ua}"`;
}

// === Main ===
async function main(): Promise<void> {
  const stream = createWriteStream(OUTPUT_FILE, { encoding: 'utf8' });

  console.log(`Generating ${LINE_COUNT.toLocaleString()} log lines...`);
  const start = Date.now();

  for (let i = 0; i < LINE_COUNT; i++) {
    // 90% clean, 10% attack
    const line = Math.random() < 0.9 ? generateCleanLine(i) : generateAttackLine(i);
    stream.write(line + '\n');
  }

  // Wait for the stream to finish flushing
  await new Promise<void>((resolve, reject) => {
    stream.end(() => resolve());
    stream.on('error', reject);
  });

  const elapsed = Date.now() - start;
  console.log(`Done in ${elapsed}ms → ${OUTPUT_FILE}`);

  // File size
  const { statSync } = await import('node:fs');
  const stats = statSync(OUTPUT_FILE);
  const sizeMB = (stats.size / (1024 * 1024)).toFixed(1);
  console.log(`File size: ${sizeMB} MB`);
}

main().catch(console.error);