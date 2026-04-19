# SignalParse

> High-performance, type-safe log analysis engine for detecting security threats in web server logs.

SignalParse is a CLI tool that streams Apache and Nginx access logs, parses them into structured events, and detects common web attacks using a modular signature engine — all with constant memory usage, regardless of file size.

---

## Features

- **Streaming parser** — processes arbitrarily large log files with constant memory footprint
- **Multi-format support** — Apache Combined Log Format + Nginx default format
- **Pluggable parsers** — add new log formats by implementing a single interface
- **20 detection signatures** across 4 attack categories:
  - **SQL Injection** (6 signatures) — tautology, UNION SELECT, comment injection, destructive keywords, scanner fingerprinting
  - **Cross-Site Scripting** (5 signatures) — script tags, event handlers, javascript: protocol, iframe, dangerous HTML tags
  - **Path Traversal / LFI** (4 signatures) — literal, URL-encoded, double-encoded (WAF bypass), sensitive file references
  - **Command Injection** (5 signatures) — shell chaining, command substitution, reverse shell, shell path, bare recon commands
- **Encoding-evasion resistant** — patterns match both literal AND URL-encoded variants, including double-encoding for WAF bypass detection
- **Context-aware matching** — signatures target specific fields (queryString, path, userAgent) to minimize false positives
- **Confidence scoring** — every detection has a confidence score (0–100) and severity level
- **MITRE ATT&CK mapping** — each signature mapped to a MITRE technique ID
- **OWASP Top 10 mapping** — each signature mapped to an OWASP category
- **Structured NDJSON output** — pipe results to `jq`, Elasticsearch, Splunk, or any downstream tool
- **CI/CD-friendly exit codes** — exit 0 (clean), exit 1 (threats found)
- **TypeScript-first** — full type safety with strict mode across all layers

## Planned

- GeoIP enrichment (flag suspicious source countries)
- Brute force detection (stateful, time-windowed)
- Terminal dashboard (blessed-contrib)
- CEF / ECS output formats for SIEM integration
- Real-time tailing mode (`-f` flag)
- Threat intelligence integration (AbuseIPDB)

---

## Performance

Benchmarked on a 73.6 MB log file (500,000 lines, 90% clean / 10% attack traffic):

| Metric | Value |
|--------|-------|
| Throughput | **176,000 lines/second** (single thread, compiled JS) |
| Peak heap memory | **19 MB** |
| File size processed | 73.6 MB |
| Parse errors | 0 |
| Threats detected | 52,810 across 46,877 entries |
| Signatures evaluated | 20 per line |

Memory usage remains bounded regardless of input file size — a 73 MB file is processed with only 19 MB of heap. Streaming via `readline` + `createReadStream` ensures constant memory regardless of whether the input is 10 MB or 10 GB.

---

## Architecture

```
┌──────────────┐
       │  Log File     │
       │ (Apache/Nginx)│
       └──────┬───────┘
              │
              ▼
    ┌──────────────────┐
    │     Streamer     │  ← readline + createReadStream
    │  (line-by-line)  │     constant memory
    └──────┬───────────┘
           │ raw line
           ▼
    ┌──────────────────┐
    │  Format Parser   │  ← strategy pattern
    │ (Apache | Nginx) │     returns LogEntry
    └──────┬───────────┘
           │ LogEntry
           ▼
    ┌──────────────────┐
    │     Detector     │  ← runs all signatures
    │  (signature/*)   │     returns DetectionResult
    └──────┬───────────┘
           │ DetectionResult
           ▼
    ┌──────────────────┐
    │     Output       │  ← NDJSON / stdout / file
    └──────────────────┘
```


**Key design decisions:**

- **Stream, never buffer.** The streamer uses Node's `readline` over `createReadStream` so memory usage stays flat even on multi-GB files.
- **Parsers are pluggable.** Each log format implements a `LogParser` interface. Adding Nginx required zero changes to the streamer, detector, or CLI — just a new file and one registry line.
- **Signatures are data, not code.** Each signature is a typed object describing what field to match, the regex pattern, confidence, and severity. New signatures don't require engine changes. This is how Suricata, YARA, and Snort work.
- **Detection is separate from parsing.** A `LogEntry` is a pure representation of the log line. A `DetectionResult` is the output of running signatures against it. Both sides are independently testable.
- **Never throw in a stream.** Parse failures return `{ ok: false }` instead of throwing, so a single malformed line doesn't kill the entire pipeline.

---

## Installation

```bash
git clone https://github.com/<your-username>/signalparse.git
cd signalparse
npm install
npm run build
```

---

## Usage

```bash
# Analyze an Apache log
npx signalparse scan --format apache --file /var/log/apache2/access.log

# Analyze an Nginx log
npx signalparse scan --format nginx --file /var/log/nginx/access.log

# Only show threats, pretty-printed
npx signalparse scan --format apache --file access.log --threats-only --pretty

# Only show HIGH and CRITICAL severity
npx signalparse scan --format apache --file access.log --min-severity HIGH

# Pipe into jq for filtering
npx signalparse scan --format nginx --file access.log -q | jq 'select(.severity == "CRITICAL")'

# Write threats to a file
npx signalparse scan --format apache --file access.log --threats-only --output threats.json

# List supported formats
npx signalparse formats
```

### Example Output

```json
{
  "timestamp": "2024-06-15T08:30:01.000Z",
  "ip": "203.0.113.5",
  "method": "GET",
  "path": "/login",
  "queryString": "u=admin%27%20OR%20%271%27=%271",
  "statusCode": 200,
  "format": "nginx",
  "severity": "CRITICAL",
  "threats": [
    {
      "signatureId": "sqli-tautology-01",
      "type": "SQLI",
      "field": "queryString",
      "matchedString": "%27%20OR%20%271%27=%271",
      "confidence": 95,
      "severity": "CRITICAL",
      "mitreTechnique": "T1190"
    }
  ]
}
```

---

## Project Structure

```
src/
├── core/
│   ├── detector.ts       # Detection engine — runs signatures against entries
│   └── streamer.ts       # File streaming with readline (constant memory)
├── parsers/
│   ├── types.ts          # LogParser interface (strategy pattern)
│   ├── apache.ts         # Apache Combined Log Format parser
│   ├── nginx.ts          # Nginx default format parser
│   └── index.ts          # Parser registry
├── signatures/
│   ├── sqli.ts           # SQL Injection patterns (6 signatures)
│   ├── xss.ts            # Cross-Site Scripting patterns (5 signatures)
│   ├── path-traversal.ts # Directory traversal patterns (4 signatures)
│   ├── command-injection.ts # OS command injection patterns (5 signatures)
│   └── index.ts          # Signature registry
├── output/
│   └── json.ts           # NDJSON formatter
├── types/
│   ├── log.types.ts      # LogEntry, ParseResult, HttpMethod
│   └── threat.types.ts   # Signature, Threat, DetectionResult, Severity
└── cli/
    └── index.ts          # Commander.js CLI entry point
tests/
├── core/
│   ├── detector.test.ts  # 21 tests — field targeting, severity, purity
│   └── streamer.test.ts  # 14 tests — CRLF, file handle leaks, error isolation
├── parsers/
│   ├── apache.test.ts    # 20 tests — timestamps, methods, adversarial input
│   ├── nginx.test.ts     # 18 tests — IPv6, format field, encoding
│   └── index.test.ts     # 7 tests — registry lookup, format listing
├── signatures/
│   ├── xss.test.ts       # 18 tests — script tags, event handlers, false positives
│   ├── path-traversal.test.ts  # 17 tests — encoded, double-encoded, sensitive files
│   └── command-injection.test.ts # 16 tests — chaining, substitution, reverse shell
└── output/
    └── json.test.ts      # 17 tests — schema stability, round-trip, encoding
```


---

## Testing

```bash
npm test              # run all tests
npm run test:watch    # watch mode
npm run test:coverage # coverage report
```

**148 unit tests** across 9 test suites:

| Component | Tests | Line Coverage |
|-----------|-------|---------------|
| Detector | 21 | 95% |
| Streamer | 14 | 100% |
| Apache parser | 20 | 91% |
| Nginx parser | 18 | 89% |
| Parser registry | 7 | 100% |
| SQLi signatures | (via detector) | 100% |
| XSS signatures | 18 | 100% |
| Path traversal | 17 | 100% |
| Command injection | 16 | 100% |
| JSON output | 17 | 100% |
| **Overall** | **148** | **95%** |

---

## Signature Coverage

| Attack Category | Signatures | MITRE Technique | OWASP Category |
|----------------|------------|-----------------|----------------|
| SQL Injection | 6 | T1190, T1595 | A03:2021 |
| Cross-Site Scripting | 5 | T1059 | A03:2021 |
| Path Traversal / LFI | 4 | T1083 | A01:2021 |
| Command Injection | 5 | T1059 | A03:2021 |
| **Total** | **20** | | |

Each signature includes:
- Context-aware field targeting (only scans relevant fields)
- Encoding-evasion resistance (literal + URL-encoded + double-encoded)
- Confidence scoring (0–100)
- MITRE ATT&CK and OWASP Top 10 mapping

---

## License

MIT