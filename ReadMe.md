# SignalParse

> High-performance, type-safe log analysis engine for detecting security threats in web server logs.

SignalParse is a CLI tool that streams Apache and Nginx access logs, parses them into structured events, and detects common web attacks (SQL Injection, XSS, brute force, path traversal) using a modular signature engine — all with constant memory usage, regardless of file size.

---

## Why SignalParse?

Most log analysis tools either:
- Load entire files into memory (dies on 2GB+ logs), or
- Are tightly coupled to a specific vendor (Splunk, ELK, Wazuh)

SignalParse is built to be **format-agnostic**, **stream-based**, and **signature-driven** — inspired by how real SIEM engines work, but as a lightweight, standalone tool you can drop into any pipeline.

---

## Features (MVP)

- **Streaming parser** — processes arbitrarily large log files with constant memory footprint
- **Multi-format support** — Apache Combined Log Format + Nginx default format out of the box
- **Pluggable parsers** — add new log formats by implementing a single interface
- **Signature-based detection** — modular threat signatures (SQLi, XSS, brute force, path traversal)
- **Context-aware matching** — patterns only run against relevant fields (query string, path, body) to minimize false positives
- **Confidence scoring** — every detection has a confidence score (0–100) and severity level
- **Structured JSON output** — pipe results to `jq`, Elasticsearch, or any downstream tool
- **TypeScript-first** — full type safety across parser, detector, and output layers

## Planned (Post-MVP)

- GeoIP enrichment (flag suspicious countries)
- MITRE ATT&CK technique mapping
- Terminal dashboard (blessed-contrib)
- CEF / ECS output formats
- Real-time tailing mode (`-f` flag, like `tail -f`)
- Threat intelligence integration (AbuseIPDB)

---

## Architecture

```
           ┌──────────────┐
           │  Log File    │
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
        │     Detector     │  ← runs signatures
        │  (signatures/*)  │     returns DetectionResult
        └──────┬───────────┘
               │ DetectionResult
               ▼
        ┌──────────────────┐
        │     Output       │  ← JSON / stdout / file
        └──────────────────┘
```

**Key design decisions:**
- **Stream, never buffer.** The streamer uses Node's `readline` over `createReadStream` so memory usage stays flat even on 10GB+ files.
- **Parsers are pluggable.** Each log format implements a `LogParser` interface — adding IIS or custom formats is a single-file change.
- **Signatures are data, not code.** Each signature is a typed object describing what field to match, the regex, the severity, and the threat type. New signatures don't require engine changes.
- **Detection is separate from parsing.** A `LogEntry` is a pure representation of the log line. A `DetectionResult` is the output of running signatures against it. This separation makes both sides independently testable.

---

## Installation

```bash
git clone https://github.com/thousaba/signalparse.git
cd signalparse
npm install
npm run build
```

---

## Usage

```bash
# Analyze an Apache log
signalparse scan --format apache --file /var/log/apache2/access.log

# Analyze an Nginx log and output JSON to a file
signalparse scan --format nginx --file access.log --output threats.json

# Only show HIGH and CRITICAL severity detections
signalparse scan --format apache --file access.log --min-severity HIGH

# Pipe into jq for filtering
signalparse scan --format nginx --file access.log | jq '.threats[] | select(.type == "SQLI")'
```

### Example Output

```json
{
  "entry": {
    "timestamp": "2026-04-08T14:23:11.000Z",
    "ip": "203.0.113.42",
    "method": "GET",
    "path": "/products",
    "queryString": "id=1' OR '1'='1",
    "statusCode": 200,
    "userAgent": "sqlmap/1.7.2"
  },
  "threats": [
    {
      "type": "SQLI",
      "pattern": "sqli-tautology-01",
      "confidence": 95,
      "matchedString": "' OR '1'='1",
      "field": "queryString"
    },
    {
      "type": "RECON",
      "pattern": "ua-sqlmap",
      "confidence": 100,
      "matchedString": "sqlmap/1.7.2",
      "field": "userAgent"
    }
  ],
  "severity": "CRITICAL"
}
```

---

## Project Structure

```
/src
  /core
    streamer.ts       # File streaming (readline wrapper)
    detector.ts       # Runs signatures against log entries
    scoring.ts        # Severity calculation logic
  /parsers
    index.ts          # Parser registry
    apache.ts         # Apache Combined Log Format parser
    nginx.ts          # Nginx default format parser
    types.ts          # LogParser interface
  /signatures
    index.ts          # Signature registry
    sqli.ts           # SQL Injection patterns
    xss.ts            # Cross-Site Scripting patterns
    path-traversal.ts # Directory traversal patterns
    brute-force.ts    # Authentication abuse patterns
  /output
    json.ts           # JSON formatter
  /types
    log.types.ts      # LogEntry, HttpMethod
    threat.types.ts   # Threat, DetectionResult, Severity, Signature
  /cli
    index.ts          # Commander.js CLI entry point
  index.ts            # Library entry point
/tests
  /fixtures
    apache-clean.log
    apache-attacks.log
    nginx-clean.log
    nginx-attacks.log
  parsers.test.ts
  signatures.test.ts
  detector.test.ts
```

---

## Performance

Target benchmarks (to be measured on MVP completion):

- **Throughput:** 500k+ log lines/second on a single thread
- **Memory:** < 100MB RAM regardless of input file size
- **Latency:** First detection emitted within 50ms of stream start

---

## Testing

```bash
npm test              # run all tests
npm run test:watch    # watch mode
npm run test:coverage # coverage report
```

Target: **90%+ coverage** on parsers, detector, and signatures.

---

## License

MIT