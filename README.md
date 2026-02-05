# SentinelScope ⊕

**A modular cybersecurity toolkit for threat intelligence aggregation, network reconnaissance, and log forensics.**

Built with FastAPI (async Python) + React/Vite. Designed for SOC analysts, pentesters, home lab operators, and security engineers who want a unified dashboard instead of juggling 6 browser tabs.

---

## Architecture

```
sentinelscope/
├── backend/                    # FastAPI (Python 3.11+)
│   ├── app/
│   │   ├── main.py             # ASGI entry, CORS, router mounts
│   │   ├── config.py           # pydantic-settings, env loading
│   │   ├── routers/
│   │   │   ├── threat_intel.py # POST/GET /api/v1/threat-intel/lookup
│   │   │   ├── net_scanner.py  # POST /scan, /ping, GET /presets
│   │   │   └── log_analyzer.py # POST /upload, /parse, GET /events, /summary
│   │   ├── services/           # API integrations (one file per source)
│   │   │   ├── virustotal.py   # VT v3 API — IP, hash, domain
│   │   │   ├── abuseipdb.py    # AbuseIPDB v2 — IP reputation
│   │   │   ├── shodan_svc.py   # Shodan REST — host info, ports, vulns
│   │   │   ├── otx.py          # AlienVault OTX — pulse intelligence
│   │   │   └── aggregator.py   # Parallel orchestration + risk scoring
│   │   ├── models/
│   │   │   └── schemas.py      # Pydantic v2 request/response models
│   │   └── utils/
│   │       └── validators.py   # Indicator type detection (IP/hash/domain)
│   ├── requirements.txt
│   └── .env.example
│
├── frontend/                   # React 18 + Vite 6
│   ├── src/
│   │   ├── App.jsx             # Module router, health check poller
│   │   ├── components/
│   │   │   ├── Header.jsx      # Nav bar, module tabs, API status LED
│   │   │   ├── Footer.jsx      # Version, configured source count
│   │   │   ├── common/         # Shared UI primitives
│   │   │   │   ├── RiskGauge.jsx    # SVG arc gauge (0-100)
│   │   │   │   ├── GlowBar.jsx     # Animated progress bar
│   │   │   │   └── DataDisplay.jsx  # SourceCard, DataRow, TagList, VerdictBadge
│   │   │   └── modules/
│   │   │       ├── threat-intel/    # 8 components (see below)
│   │   │       ├── net-scanner/     # Placeholder (frontend not built yet)
│   │   │       └── log-analyzer/    # Placeholder (frontend not built yet)
│   │   ├── hooks/              # (reserved for custom hooks)
│   │   ├── styles/
│   │   │   └── global.css      # CSS variables, animations, scrollbar
│   │   └── utils/
│   │       ├── api.js          # Fetch wrapper, error handling
│   │       └── helpers.js      # Risk colors, verdict styles, type detection
│   ├── package.json
│   ├── vite.config.js          # Dev proxy /api → :8000
│   └── index.html
│
└── README.md
```

**Total: 45 source files, 0 external dependencies beyond pip/npm installs.**

---

## Module 1: Threat Intel Aggregator

### What It Does

Accepts an IP address, domain, or file hash. Queries up to 4 threat intelligence sources **in parallel** using `asyncio.gather`. Returns a unified risk assessment with per-source breakdowns.

### Supported Indicator Types

| Type   | Detection Pattern                          | Sources Queried                    |
|--------|--------------------------------------------|------------------------------------|
| IP     | `^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`   | VirusTotal, AbuseIPDB, Shodan, OTX |
| Domain | `^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$` | VirusTotal, OTX                |
| Hash   | MD5 (32), SHA-1 (40), SHA-256 (64) hex chars | VirusTotal, OTX                 |

### Risk Scoring Algorithm

Weighted scoring normalized to 0–100. Weights adjust based on which sources returned data (only active weights count toward normalization).

**IP Scoring:**
| Source       | Weight | Scale                                |
|--------------|--------|--------------------------------------|
| VirusTotal   | 30%    | detections × 10, capped at 100       |
| AbuseIPDB    | 30%    | abuse confidence score (0-100)        |
| Shodan       | 15%    | vuln_count × 20, capped at 100       |
| AlienVault   | 25%    | pulses × 2 (cap 80) + malware × 10 (cap 20) |

**Hash Scoring:** VT 70% (detections × 2) + OTX 30% (pulses + family bonus)

**Domain Scoring:** VT 50% (detections × 10) + OTX 50% (pulses + malware)

**Verdict Thresholds:**
- `MALICIOUS` — risk ≥ 70
- `SUSPICIOUS` — risk ≥ 30
- `BENIGN` — risk > 0
- `UNKNOWN` — risk = 0 (no data returned)

### API Endpoints

```
POST /api/v1/threat-intel/lookup
Body: { "query": "185.220.101.34", "indicator_type": "ip" }  // type is optional, auto-detected

GET  /api/v1/threat-intel/lookup/{indicator}   // shorthand, auto-detects type
```

**Response shape:**
```json
{
  "query": "185.220.101.34",
  "indicator_type": "ip",
  "risk_score": 95,
  "verdict": "MALICIOUS",
  "sources": {
    "virustotal": { "score": 14, "reputation": "Malicious", "detections": "14/94", ... },
    "abuseipdb": { "score": 100, "reports": 4832, "confidence": 100, ... },
    "shodan": { "ports": [80, 443, 9001], "vulns": ["CVE-2023-44487"], ... },
    "otx": { "pulses": 47, "tags": ["tor", "exit-node", "bruteforce"], ... }
  },
  "errors": {}
}
```

### Frontend Components (Threat Intel)

| Component             | Purpose                                           |
|-----------------------|---------------------------------------------------|
| `ThreatIntelModule`   | Orchestrator — state management, API calls         |
| `SearchBar`           | Input with auto-type detection badge, example chips |
| `IPResults`           | 4-card layout for IP lookups                       |
| `HashResults`         | 2-card layout (VT + OTX) for file hashes           |
| `DomainResults`       | 2-card layout for domain lookups                   |
| `ScanHistory`         | Sidebar with clickable scan history (in-memory)    |
| `LoadingState`        | Animated source badges while querying              |
| `EmptyStates`         | Welcome screen + not-found state                   |

---

## Module 2: Network Scanner

### What It Does

TCP connect scanning with async concurrency control. Resolves hostnames, scans configurable port sets, grabs service banners, and identifies services from banner fingerprints.

### Scan Flow

```
1. Resolve target (hostname → IP, strip protocols/paths)
2. Select port set (top20, top100, or custom up to 1000 ports)
3. Run TCP connect scan (asyncio.gather + Semaphore for concurrency)
4. For open ports: grab banners (separate lower-concurrency pass)
5. Identify services from banner content
6. Return results sorted by port number
```

### Port Presets

| Preset  | Count | Includes                                                |
|---------|-------|---------------------------------------------------------|
| top20   | 20    | 21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,8080,8443 |
| top100  | 48    | Top 20 + common services, databases, caches, proxies    |
| custom  | 1-1000| User-specified port list                                |

### Banner Grabbing Strategy

1. Connect to open port
2. Wait 1.5s for voluntary banner (SSH, FTP, SMTP send banners unprompted)
3. If no banner: send protocol-appropriate probe
   - HTTP ports (80, 8080, 8443, 8888): `HEAD / HTTP/1.0\r\n\r\n`
   - Other ports: `\r\n` (generic nudge)
4. Read up to 1024 bytes, decode UTF-8, return first meaningful line (max 200 chars)

### Service Identification

Regex-based fingerprinting from banner content. Matches: SSH, HTTP, SMTP, FTP, MySQL, PostgreSQL, Redis, MongoDB, IMAP, POP3, VNC, nginx, Apache, TLS/OpenSSL.

### API Endpoints

```
POST /api/v1/net-scanner/scan
Body: {
  "target": "scanme.nmap.org",
  "preset": "top20",         // "top20" | "top100" | "custom"
  "ports": [80, 443, 8080],  // only used with preset="custom"
  "timeout": 1.5,            // per-port timeout (0.3–10.0s)
  "grab_banners": true,
  "max_concurrent": 50       // max 200
}

GET  /api/v1/net-scanner/scan/{target}?preset=top20  // quick scan shorthand
POST /api/v1/net-scanner/ping                         // TCP ping (80→443→22)
GET  /api/v1/net-scanner/ports/presets                // list available presets
GET  /api/v1/net-scanner/status
```

**Response shape:**
```json
{
  "target": "scanme.nmap.org",
  "ip": "45.33.32.156",
  "hostname": "scanme.nmap.org",
  "ports_scanned": 20,
  "open_ports": 4,
  "results": [
    { "port": 22, "state": "open", "service": "SSH", "banner": "SSH-2.0-OpenSSH_6.6.1p1", "latency_ms": 42.3 },
    { "port": 80, "state": "open", "service": "HTTP (Apache)", "banner": "HTTP/1.1 200 OK", "latency_ms": 44.1 }
  ],
  "scan_time_ms": 1823.45,
  "errors": []
}
```

### Concurrency Model

- Port scanning: `asyncio.Semaphore(max_concurrent)` — default 50, max 200
- Banner grabbing: separate `Semaphore(10)` to avoid overwhelming targets
- All scanning is pure `asyncio.open_connection` — no raw sockets, no external tools

---

## Module 3: Log Analyzer

### What It Does

Accepts log files via upload or raw text paste. Auto-detects the log format, parses lines into structured events, runs 7 anomaly detection checks, and provides queryable results with aggregated statistics.

### Supported Log Formats

| Format          | Detection Method                            | Example                                                    |
|-----------------|---------------------------------------------|------------------------------------------------------------|
| syslog          | `^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`    | `Jan  5 14:23:01 web sshd[1234]: Accepted publickey`       |
| auth            | syslog pattern + auth keywords (sshd, pam)  | `Jan  5 14:23:01 web sshd[1234]: Failed password for root` |
| apache_access   | `^\d+\.\d+\.\d+\.\d+` + combined log regex | `10.0.0.1 - - [05/Jan/2025:14:23:01] "GET / HTTP/1.1" 200` |
| nginx_access    | Similar to apache, slightly different format | `10.0.0.1 - - [05/Jan/2025:14:23:01] "GET / HTTP/1.1" 200` |
| apache_error    | `^\[.*\]\s+\[.*:?\w+\]`                    | `[Mon Jan 05 14:23:01 2025] [error] File not found`        |
| nginx_error     | `^\d{4}/\d{2}/\d{2}`                       | `2025/01/05 14:23:01 [error] 1234#0: open() failed`        |
| json            | `^{` ... `}$`                               | `{"timestamp":"...","level":"error","message":"..."}`       |

Format detection scores 50 sample lines and picks the highest-scoring format.

### Event Classification

Auth/security event types detected from message content:
- `failed_login` — failed/failure/invalid password
- `successful_login` — accepted/session opened
- `sudo` — sudo usage
- `privilege_escalation` — su, sudo, root access
- `account_change` — useradd, userdel, usermod, passwd, groupadd
- `ssh_disconnect` — disconnect, closed, bye
- `ssh_key` — publickey, authorized_key
- `firewall` — iptables, ufw, DROP, REJECT, BLOCK
- `service_start` / `service_stop` — started/stopped/enabling/disabling
- `error` — generic error/fail/crit/emerg

### Severity Classification

| Priority | Keywords                                          | HTTP Status |
|----------|---------------------------------------------------|-------------|
| CRITICAL | crit, critical, emerg, panic, fatal                | —           |
| HIGH     | error, fail, denied, reject, block, invalid        | 5xx         |
| MEDIUM   | warn, timeout, refused, retry                      | 4xx         |
| LOW      | notice, disconnect, closed                         | —           |
| INFO     | everything else                                    | 2xx, 3xx    |

### Anomaly Detection Engine

7 detection checks, run after parsing. Results sorted by severity.

| # | Check                      | Threshold               | Severity  | What It Catches                       |
|---|----------------------------|-------------------------|-----------|---------------------------------------|
| 1 | Brute Force                | ≥5 failed logins/IP     | HIGH/CRIT | SSH/FTP credential stuffing           |
| 2 | Login After Brute Force    | Success after ≥3 fails  | CRITICAL  | Potential account compromise          |
| 3 | Privilege Escalation Spike | ≥3 priv_esc events      | HIGH      | Unusual sudo/su/root activity         |
| 4 | High Error Rate            | >30% errors, ≥10 total  | HIGH      | Service degradation, misconfig        |
| 5 | Port Scan Detection        | ≥15 ports from one IP   | HIGH      | Network reconnaissance                |
| 6 | Path Enumeration           | ≥20 404s from one IP    | MEDIUM    | Directory brute force, vuln scanning  |
| 7 | Account Changes            | ≥3 account mod events   | MEDIUM    | Unauthorized user management          |

Each anomaly includes evidence (up to 5 raw log lines), count, and source IP when applicable.

### Session Management

Parsed logs are stored in-memory keyed by session ID (MD5 hash). Sessions persist for the lifetime of the backend process.

### API Endpoints

```
POST /api/v1/log-analyzer/upload           # Upload file (max 10MB)
POST /api/v1/log-analyzer/parse            # Parse raw text (max 50,000 lines)
     Body: { "raw_text": "...", "format_hint": "auth" }

GET  /api/v1/log-analyzer/sessions/{id}/events
     ?severity=high&source_ip=10.0.0.1&event_type=failed_login&search=root&limit=100&offset=0

GET  /api/v1/log-analyzer/sessions/{id}/summary     # Stats + anomalies
GET  /api/v1/log-analyzer/sessions/{id}/anomalies   # Just anomalies
GET  /api/v1/log-analyzer/sessions                   # List all sessions
DELETE /api/v1/log-analyzer/sessions/{id}            # Clean up
GET  /api/v1/log-analyzer/formats                    # Supported formats + examples
GET  /api/v1/log-analyzer/status
```

**Summary response includes:** severity breakdown, top 20 source IPs, top 10 services, top 10 event types, hourly timeline buckets, full anomaly report.

---

## What Works

- [x] Full FastAPI backend with all 3 module routers
- [x] VirusTotal v3 API integration (IP, hash, domain)
- [x] AbuseIPDB v2 API integration (IP)
- [x] Shodan REST API integration (IP host info)
- [x] AlienVault OTX API integration (IP, hash, domain)
- [x] Parallel async API calls with error isolation (one source failing doesn't crash others)
- [x] Weighted risk scoring with dynamic normalization
- [x] TCP connect scanning with configurable concurrency
- [x] Service banner grabbing with protocol-aware probes
- [x] Service identification from banner fingerprints
- [x] TCP-based ping (port 80 → 443 → 22 fallback)
- [x] Log file upload and raw text parsing
- [x] Auto-detection of 7 log formats
- [x] Regex-based structured event parsing
- [x] 7 anomaly detection checks
- [x] Event querying with filters (severity, IP, type, full-text search)
- [x] Aggregated statistics and timeline
- [x] Session management (list, query, delete)
- [x] React frontend for Threat Intel module (search, results, history, loading states)
- [x] Health check endpoint with service availability reporting
- [x] Vite dev proxy for seamless frontend ↔ backend development
- [x] CORS configuration from environment
- [x] Pydantic v2 models for all request/response schemas
- [x] Auto-detection of indicator type from raw input

## What Doesn't Work Yet

### Backend Gaps

- [ ] **No caching layer** — Every lookup hits the APIs fresh. Should add Redis or in-memory TTL cache (especially important for VT's 4 req/min free tier)
- [ ] **No rate limiting** — `slowapi` is in requirements but not wired up. Heavy usage will burn through free API quotas fast
- [ ] **No authentication** — API is wide open. Fine for localhost/lab use, not for deployment
- [ ] **No persistent storage** — Log sessions are in-memory dict. Server restart = everything gone. Needs SQLite/Postgres
- [ ] **No WebSocket streaming** — Network scans block until complete. Long scans on 1000 ports should stream results as they come in
- [ ] **No IPv6 support** — Validator regex only matches IPv4. Threat intel sources mostly support IPv6 but we don't
- [ ] **No CIDR/range scanning** — Network scanner only handles single IPs, not subnets
- [ ] **No UDP scanning** — Only TCP connect scan. UDP services (DNS, SNMP, DHCP) won't be detected
- [ ] **No OS fingerprinting** — Would need raw sockets or nmap integration
- [ ] **Shodan requires paid key for full host data** — Free tier returns limited info
- [ ] **VT timestamps are Unix epoch** — Not converted to human-readable in the response
- [ ] **No WHOIS integration** — Domain lookups don't include registration data
- [ ] **No DNS record lookup** — No A/AAAA/MX/TXT/NS resolution
- [ ] **Log parser doesn't handle multi-line logs** — Java stack traces, Python tracebacks, etc. will be split across multiple events
- [ ] **Log timeline bucketing is fragile** — Relies on string splitting for timestamp grouping, doesn't handle timezone offsets properly
- [ ] **No Windows Event Log (.evtx) support** — Would need python-evtx library
- [ ] **Anomaly thresholds are hardcoded** — Should be configurable per-session
- [ ] **No export functionality** — Can't export results to JSON/CSV/PDF from the API

### Frontend Gaps

- [ ] **Network Scanner frontend not built** — Backend is ready, frontend is a "Coming Soon" placeholder
- [ ] **Log Analyzer frontend not built** — Same situation — backend fully functional, no UI
- [ ] **No dark/light theme toggle** — Hardcoded dark theme
- [ ] **No responsive mobile layout** — Sidebar and cards don't collapse well on small screens
- [ ] **Scan history is ephemeral** — Stored in React state, lost on refresh. Should use localStorage or backend persistence
- [ ] **No bulk IOC search** — Can only query one indicator at a time
- [ ] **No export/download buttons** — Can't save results
- [ ] **No error retry UI** — Failed API calls just show error, no retry button
- [ ] **No settings panel** — Can't configure API timeout, concurrent connections, etc. from the UI
- [ ] **No keyboard shortcuts** — Enter-to-search works, but no Ctrl+K spotlight, Esc to clear, etc.

### Infra / DX Gaps

- [ ] **No Docker setup** — No Dockerfile or docker-compose.yml
- [ ] **No tests** — Zero unit or integration tests
- [ ] **No CI/CD** — No GitHub Actions, no linting pipeline
- [ ] **No production WSGI config** — Would need gunicorn + uvicorn workers for real deployment
- [ ] **No API documentation beyond Swagger** — FastAPI auto-generates /docs but there's no standalone API reference
- [ ] **No logging configuration** — Python logger is referenced but never configured with handlers/formatters
- [ ] **No .gitignore** — Missing from project root

---

## Setup

### Prerequisites

- Python 3.11+
- Node.js 18+
- API keys (see below)

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # Then edit .env with your keys
uvicorn app.main:app --reload --port 8000
```

Backend runs at `http://localhost:8000`. Swagger docs at `/docs`, ReDoc at `/redoc`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`. Vite proxies `/api/*` to the backend.

### API Keys

| Service        | Free Tier         | Rate Limit        | Get Key                                       |
|----------------|-------------------|--------------------|-----------------------------------------------|
| VirusTotal     | Free              | 4 requests/min     | https://www.virustotal.com/gui/join-us         |
| AbuseIPDB      | Free              | 1,000 requests/day | https://www.abuseipdb.com/register             |
| Shodan         | Free (limited)    | 1 request/sec      | https://account.shodan.io/register             |
| AlienVault OTX | Free (unlimited)  | No hard limit      | https://otx.alienvault.com/api                 |

**Graceful degradation:** Missing API keys don't crash anything. The aggregator skips unconfigured sources and scores using only what's available. The `/health` endpoint reports which sources are active.

---

## Tech Stack

| Layer     | Tech                | Why                                                    |
|-----------|---------------------|--------------------------------------------------------|
| Backend   | FastAPI 0.115       | Async-native, auto OpenAPI docs, Pydantic validation   |
| HTTP      | httpx 0.28          | Async HTTP client for API calls                        |
| Schemas   | Pydantic 2.10       | Type-safe request/response models                      |
| Config    | pydantic-settings   | Env file loading with type coercion                    |
| Frontend  | React 18            | Component composition, hooks                           |
| Bundler   | Vite 6              | Fast HMR, dev proxy, ESM-native                        |
| Scanning  | asyncio + socket    | Pure stdlib TCP scanning, no nmap dependency            |
| Parsing   | re (stdlib)         | Regex-based log parsing, zero dependencies             |

**Total external Python dependencies: 6** (fastapi, uvicorn, httpx, pydantic, pydantic-settings, python-dotenv, slowapi)

**Total external JS dependencies: 2** (react, react-dom) + 2 dev (vite, @vitejs/plugin-react)

---

## License

Personal project / portfolio piece. Use however you want.
