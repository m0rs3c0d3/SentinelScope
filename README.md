# SentinelScope 

A modular cybersecurity toolkit with threat intelligence aggregation, network scanning, and log analysis.

## Architecture

```
sentinelscope/
├── backend/                # FastAPI backend
│   ├── app/
│   │   ├── main.py         # FastAPI app entry point
│   │   ├── config.py       # API keys & settings
│   │   ├── routers/        # API route handlers
│   │   │   ├── threat_intel.py
│   │   │   ├── net_scanner.py
│   │   │   └── log_analyzer.py
│   │   ├── services/       # Business logic & API integrations
│   │   │   ├── virustotal.py
│   │   │   ├── abuseipdb.py
│   │   │   ├── shodan_svc.py
│   │   │   ├── otx.py
│   │   │   └── aggregator.py
│   │   ├── models/         # Pydantic schemas
│   │   │   └── schemas.py
│   │   └── utils/          # Helpers
│   │       └── validators.py
│   ├── requirements.txt
│   └── .env.example
├── frontend/               # React frontend
│   ├── src/
│   │   ├── App.jsx
│   │   ├── index.jsx
│   │   ├── components/
│   │   │   ├── common/     # Shared UI components
│   │   │   └── modules/    # Feature modules
│   │   ├── hooks/          # Custom React hooks
│   │   ├── styles/         # Global styles
│   │   └── utils/          # Frontend helpers
│   ├── package.json
│   └── vite.config.js
└── README.md
```

## Quick Start

### 1. Backend Setup

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env      # Add your API keys
uvicorn app.main:app --reload --port 8000
```

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

App runs at `http://localhost:5173` with API at `http://localhost:8000`.

## API Keys (Free Tiers)

| Service       | Free Tier            | Get Key                                      |
|---------------|----------------------|----------------------------------------------|
| VirusTotal    | 4 req/min            | https://www.virustotal.com/gui/join-us        |
| AbuseIPDB     | 1,000 req/day        | https://www.abuseipdb.com/register            |
| Shodan        | Limited (dev: $59)   | https://account.shodan.io/register            |
| AlienVault OTX| Unlimited            | https://otx.alienvault.com/api                |

## Modules

- **Threat Intel Aggregator** ✅ — Query IPs, domains, hashes across 4 sources
- **Network Scanner** 🔜 — Port scanning, service detection, OS fingerprinting
- **Log Analyzer** 🔜 — Parse and analyze syslog, auth, web server logs
