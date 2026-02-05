import re
import hashlib
import time
import logging
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from io import StringIO
from enum import Enum
from fastapi import APIRouter, HTTPException, UploadFile, File, Query
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/log-analyzer", tags=["Log Analyzer"])
logger = logging.getLogger(__name__)

# --- In-memory store (swap for DB in production) ---
log_store: dict[str, "LogSession"] = {}


# --- Enums & Models ---

class LogFormat(str, Enum):
    SYSLOG = "syslog"
    AUTH = "auth"
    APACHE_ACCESS = "apache_access"
    APACHE_ERROR = "apache_error"
    NGINX_ACCESS = "nginx_access"
    NGINX_ERROR = "nginx_error"
    JSON = "json"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class LogEvent(BaseModel):
    line_number: int
    timestamp: str | None = None
    source_ip: str | None = None
    hostname: str | None = None
    service: str | None = None
    message: str
    severity: Severity = Severity.INFO
    event_type: str | None = None
    raw: str


class Anomaly(BaseModel):
    type: str
    severity: Severity
    description: str
    evidence: list[str] = []
    count: int = 1
    source_ip: str | None = None


class LogSession(BaseModel):
    session_id: str
    filename: str | None = None
    format_detected: LogFormat
    total_lines: int
    parsed_lines: int
    failed_lines: int
    events: list[LogEvent] = []
    anomalies: list[Anomaly] = []
    created_at: str


class UploadResponse(BaseModel):
    session_id: str
    filename: str | None = None
    format_detected: LogFormat
    total_lines: int
    parsed_lines: int
    failed_lines: int
    anomaly_count: int
    preview: list[LogEvent] = []


class ParseRequest(BaseModel):
    raw_text: str
    format_hint: LogFormat | None = None


class EventQuery(BaseModel):
    severity: Severity | None = None
    source_ip: str | None = None
    event_type: str | None = None
    search: str | None = None
    limit: int = 100
    offset: int = 0


class SummaryResponse(BaseModel):
    total_events: int
    severity_breakdown: dict[str, int]
    top_source_ips: list[dict]
    top_services: list[dict]
    top_event_types: list[dict]
    timeline: list[dict]
    anomalies: list[Anomaly]
    format_detected: LogFormat


# --- Log Parsing Patterns ---

PATTERNS = {
    LogFormat.SYSLOG: re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
    ),
    LogFormat.AUTH: re.compile(
        r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
        r"(?P<hostname>\S+)\s+"
        r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<message>.+)$"
    ),
    LogFormat.APACHE_ACCESS: re.compile(
        r'^(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    ),
    LogFormat.NGINX_ACCESS: re.compile(
        r'^(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+-\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
        r'(?P<status>\d{3})\s+(?P<bytes>\d+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    ),
    LogFormat.APACHE_ERROR: re.compile(
        r'^\[(?P<timestamp>[^\]]+)\]\s+'
        r'\[(?:(?P<module>\w+):)?(?P<level>\w+)\]\s+'
        r'(?:\[pid\s+(?P<pid>\d+)\]\s+)?'
        r'(?P<message>.+)$'
    ),
    LogFormat.NGINX_ERROR: re.compile(
        r'^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
        r'\[(?P<level>\w+)\]\s+'
        r'(?P<pid>\d+)#\d+:\s+'
        r'(?P<message>.+)$'
    ),
}

IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# Auth-specific patterns for event classification
AUTH_PATTERNS = {
    "failed_login": re.compile(r"(?:failed|failure|invalid|bad)\s+(?:password|login|auth)", re.I),
    "successful_login": re.compile(r"(?:accepted|session opened|successful login)", re.I),
    "sudo": re.compile(r"sudo[:\s]", re.I),
    "privilege_escalation": re.compile(r"(?:su\[|sudo|root|privilege|escalat)", re.I),
    "account_change": re.compile(r"(?:useradd|userdel|usermod|passwd|chpasswd|groupadd)", re.I),
    "ssh_disconnect": re.compile(r"(?:disconnect|closed|bye)", re.I),
    "ssh_key": re.compile(r"(?:publickey|authorized_key)", re.I),
    "firewall": re.compile(r"(?:iptables|ufw|firewall|DROP|REJECT|BLOCK)", re.I),
    "service_start": re.compile(r"(?:started|starting|enabling|reloaded)", re.I),
    "service_stop": re.compile(r"(?:stopped|stopping|disabling|shutdown)", re.I),
    "error": re.compile(r"(?:error|fail|crit|emerg|alert|panic)", re.I),
}

HTTP_SEVERITY = {
    "2": Severity.INFO,
    "3": Severity.INFO,
    "4": Severity.MEDIUM,
    "5": Severity.HIGH,
}


# --- Format Detection ---

def detect_format(lines: list[str]) -> LogFormat:
    """Auto-detect log format from sample lines."""
    if not lines:
        return LogFormat.UNKNOWN

    sample = lines[:50]
    scores = Counter()

    for line in sample:
        line = line.strip()
        if not line:
            continue

        # JSON detection
        if line.startswith("{") and line.endswith("}"):
            scores[LogFormat.JSON] += 2

        # Apache/nginx access log (starts with IP)
        if re.match(r'^\d+\.\d+\.\d+\.\d+\s', line):
            if PATTERNS[LogFormat.APACHE_ACCESS].match(line):
                scores[LogFormat.APACHE_ACCESS] += 2
            elif PATTERNS[LogFormat.NGINX_ACCESS].match(line):
                scores[LogFormat.NGINX_ACCESS] += 2

        # Apache error log
        if line.startswith("[") and PATTERNS[LogFormat.APACHE_ERROR].match(line):
            scores[LogFormat.APACHE_ERROR] += 2

        # Nginx error log (starts with date YYYY/MM/DD)
        if re.match(r'^\d{4}/\d{2}/\d{2}', line):
            scores[LogFormat.NGINX_ERROR] += 2

        # Syslog / auth (starts with month day time)
        if re.match(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}', line):
            if any(kw in line.lower() for kw in ["sshd", "pam_", "sudo", "login", "auth", "passwd"]):
                scores[LogFormat.AUTH] += 2
            else:
                scores[LogFormat.SYSLOG] += 1

    if not scores:
        return LogFormat.UNKNOWN

    return scores.most_common(1)[0][0]


# --- Line Parsing ---

def parse_line(line: str, line_num: int, fmt: LogFormat) -> LogEvent | None:
    """Parse a single log line into a structured LogEvent."""
    line = line.strip()
    if not line:
        return None

    # JSON logs
    if fmt == LogFormat.JSON:
        return _parse_json_line(line, line_num)

    # Regex-based parsing
    pattern = PATTERNS.get(fmt)
    if not pattern:
        return LogEvent(
            line_number=line_num, message=line, raw=line,
            severity=classify_severity(line, fmt),
        )

    match = pattern.match(line)
    if not match:
        # Fallback: still capture the line
        return LogEvent(
            line_number=line_num, message=line, raw=line,
            severity=classify_severity(line, fmt),
            source_ip=_extract_ip(line),
        )

    groups = match.groupdict()

    # Extract source IP from message if not in pattern
    source_ip = groups.get("source_ip") or _extract_ip(groups.get("message", ""))

    # Build event type
    event_type = classify_event(groups.get("message", ""), fmt)

    # HTTP status-based fields
    status = groups.get("status")
    message = groups.get("message", "")
    if status:
        method = groups.get("method", "")
        path = groups.get("path", "")
        message = f"{method} {path} → {status} ({groups.get('bytes', '-')} bytes)"

    return LogEvent(
        line_number=line_num,
        timestamp=groups.get("timestamp"),
        source_ip=source_ip,
        hostname=groups.get("hostname"),
        service=groups.get("service"),
        message=message,
        severity=classify_severity(line, fmt, status=status),
        event_type=event_type,
        raw=line,
    )


def _parse_json_line(line: str, line_num: int) -> LogEvent | None:
    """Parse a JSON-formatted log line."""
    import json
    try:
        data = json.loads(line)
        return LogEvent(
            line_number=line_num,
            timestamp=data.get("timestamp") or data.get("time") or data.get("@timestamp"),
            source_ip=data.get("source_ip") or data.get("remote_addr") or data.get("clientip"),
            hostname=data.get("hostname") or data.get("host"),
            service=data.get("service") or data.get("program") or data.get("app"),
            message=data.get("message") or data.get("msg") or str(data),
            severity=_json_severity(data),
            event_type=data.get("event_type") or data.get("type"),
            raw=line,
        )
    except (json.JSONDecodeError, ValueError):
        return LogEvent(line_number=line_num, message=line, raw=line)


def _json_severity(data: dict) -> Severity:
    level = str(data.get("level") or data.get("severity") or data.get("loglevel") or "").lower()
    if level in ("critical", "fatal", "emerg", "panic"):
        return Severity.CRITICAL
    if level in ("error", "err", "high"):
        return Severity.HIGH
    if level in ("warning", "warn", "medium"):
        return Severity.MEDIUM
    if level in ("notice", "low"):
        return Severity.LOW
    return Severity.INFO


def _extract_ip(text: str) -> str | None:
    """Extract the first IP address from text."""
    match = IP_PATTERN.search(text)
    if match:
        ip = match.group(1)
        # Skip loopback and broadcast
        if not ip.startswith("127.") and ip != "255.255.255.255":
            return ip
    return None


def classify_severity(line: str, fmt: LogFormat, status: str | None = None) -> Severity:
    """Determine severity from log content."""
    lower = line.lower()

    # HTTP status codes
    if status:
        return HTTP_SEVERITY.get(status[0], Severity.INFO)

    # Keyword-based
    if any(kw in lower for kw in ["crit", "critical", "emerg", "panic", "fatal"]):
        return Severity.CRITICAL
    if any(kw in lower for kw in ["error", "fail", "denied", "reject", "block", "invalid"]):
        return Severity.HIGH
    if any(kw in lower for kw in ["warn", "timeout", "refused", "retry"]):
        return Severity.MEDIUM
    if any(kw in lower for kw in ["notice", "disconnect", "closed"]):
        return Severity.LOW
    return Severity.INFO


def classify_event(message: str, fmt: LogFormat) -> str | None:
    """Classify the event type based on message content."""
    for event_type, pattern in AUTH_PATTERNS.items():
        if pattern.search(message):
            return event_type
    return None


# --- Anomaly Detection ---

def detect_anomalies(events: list[LogEvent]) -> list[Anomaly]:
    """Analyze parsed events for suspicious patterns."""
    anomalies = []

    # 1. Brute force detection (failed logins from same IP)
    failed_by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "failed_login" and e.source_ip:
            failed_by_ip[e.source_ip].append(e)

    for ip, failures in failed_by_ip.items():
        if len(failures) >= 5:
            anomalies.append(Anomaly(
                type="brute_force",
                severity=Severity.CRITICAL if len(failures) >= 20 else Severity.HIGH,
                description=f"Possible brute force: {len(failures)} failed login attempts from {ip}",
                evidence=[f.raw[:150] for f in failures[:5]],
                count=len(failures),
                source_ip=ip,
            ))

    # 2. Successful login after failures (potential compromise)
    success_by_ip = defaultdict(list)
    for e in events:
        if e.event_type == "successful_login" and e.source_ip:
            success_by_ip[e.source_ip].append(e)

    for ip in failed_by_ip:
        if ip in success_by_ip and len(failed_by_ip[ip]) >= 3:
            anomalies.append(Anomaly(
                type="login_after_brute_force",
                severity=Severity.CRITICAL,
                description=f"Successful login from {ip} after {len(failed_by_ip[ip])} failed attempts — possible compromise",
                evidence=[success_by_ip[ip][0].raw[:150]],
                count=1,
                source_ip=ip,
            ))

    # 3. Privilege escalation
    priv_events = [e for e in events if e.event_type == "privilege_escalation"]
    if len(priv_events) >= 3:
        anomalies.append(Anomaly(
            type="privilege_escalation_spike",
            severity=Severity.HIGH,
            description=f"{len(priv_events)} privilege escalation events detected",
            evidence=[e.raw[:150] for e in priv_events[:3]],
            count=len(priv_events),
        ))

    # 4. High error rate
    errors = [e for e in events if e.severity in (Severity.HIGH, Severity.CRITICAL)]
    total = len(events) or 1
    error_rate = len(errors) / total
    if error_rate > 0.3 and len(errors) >= 10:
        anomalies.append(Anomaly(
            type="high_error_rate",
            severity=Severity.HIGH,
            description=f"High error rate: {len(errors)}/{total} events ({error_rate:.0%}) are errors",
            evidence=[e.raw[:150] for e in errors[:3]],
            count=len(errors),
        ))

    # 5. Port scan indicators (many different ports from same IP in access logs)
    ports_by_ip = defaultdict(set)
    for e in events:
        if e.source_ip and e.message:
            # Look for port references in the message
            port_matches = re.findall(r':(\d{2,5})\b', e.raw)
            for p in port_matches:
                ports_by_ip[e.source_ip].add(p)

    for ip, ports in ports_by_ip.items():
        if len(ports) >= 15:
            anomalies.append(Anomaly(
                type="port_scan",
                severity=Severity.HIGH,
                description=f"Possible port scan from {ip}: activity on {len(ports)} different ports",
                count=len(ports),
                source_ip=ip,
            ))

    # 6. HTTP scan / path enumeration
    paths_by_ip = defaultdict(set)
    status_404_by_ip = defaultdict(int)
    for e in events:
        if e.source_ip and "404" in (e.message or "") and e.event_type is None:
            status_404_by_ip[e.source_ip] += 1

    for ip, count in status_404_by_ip.items():
        if count >= 20:
            anomalies.append(Anomaly(
                type="path_enumeration",
                severity=Severity.MEDIUM,
                description=f"Possible directory/path enumeration from {ip}: {count} 404 responses",
                count=count,
                source_ip=ip,
            ))

    # 7. Account changes
    acct_events = [e for e in events if e.event_type == "account_change"]
    if len(acct_events) >= 3:
        anomalies.append(Anomaly(
            type="account_changes",
            severity=Severity.MEDIUM,
            description=f"{len(acct_events)} account modification events detected",
            evidence=[e.raw[:150] for e in acct_events[:3]],
            count=len(acct_events),
        ))

    return sorted(anomalies, key=lambda a: {
        Severity.CRITICAL: 0, Severity.HIGH: 1,
        Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4,
    }.get(a.severity, 5))


# --- Session Helpers ---

def create_session(lines: list[str], fmt: LogFormat, filename: str | None = None) -> LogSession:
    """Parse all lines and create a session with anomaly detection."""
    events = []
    failed = 0

    for i, line in enumerate(lines, start=1):
        event = parse_line(line, i, fmt)
        if event:
            events.append(event)
        elif line.strip():
            failed += 1

    anomalies = detect_anomalies(events)

    session_id = hashlib.md5(f"{time.time()}{filename}".encode()).hexdigest()[:12]

    return LogSession(
        session_id=session_id,
        filename=filename,
        format_detected=fmt,
        total_lines=len(lines),
        parsed_lines=len(events),
        failed_lines=failed,
        events=events,
        anomalies=anomalies,
        created_at=datetime.utcnow().isoformat(),
    )


# --- Endpoints ---

@router.get("/status")
async def analyzer_status():
    return {
        "module": "log-analyzer",
        "status": "active",
        "version": "1.0.0",
        "active_sessions": len(log_store),
        "supported_formats": [f.value for f in LogFormat if f != LogFormat.UNKNOWN],
    }


@router.post("/upload", response_model=UploadResponse)
async def upload_log_file(file: UploadFile = File(...)):
    """
    Upload a log file for analysis.

    Supports: syslog, auth.log, Apache/nginx access & error logs, JSON logs.
    Format is auto-detected from content. Max file size: 10MB.
    """
    # Read file
    try:
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large (max 10MB)")
        text = content.decode("utf-8", errors="replace")
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File must be UTF-8 text")

    lines = text.splitlines()
    if not lines:
        raise HTTPException(status_code=400, detail="File is empty")

    # Detect and parse
    fmt = detect_format(lines)
    session = create_session(lines, fmt, filename=file.filename)

    # Store
    log_store[session.session_id] = session

    return UploadResponse(
        session_id=session.session_id,
        filename=session.filename,
        format_detected=session.format_detected,
        total_lines=session.total_lines,
        parsed_lines=session.parsed_lines,
        failed_lines=session.failed_lines,
        anomaly_count=len(session.anomalies),
        preview=session.events[:10],
    )


@router.post("/parse", response_model=UploadResponse)
async def parse_raw_text(request: ParseRequest):
    """
    Parse raw log text directly (no file upload needed).
    Useful for pasting log snippets.
    """
    lines = request.raw_text.splitlines()
    if not lines:
        raise HTTPException(status_code=400, detail="No log data provided")
    if len(lines) > 50000:
        raise HTTPException(status_code=413, detail="Too many lines (max 50,000)")

    fmt = request.format_hint or detect_format(lines)
    session = create_session(lines, fmt, filename="raw_input")
    log_store[session.session_id] = session

    return UploadResponse(
        session_id=session.session_id,
        filename=session.filename,
        format_detected=session.format_detected,
        total_lines=session.total_lines,
        parsed_lines=session.parsed_lines,
        failed_lines=session.failed_lines,
        anomaly_count=len(session.anomalies),
        preview=session.events[:10],
    )


@router.get("/sessions/{session_id}/events", response_model=list[LogEvent])
async def get_events(
    session_id: str,
    severity: Severity | None = None,
    source_ip: str | None = None,
    event_type: str | None = None,
    search: str | None = None,
    limit: int = Query(default=100, le=1000),
    offset: int = Query(default=0, ge=0),
):
    """
    Query parsed events with optional filters.

    - **severity**: Filter by severity level
    - **source_ip**: Filter by source IP
    - **event_type**: Filter by event type (failed_login, sudo, etc.)
    - **search**: Full-text search in message and raw fields
    - **limit/offset**: Pagination
    """
    session = log_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events = session.events

    if severity:
        events = [e for e in events if e.severity == severity]
    if source_ip:
        events = [e for e in events if e.source_ip == source_ip]
    if event_type:
        events = [e for e in events if e.event_type == event_type]
    if search:
        search_lower = search.lower()
        events = [e for e in events if search_lower in e.message.lower() or search_lower in e.raw.lower()]

    return events[offset:offset + limit]


@router.get("/sessions/{session_id}/summary", response_model=SummaryResponse)
async def get_summary(session_id: str):
    """
    Get aggregated statistics and anomaly report for a log session.
    """
    session = log_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    events = session.events

    # Severity breakdown
    severity_counts = Counter(e.severity.value for e in events)

    # Top source IPs
    ip_counts = Counter(e.source_ip for e in events if e.source_ip)
    top_ips = [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(20)]

    # Top services
    svc_counts = Counter(e.service for e in events if e.service)
    top_services = [{"service": svc, "count": count} for svc, count in svc_counts.most_common(10)]

    # Top event types
    type_counts = Counter(e.event_type for e in events if e.event_type)
    top_types = [{"event_type": et, "count": count} for et, count in type_counts.most_common(10)]

    # Timeline (group by hour from timestamps)
    timeline = _build_timeline(events)

    return SummaryResponse(
        total_events=len(events),
        severity_breakdown=dict(severity_counts),
        top_source_ips=top_ips,
        top_services=top_services,
        top_event_types=top_types,
        timeline=timeline,
        anomalies=session.anomalies,
        format_detected=session.format_detected,
    )


@router.get("/sessions/{session_id}/anomalies", response_model=list[Anomaly])
async def get_anomalies(session_id: str):
    """Get detected anomalies for a session."""
    session = log_store.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session.anomalies


@router.get("/sessions")
async def list_sessions():
    """List all active log analysis sessions."""
    return [
        {
            "session_id": s.session_id,
            "filename": s.filename,
            "format": s.format_detected.value,
            "total_lines": s.total_lines,
            "anomaly_count": len(s.anomalies),
            "created_at": s.created_at,
        }
        for s in log_store.values()
    ]


@router.delete("/sessions/{session_id}")
async def delete_session(session_id: str):
    """Delete a log analysis session."""
    if session_id not in log_store:
        raise HTTPException(status_code=404, detail="Session not found")
    del log_store[session_id]
    return {"deleted": session_id}


@router.get("/formats")
async def supported_formats():
    """List supported log formats with example patterns."""
    return {
        "syslog": {
            "description": "Standard syslog format (RFC 3164)",
            "example": "Jan  5 14:23:01 webserver sshd[1234]: Accepted publickey for admin",
        },
        "auth": {
            "description": "Authentication logs (auth.log, secure)",
            "example": "Jan  5 14:23:01 webserver sshd[1234]: Failed password for root from 10.0.0.1",
        },
        "apache_access": {
            "description": "Apache combined access log",
            "example": '10.0.0.1 - - [05/Jan/2025:14:23:01 +0000] "GET /admin HTTP/1.1" 404 209',
        },
        "nginx_access": {
            "description": "Nginx access log (default format)",
            "example": '10.0.0.1 - - [05/Jan/2025:14:23:01 +0000] "GET / HTTP/1.1" 200 612',
        },
        "apache_error": {
            "description": "Apache error log",
            "example": "[Mon Jan 05 14:23:01 2025] [error] [pid 1234] File not found: /var/www/admin",
        },
        "nginx_error": {
            "description": "Nginx error log",
            "example": "2025/01/05 14:23:01 [error] 1234#0: open() failed (2: No such file)",
        },
        "json": {
            "description": "JSON-formatted logs (structured logging)",
            "example": '{"timestamp":"2025-01-05T14:23:01Z","level":"error","message":"connection refused"}',
        },
    }


# --- Helpers ---

def _build_timeline(events: list[LogEvent]) -> list[dict]:
    """Group events into time buckets for timeline visualization."""
    buckets = defaultdict(lambda: {"total": 0, "errors": 0})

    for e in events:
        ts = e.timestamp
        if not ts:
            continue

        # Normalize to hour bucket — handle common formats
        hour_key = None
        # Syslog: "Jan  5 14:23:01"
        if re.match(r'\w{3}\s+\d', ts):
            parts = ts.split(":")
            if len(parts) >= 2:
                hour_key = f"{parts[0]}:00"
        # Apache/nginx: "05/Jan/2025:14:23:01 +0000"
        elif "/" in ts and ":" in ts:
            try:
                hour_key = ts.split(":")[0] + ":00"
            except (IndexError, ValueError):
                pass
        # ISO / nginx error: "2025/01/05 14:23:01"
        elif re.match(r'\d{4}', ts):
            parts = ts.split(":")
            if len(parts) >= 2:
                hour_key = f"{parts[0]}:00"

        if hour_key:
            buckets[hour_key]["total"] += 1
            if e.severity in (Severity.HIGH, Severity.CRITICAL):
                buckets[hour_key]["errors"] += 1

    return [
        {"time": k, "total": v["total"], "errors": v["errors"]}
        for k, v in sorted(buckets.items())
    ]
