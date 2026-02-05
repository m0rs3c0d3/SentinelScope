import asyncio
import socket
import struct
import time
import logging
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/net-scanner", tags=["Network Scanner"])
logger = logging.getLogger(__name__)

# --- Common service banners / port mappings ---
WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 119: "NNTP", 123: "NTP",
    135: "MSRPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 515: "LPD", 587: "Submission",
    631: "IPP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS", 1433: "MSSQL", 1434: "MSSQL-UDP", 1521: "Oracle",
    1723: "PPTP", 2049: "NFS", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 5985: "WinRM", 6379: "Redis",
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9200: "Elasticsearch", 9300: "Elasticsearch-Transport",
    27017: "MongoDB", 11211: "Memcached",
}

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 119, 135, 139, 143, 161, 179,
    389, 443, 445, 465, 514, 515, 587, 631, 636, 993, 995,
    1080, 1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
    3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 8888,
    9200, 9300, 27017, 11211,
]

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443]


# --- Request / Response Models ---

class ScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None
    preset: str = "top20"  # "top20", "top100", "custom"
    timeout: float = 1.5
    grab_banners: bool = True
    max_concurrent: int = 50


class PortResult(BaseModel):
    port: int
    state: str  # "open", "closed", "filtered"
    service: str | None = None
    banner: str | None = None
    latency_ms: float | None = None


class ScanResponse(BaseModel):
    target: str
    ip: str | None = None
    hostname: str | None = None
    ports_scanned: int
    open_ports: int
    results: list[PortResult]
    scan_time_ms: float
    errors: list[str] = []


class PingResult(BaseModel):
    target: str
    ip: str | None = None
    alive: bool
    latency_ms: float | None = None
    method: str


# --- Helpers ---

def resolve_target(target: str) -> tuple[str, str | None]:
    """Resolve hostname to IP. Returns (ip, hostname) or raises."""
    target = target.strip().lower()
    # Strip protocol if accidentally included
    for prefix in ("http://", "https://", "ftp://"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.rstrip("/").split("/")[0]  # remove paths

    try:
        ip = socket.gethostbyname(target)
        hostname = target if ip != target else None
        return ip, hostname
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Cannot resolve hostname: {target}")


async def tcp_connect_scan(ip: str, port: int, timeout: float) -> PortResult:
    """Attempt a TCP connect to a single port."""
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        latency = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return PortResult(
            port=port,
            state="open",
            service=WELL_KNOWN_PORTS.get(port),
            latency_ms=round(latency, 2),
        )
    except asyncio.TimeoutError:
        return PortResult(port=port, state="filtered", service=WELL_KNOWN_PORTS.get(port))
    except (ConnectionRefusedError, ConnectionResetError):
        return PortResult(port=port, state="closed", service=WELL_KNOWN_PORTS.get(port))
    except OSError:
        return PortResult(port=port, state="filtered", service=WELL_KNOWN_PORTS.get(port))


async def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str | None:
    """Try to grab a service banner from an open port."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )

        # Some services send a banner immediately, others need a nudge
        banner = None
        try:
            data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
            if data:
                banner = data.decode("utf-8", errors="replace").strip()
        except asyncio.TimeoutError:
            # Try sending a probe for HTTP-like services
            if port in (80, 8080, 8443, 8888, 443):
                writer.write(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                    if data:
                        banner = data.decode("utf-8", errors="replace").strip()
                except asyncio.TimeoutError:
                    pass
            else:
                # Generic probe
                writer.write(b"\r\n")
                await writer.drain()
                try:
                    data = await asyncio.wait_for(reader.read(512), timeout=1.0)
                    if data:
                        banner = data.decode("utf-8", errors="replace").strip()
                except asyncio.TimeoutError:
                    pass

        writer.close()
        await writer.wait_closed()

        if banner:
            # Truncate and clean
            banner = banner[:500].replace("\x00", "")
            # Extract useful first line for noisy banners
            lines = [l for l in banner.split("\n") if l.strip()]
            if lines:
                return lines[0][:200]
        return None

    except Exception:
        return None


async def tcp_ping(ip: str, port: int = 80, timeout: float = 3.0) -> tuple[bool, float | None]:
    """TCP-based ping (SYN to common port)."""
    start = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        latency = (time.monotonic() - start) * 1000
        writer.close()
        await writer.wait_closed()
        return True, round(latency, 2)
    except Exception:
        return False, None


# --- Endpoints ---

@router.get("/status")
async def scanner_status():
    return {"module": "net-scanner", "status": "active", "version": "1.0.0"}


@router.post("/scan", response_model=ScanResponse)
async def scan_target(request: ScanRequest):
    """
    Run a TCP connect scan against a target.

    - **target**: IP address or hostname
    - **preset**: "top20" (fast), "top100" (thorough), or "custom" (use ports list)
    - **ports**: Custom port list (only used when preset="custom")
    - **timeout**: Per-port timeout in seconds (default 1.5)
    - **grab_banners**: Attempt banner grabbing on open ports (default true)
    - **max_concurrent**: Max parallel connections (default 50, max 200)
    """
    # Resolve target
    ip, hostname = resolve_target(request.target)

    # Determine ports
    if request.preset == "custom" and request.ports:
        ports = sorted(set(p for p in request.ports if 1 <= p <= 65535))
        if not ports:
            raise HTTPException(status_code=400, detail="No valid ports provided (1-65535)")
        if len(ports) > 1000:
            raise HTTPException(status_code=400, detail="Maximum 1000 ports per scan")
    elif request.preset == "top100":
        ports = TOP_100_PORTS
    else:
        ports = TOP_20_PORTS

    # Clamp settings
    timeout = max(0.3, min(request.timeout, 10.0))
    max_concurrent = max(1, min(request.max_concurrent, 200))

    # Run scan with semaphore for concurrency control
    semaphore = asyncio.Semaphore(max_concurrent)
    errors = []

    async def scan_port(port):
        async with semaphore:
            return await tcp_connect_scan(ip, port, timeout)

    start_time = time.monotonic()

    try:
        results = await asyncio.gather(*[scan_port(p) for p in ports])
    except Exception as e:
        logger.error(f"Scan failed for {ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    # Banner grabbing on open ports
    open_results = [r for r in results if r.state == "open"]

    if request.grab_banners and open_results:
        banner_semaphore = asyncio.Semaphore(10)

        async def fetch_banner(result):
            async with banner_semaphore:
                banner = await grab_banner(ip, result.port, timeout=2.0)
                if banner:
                    result.banner = banner
                    # Try to identify service from banner if unknown
                    if not result.service:
                        result.service = identify_service(banner)

        await asyncio.gather(*[fetch_banner(r) for r in open_results])

    scan_time = (time.monotonic() - start_time) * 1000

    return ScanResponse(
        target=request.target,
        ip=ip,
        hostname=hostname,
        ports_scanned=len(ports),
        open_ports=len(open_results),
        results=sorted([r for r in results if r.state == "open"], key=lambda r: r.port),
        scan_time_ms=round(scan_time, 2),
        errors=errors,
    )


@router.get("/scan/{target}", response_model=ScanResponse)
async def quick_scan(target: str, preset: str = "top20"):
    """GET shorthand for a quick scan with defaults."""
    request = ScanRequest(target=target, preset=preset)
    return await scan_target(request)


@router.post("/ping", response_model=PingResult)
async def ping_target(target: str):
    """
    Check if a host is alive using TCP ping (port 80, then 443).
    """
    ip, _ = resolve_target(target)

    # Try port 80 first, then 443
    for port in [80, 443, 22]:
        alive, latency = await tcp_ping(ip, port)
        if alive:
            return PingResult(
                target=target, ip=ip, alive=True,
                latency_ms=latency, method=f"TCP/{port}",
            )

    return PingResult(
        target=target, ip=ip, alive=False,
        latency_ms=None, method="TCP/80,443,22",
    )


@router.get("/ports/presets")
async def get_port_presets():
    """Return available port scan presets."""
    return {
        "top20": {"count": len(TOP_20_PORTS), "ports": TOP_20_PORTS},
        "top100": {"count": len(TOP_100_PORTS), "ports": TOP_100_PORTS},
    }


# --- Service Identification ---

def identify_service(banner: str) -> str | None:
    """Try to identify a service from its banner string."""
    b = banner.lower()
    if "ssh" in b:
        return "SSH"
    if "http" in b or "html" in b:
        return "HTTP"
    if "smtp" in b or "mail" in b or "postfix" in b:
        return "SMTP"
    if "ftp" in b or "vsftpd" in b or "proftpd" in b:
        return "FTP"
    if "mysql" in b or "mariadb" in b:
        return "MySQL"
    if "postgresql" in b:
        return "PostgreSQL"
    if "redis" in b:
        return "Redis"
    if "mongodb" in b:
        return "MongoDB"
    if "imap" in b:
        return "IMAP"
    if "pop3" in b or "pop " in b:
        return "POP3"
    if "vnc" in b or "rfb" in b:
        return "VNC"
    if "nginx" in b:
        return "HTTP (nginx)"
    if "apache" in b:
        return "HTTP (Apache)"
    if "openssl" in b or "tls" in b:
        return "TLS"
    return None
