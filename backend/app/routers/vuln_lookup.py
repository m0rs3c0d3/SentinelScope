import asyncio
import re
import logging
from datetime import datetime
from enum import Enum
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
import httpx

router = APIRouter(prefix="/api/v1/vuln-lookup", tags=["Vulnerability Lookup"])
app = None  # populated in __main__
logger = logging.getLogger(__name__)

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOIT_DB_SEARCH = "https://exploit-db.com/search"
# NVD rate limit: 5 req/30s without key, 50 req/30s with key


# --- Models ---

class CVSSMetrics(BaseModel):
    version: str
    score: float
    severity: str
    vector: str | None = None
    attack_vector: str | None = None
    attack_complexity: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    scope: str | None = None
    confidentiality: str | None = None
    integrity: str | None = None
    availability: str | None = None


class Reference(BaseModel):
    url: str
    source: str | None = None
    tags: list[str] = []


class ExploitInfo(BaseModel):
    exploit_db_id: str | None = None
    title: str | None = None
    url: str | None = None
    platform: str | None = None
    type: str | None = None
    has_public_exploit: bool = False


class Weakness(BaseModel):
    cwe_id: str
    name: str | None = None


class CVEResult(BaseModel):
    cve_id: str
    description: str
    published: str | None = None
    last_modified: str | None = None
    status: str | None = None
    cvss: CVSSMetrics | None = None
    weaknesses: list[Weakness] = []
    references: list[Reference] = []
    affected_products: list[str] = []
    exploit_info: ExploitInfo | None = None


class SearchResponse(BaseModel):
    query: str
    total_results: int
    results: list[CVEResult]
    search_time_ms: float


class CVEDetailResponse(BaseModel):
    cve: CVEResult
    related_cves: list[str] = []


class ProductVulnResponse(BaseModel):
    product: str
    cpe_match: str | None = None
    total_cves: int
    critical: int
    high: int
    medium: int
    low: int
    results: list[CVEResult]


class StatsResponse(BaseModel):
    severity: str
    count: int


# --- NVD API Client ---

async def _nvd_request(params: dict, timeout: float = 20.0) -> dict:
    """Make a request to the NVD CVE API with error handling."""
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(NVD_BASE, params=params)
            resp.raise_for_status()
            return resp.json()
        except httpx.TimeoutException:
            raise HTTPException(status_code=504, detail="NVD API timeout — try again in a few seconds")
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                raise HTTPException(status_code=429, detail="NVD rate limit hit — wait 30 seconds and retry")
            raise HTTPException(status_code=502, detail=f"NVD API error: {e.response.status_code}")


def _parse_cve(item: dict) -> CVEResult:
    """Parse a single CVE item from NVD API response into our model."""
    cve_data = item.get("cve", {})
    cve_id = cve_data.get("id", "UNKNOWN")

    # Description (prefer English)
    descriptions = cve_data.get("descriptions", [])
    desc = "No description available."
    for d in descriptions:
        if d.get("lang") == "en":
            desc = d.get("value", desc)
            break

    # CVSS — try v3.1 first, then v3.0, then v2
    cvss = _extract_cvss(cve_data.get("metrics", {}))

    # Weaknesses (CWE)
    weaknesses = []
    for w in cve_data.get("weaknesses", []):
        for wd in w.get("description", []):
            if wd.get("lang") == "en":
                cwe_id = wd.get("value", "")
                if cwe_id.startswith("CWE-"):
                    weaknesses.append(Weakness(cwe_id=cwe_id, name=_cwe_name(cwe_id)))

    # References
    references = []
    for ref in cve_data.get("references", [])[:15]:
        references.append(Reference(
            url=ref.get("url", ""),
            source=ref.get("source"),
            tags=ref.get("tags", []),
        ))

    # Affected products from CPE matches
    affected = _extract_affected_products(cve_data.get("configurations", []))

    # Exploit info from references
    exploit_info = _check_exploits(references)

    return CVEResult(
        cve_id=cve_id,
        description=desc,
        published=cve_data.get("published", "")[:10],
        last_modified=cve_data.get("lastModified", "")[:10],
        status=cve_data.get("vulnStatus"),
        cvss=cvss,
        weaknesses=weaknesses,
        references=references,
        affected_products=affected[:20],
        exploit_info=exploit_info,
    )


def _extract_cvss(metrics: dict) -> CVSSMetrics | None:
    """Extract best available CVSS score."""
    # Try v3.1
    for entry in metrics.get("cvssMetricV31", []):
        data = entry.get("cvssData", {})
        return CVSSMetrics(
            version="3.1",
            score=data.get("baseScore", 0),
            severity=data.get("baseSeverity", "NONE"),
            vector=data.get("vectorString"),
            attack_vector=data.get("attackVector"),
            attack_complexity=data.get("attackComplexity"),
            privileges_required=data.get("privilegesRequired"),
            user_interaction=data.get("userInteraction"),
            scope=data.get("scope"),
            confidentiality=data.get("confidentialityImpact"),
            integrity=data.get("integrityImpact"),
            availability=data.get("availabilityImpact"),
        )

    # Try v3.0
    for entry in metrics.get("cvssMetricV30", []):
        data = entry.get("cvssData", {})
        return CVSSMetrics(
            version="3.0",
            score=data.get("baseScore", 0),
            severity=data.get("baseSeverity", "NONE"),
            vector=data.get("vectorString"),
            attack_vector=data.get("attackVector"),
            attack_complexity=data.get("attackComplexity"),
            privileges_required=data.get("privilegesRequired"),
            user_interaction=data.get("userInteraction"),
            scope=data.get("scope"),
            confidentiality=data.get("confidentialityImpact"),
            integrity=data.get("integrityImpact"),
            availability=data.get("availabilityImpact"),
        )

    # Fallback to v2
    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData", {})
        score = data.get("baseScore", 0)
        return CVSSMetrics(
            version="2.0",
            score=score,
            severity=_cvss2_severity(score),
            vector=data.get("vectorString"),
            attack_vector=data.get("accessVector"),
            attack_complexity=data.get("accessComplexity"),
        )

    return None


def _cvss2_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0: return "LOW"
    return "NONE"


def _extract_affected_products(configurations: list) -> list[str]:
    """Extract human-readable product names from CPE configurations."""
    products = set()
    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                # CPE format: cpe:2.3:a:vendor:product:version:...
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3].replace("_", " ").title()
                    product = parts[4].replace("_", " ").title()
                    version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
                    entry = f"{vendor} {product}"
                    if version:
                        entry += f" {version}"
                    # Version range
                    start = match.get("versionStartIncluding", "")
                    end = match.get("versionEndExcluding", match.get("versionEndIncluding", ""))
                    if start and end:
                        entry += f" ({start} – {end})"
                    elif end:
                        entry += f" (< {end})"
                    products.add(entry)
    return sorted(products)


def _check_exploits(references: list[Reference]) -> ExploitInfo:
    """Check references for known exploit sources."""
    info = ExploitInfo(has_public_exploit=False)

    for ref in references:
        url = ref.url.lower()
        tags = [t.lower() for t in ref.tags]

        # Exploit-DB
        edb_match = re.search(r'exploit-db\.com/exploits/(\d+)', url)
        if edb_match:
            info.exploit_db_id = edb_match.group(1)
            info.url = ref.url
            info.has_public_exploit = True

        # GitHub PoC
        if "github.com" in url and any(t in tags for t in ["exploit", "third party advisory"]):
            if not info.url:
                info.url = ref.url
            info.has_public_exploit = True

        # Packet Storm
        if "packetstormsecurity" in url:
            if not info.url:
                info.url = ref.url
            info.has_public_exploit = True

        # Tag-based detection
        if "exploit" in tags:
            info.has_public_exploit = True

    return info


# --- CWE Name Lookup (common ones) ---

CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Classic Buffer Overflow",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Hard-coded Credentials",
    "CWE-862": "Missing Authorization",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def _cwe_name(cwe_id: str) -> str | None:
    return CWE_NAMES.get(cwe_id)


# --- Endpoints ---

@router.get("/status")
async def vuln_status():
    return {"module": "vuln-lookup", "status": "active", "version": "1.0.0", "source": "NVD (NIST)"}


@router.get("/cve/{cve_id}", response_model=CVEDetailResponse)
async def lookup_cve(cve_id: str):
    """
    Look up a specific CVE by ID (e.g. CVE-2024-3094).

    Returns full details: CVSS score, affected products, references,
    exploit availability, and CWE weaknesses.
    """
    # Validate CVE ID format
    cve_id = cve_id.upper().strip()
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        raise HTTPException(status_code=400, detail=f"Invalid CVE ID format: {cve_id}. Expected CVE-YYYY-NNNNN")

    data = await _nvd_request({"cveId": cve_id})

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise HTTPException(status_code=404, detail=f"CVE not found: {cve_id}")

    cve = _parse_cve(vulns[0])

    # Find related CVEs from references
    related = set()
    for ref in cve.references:
        found = re.findall(r'CVE-\d{4}-\d{4,}', ref.url)
        for r in found:
            if r != cve_id:
                related.add(r)

    return CVEDetailResponse(cve=cve, related_cves=sorted(related)[:10])


@router.get("/search", response_model=SearchResponse)
async def search_cves(
    keyword: str = Query(..., min_length=2, description="Search keyword (product name, description text, etc.)"),
    severity: str | None = Query(None, description="Filter by CVSS severity: LOW, MEDIUM, HIGH, CRITICAL"),
    year: int | None = Query(None, ge=1999, description="Filter by publication year"),
    limit: int = Query(default=20, le=50, description="Max results (NVD caps at 50)"),
):
    """
    Search CVEs by keyword, severity, and/or year.

    Examples:
    - `/search?keyword=apache log4j`
    - `/search?keyword=openssl&severity=CRITICAL`
    - `/search?keyword=wordpress&year=2024&limit=10`
    """
    import time
    start = time.monotonic()

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit,
    }

    if severity:
        severity = severity.upper()
        if severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise HTTPException(status_code=400, detail="Severity must be LOW, MEDIUM, HIGH, or CRITICAL")
        params["cvssV3Severity"] = severity

    if year:
        params["pubStartDate"] = f"{year}-01-01T00:00:00.000"
        params["pubEndDate"] = f"{year}-12-31T23:59:59.999"

    data = await _nvd_request(params)

    total = data.get("totalResults", 0)
    results = [_parse_cve(v) for v in data.get("vulnerabilities", [])]

    elapsed = (time.monotonic() - start) * 1000

    return SearchResponse(
        query=keyword,
        total_results=total,
        results=results,
        search_time_ms=round(elapsed, 2),
    )


@router.get("/product/{vendor}/{product}", response_model=ProductVulnResponse)
async def product_vulnerabilities(
    vendor: str,
    product: str,
    version: str | None = Query(None, description="Specific version to check"),
    limit: int = Query(default=20, le=50),
):
    """
    Find vulnerabilities for a specific product using CPE matching.

    Examples:
    - `/product/apache/http_server`
    - `/product/microsoft/windows_10?version=21H2`
    - `/product/openssl/openssl?version=3.0.0`
    """
    # Build CPE string
    v = version if version else "*"
    cpe = f"cpe:2.3:a:{vendor.lower()}:{product.lower()}:{v}:*:*:*:*:*:*:*"

    params = {
        "cpeName": cpe,
        "resultsPerPage": limit,
    }

    data = await _nvd_request(params)

    total = data.get("totalResults", 0)
    results = [_parse_cve(v) for v in data.get("vulnerabilities", [])]

    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for r in results:
        if r.cvss:
            sev = r.cvss.severity.upper()
            if sev in counts:
                counts[sev] += 1

    return ProductVulnResponse(
        product=f"{vendor}/{product}" + (f"@{version}" if version else ""),
        cpe_match=cpe,
        total_cves=total,
        critical=counts["CRITICAL"],
        high=counts["HIGH"],
        medium=counts["MEDIUM"],
        low=counts["LOW"],
        results=results,
    )


@router.get("/recent", response_model=SearchResponse)
async def recent_cves(
    days: int = Query(default=7, le=120, description="How many days back to search"),
    severity: str | None = Query(None, description="Filter by severity"),
    limit: int = Query(default=20, le=50),
):
    """
    Get recently published or modified CVEs.

    Useful for staying on top of new disclosures.
    """
    import time
    start = time.monotonic()

    now = datetime.utcnow()
    start_date = now.replace(hour=0, minute=0, second=0) - __import__('datetime').timedelta(days=days)

    params = {
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.999"),
        "resultsPerPage": limit,
    }

    if severity:
        severity = severity.upper()
        if severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            params["cvssV3Severity"] = severity

    data = await _nvd_request(params)

    total = data.get("totalResults", 0)
    results = [_parse_cve(v) for v in data.get("vulnerabilities", [])]

    elapsed = (time.monotonic() - start) * 1000

    return SearchResponse(
        query=f"last {days} days" + (f" [{severity}]" if severity else ""),
        total_results=total,
        results=results,
        search_time_ms=round(elapsed, 2),
    )


@router.get("/stats/{cve_id}", response_model=dict)
async def cve_stats(cve_id: str):
    """
    Quick stats for a CVE — score, severity, exploit status.
    Lighter weight than full lookup.
    """
    cve_id = cve_id.upper().strip()
    if not re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
        raise HTTPException(status_code=400, detail=f"Invalid CVE ID: {cve_id}")

    data = await _nvd_request({"cveId": cve_id})
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise HTTPException(status_code=404, detail=f"CVE not found: {cve_id}")

    cve = _parse_cve(vulns[0])

    return {
        "cve_id": cve.cve_id,
        "cvss_score": cve.cvss.score if cve.cvss else None,
        "severity": cve.cvss.severity if cve.cvss else "UNKNOWN",
        "cvss_version": cve.cvss.version if cve.cvss else None,
        "has_exploit": cve.exploit_info.has_public_exploit if cve.exploit_info else False,
        "published": cve.published,
        "weakness_count": len(cve.weaknesses),
        "affected_products": len(cve.affected_products),
        "reference_count": len(cve.references),
    }


# --- Standalone Mode ---

if __name__ == "__main__":
    import uvicorn
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware

    app = FastAPI(
        title="SentinelScope — Vuln Lookup",
        description="CVE search, CVSS scoring, and exploit cross-referencing powered by NVD",
        version="1.0.0",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)

    @app.get("/")
    async def root():
        return {"module": "vuln-lookup", "docs": "/docs"}

    uvicorn.run(app, host="0.0.0.0", port=8000)
