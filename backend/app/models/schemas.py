from pydantic import BaseModel
from enum import Enum


class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


class Verdict(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    UNKNOWN = "UNKNOWN"


# --- VirusTotal ---
class VTIPResult(BaseModel):
    score: int = 0
    reputation: str = "Unknown"
    detections: str = "0/0"
    last_seen: str | None = None
    category: str | None = None


class VTHashResult(BaseModel):
    score: int = 0
    detections: str = "0/0"
    name: str | None = None
    size: str | None = None
    file_type: str | None = None
    first_submission: str | None = None


class VTDomainResult(BaseModel):
    score: int = 0
    reputation: str = "Unknown"
    detections: str = "0/0"
    category: str | None = None
    registrar: str | None = None


# --- AbuseIPDB ---
class AbuseIPDBResult(BaseModel):
    score: int = 0
    reports: int = 0
    confidence: int = 0
    isp: str | None = None
    country: str | None = None
    usage: str | None = None
    domain: str | None = None


# --- Shodan ---
class ShodanResult(BaseModel):
    ports: list[int] = []
    os: str | None = None
    org: str | None = None
    vulns: list[str] = []
    services: list[str] = []
    city: str | None = None
    country: str | None = None


# --- AlienVault OTX ---
class OTXResult(BaseModel):
    pulses: int = 0
    tags: list[str] = []
    first_seen: str | None = None
    malware_count: int = 0
    malware_family: str | None = None


# --- Aggregated ---
class ThreatIntelRequest(BaseModel):
    query: str
    indicator_type: IndicatorType | None = None


class SourceResults(BaseModel):
    virustotal: dict | None = None
    abuseipdb: AbuseIPDBResult | None = None
    shodan: ShodanResult | None = None
    otx: OTXResult | None = None


class ThreatIntelResponse(BaseModel):
    query: str
    indicator_type: IndicatorType
    risk_score: int
    verdict: Verdict
    sources: SourceResults
    errors: dict[str, str] = {}
    cached: bool = False


class HealthResponse(BaseModel):
    status: str
    version: str
    services: dict[str, bool]
