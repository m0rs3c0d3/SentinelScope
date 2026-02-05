import asyncio
import logging
from app.config import get_settings
from app.models.schemas import (
    IndicatorType,
    Verdict,
    ThreatIntelResponse,
    SourceResults,
)
from app.services import virustotal, abuseipdb, shodan_svc, otx

logger = logging.getLogger(__name__)


async def _safe_call(name: str, coro, errors: dict) -> dict | None:
    """Execute an API call, capturing errors without crashing the pipeline."""
    try:
        return await coro
    except Exception as e:
        logger.warning(f"[{name}] lookup failed: {e}")
        errors[name] = str(e)
        return None


async def aggregate_ip(ip: str) -> ThreatIntelResponse:
    """Run all sources in parallel for an IP address."""
    settings = get_settings()
    errors: dict[str, str] = {}
    tasks = {}

    if settings.virustotal_api_key:
        tasks["virustotal"] = _safe_call("virustotal", virustotal.lookup_ip(ip), errors)
    if settings.abuseipdb_api_key:
        tasks["abuseipdb"] = _safe_call("abuseipdb", abuseipdb.lookup_ip(ip), errors)
    if settings.shodan_api_key:
        tasks["shodan"] = _safe_call("shodan", shodan_svc.lookup_ip(ip), errors)
    if settings.otx_api_key:
        tasks["otx"] = _safe_call("otx", otx.lookup_ip(ip), errors)

    results = {}
    if tasks:
        gathered = await asyncio.gather(*tasks.values())
        for key, result in zip(tasks.keys(), gathered):
            results[key] = result

    risk_score = _compute_ip_risk(results)

    return ThreatIntelResponse(
        query=ip,
        indicator_type=IndicatorType.IP,
        risk_score=risk_score,
        verdict=_score_to_verdict(risk_score),
        sources=SourceResults(**results),
        errors=errors,
    )


async def aggregate_hash(file_hash: str) -> ThreatIntelResponse:
    """Run applicable sources for a file hash."""
    settings = get_settings()
    errors: dict[str, str] = {}
    tasks = {}

    if settings.virustotal_api_key:
        tasks["virustotal"] = _safe_call("virustotal", virustotal.lookup_hash(file_hash), errors)
    if settings.otx_api_key:
        tasks["otx"] = _safe_call("otx", otx.lookup_hash(file_hash), errors)

    results = {}
    if tasks:
        gathered = await asyncio.gather(*tasks.values())
        for key, result in zip(tasks.keys(), gathered):
            results[key] = result

    risk_score = _compute_hash_risk(results)

    return ThreatIntelResponse(
        query=file_hash,
        indicator_type=IndicatorType.HASH,
        risk_score=risk_score,
        verdict=_score_to_verdict(risk_score),
        sources=SourceResults(**results),
        errors=errors,
    )


async def aggregate_domain(domain: str) -> ThreatIntelResponse:
    """Run applicable sources for a domain."""
    settings = get_settings()
    errors: dict[str, str] = {}
    tasks = {}

    if settings.virustotal_api_key:
        tasks["virustotal"] = _safe_call("virustotal", virustotal.lookup_domain(domain), errors)
    if settings.otx_api_key:
        tasks["otx"] = _safe_call("otx", otx.lookup_domain(domain), errors)

    results = {}
    if tasks:
        gathered = await asyncio.gather(*tasks.values())
        for key, result in zip(tasks.keys(), gathered):
            results[key] = result

    risk_score = _compute_domain_risk(results)

    return ThreatIntelResponse(
        query=domain,
        indicator_type=IndicatorType.DOMAIN,
        risk_score=risk_score,
        verdict=_score_to_verdict(risk_score),
        sources=SourceResults(**results),
        errors=errors,
    )


# --- Risk Scoring ---

def _compute_ip_risk(results: dict) -> int:
    """
    Weighted risk score for IP indicators (0-100).

    Weights:
      - VirusTotal detections:   30%
      - AbuseIPDB confidence:    30%
      - Shodan vulnerabilities:  15%
      - OTX pulse count:         25%
    """
    score = 0.0
    weights_used = 0.0

    vt = results.get("virustotal")
    if vt:
        # Scale: 0 detections=0, 10+=100
        vt_score = min(vt.get("score", 0) * 10, 100)
        score += vt_score * 0.30
        weights_used += 0.30

    abuse = results.get("abuseipdb")
    if abuse:
        score += abuse.get("confidence", abuse.get("score", 0)) * 0.30
        weights_used += 0.30

    shodan = results.get("shodan")
    if shodan:
        vuln_count = len(shodan.get("vulns", []))
        shodan_score = min(vuln_count * 20, 100)
        score += shodan_score * 0.15
        weights_used += 0.15

    otx_data = results.get("otx")
    if otx_data:
        pulse_count = otx_data.get("pulses", 0)
        malware = otx_data.get("malware_count", 0)
        # Scale: 0 pulses=0, 50+=100, malware adds weight
        otx_score = min(pulse_count * 2, 80) + min(malware * 10, 20)
        score += min(otx_score, 100) * 0.25
        weights_used += 0.25

    if weights_used > 0:
        return min(int(score / weights_used), 100)
    return 0


def _compute_hash_risk(results: dict) -> int:
    """Risk score for file hash indicators."""
    score = 0.0
    weights_used = 0.0

    vt = results.get("virustotal")
    if vt:
        vt_score = min(vt.get("score", 0) * 2, 100)
        score += vt_score * 0.70
        weights_used += 0.70

    otx_data = results.get("otx")
    if otx_data:
        pulse_count = otx_data.get("pulses", 0)
        has_family = 20 if otx_data.get("malware_family") else 0
        otx_score = min(pulse_count * 2 + has_family, 100)
        score += otx_score * 0.30
        weights_used += 0.30

    if weights_used > 0:
        return min(int(score / weights_used), 100)
    return 0


def _compute_domain_risk(results: dict) -> int:
    """Risk score for domain indicators."""
    score = 0.0
    weights_used = 0.0

    vt = results.get("virustotal")
    if vt:
        vt_score = min(vt.get("score", 0) * 10, 100)
        score += vt_score * 0.50
        weights_used += 0.50

    otx_data = results.get("otx")
    if otx_data:
        pulse_count = otx_data.get("pulses", 0)
        malware = otx_data.get("malware_count", 0)
        otx_score = min(pulse_count * 2, 70) + min(malware * 5, 30)
        score += min(otx_score, 100) * 0.50
        weights_used += 0.50

    if weights_used > 0:
        return min(int(score / weights_used), 100)
    return 0


def _score_to_verdict(score: int) -> Verdict:
    if score >= 70:
        return Verdict.MALICIOUS
    elif score >= 30:
        return Verdict.SUSPICIOUS
    elif score > 0:
        return Verdict.BENIGN
    return Verdict.UNKNOWN
