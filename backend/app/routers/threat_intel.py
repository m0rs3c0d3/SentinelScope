from fastapi import APIRouter, HTTPException
from app.models.schemas import ThreatIntelRequest, ThreatIntelResponse, IndicatorType
from app.utils.validators import detect_indicator_type
from app.services.aggregator import aggregate_ip, aggregate_hash, aggregate_domain

router = APIRouter(prefix="/api/v1/threat-intel", tags=["Threat Intelligence"])


@router.post("/lookup", response_model=ThreatIntelResponse)
async def lookup_indicator(request: ThreatIntelRequest):
    """
    Look up a threat indicator (IP, domain, or hash) across all configured
    intelligence sources and return an aggregated risk assessment.
    """
    query = request.query.strip()
    if not query:
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    # Auto-detect or validate type
    indicator_type = request.indicator_type or detect_indicator_type(query)
    if not indicator_type:
        raise HTTPException(
            status_code=400,
            detail=f"Could not determine indicator type for: {query}. "
                   f"Expected an IP address, domain, or file hash (MD5/SHA1/SHA256).",
        )

    if indicator_type == IndicatorType.IP:
        return await aggregate_ip(query)
    elif indicator_type == IndicatorType.HASH:
        return await aggregate_hash(query.lower())
    elif indicator_type == IndicatorType.DOMAIN:
        return await aggregate_domain(query.lower())

    raise HTTPException(status_code=400, detail=f"Unsupported indicator type: {indicator_type}")


@router.get("/lookup/{indicator}", response_model=ThreatIntelResponse)
async def lookup_indicator_get(indicator: str):
    """GET shorthand — auto-detects indicator type."""
    request = ThreatIntelRequest(query=indicator)
    return await lookup_indicator(request)
