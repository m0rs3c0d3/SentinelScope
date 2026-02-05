import httpx
from app.config import get_settings

BASE_URL = "https://otx.alienvault.com/api/v1"


def _headers() -> dict:
    key = get_settings().otx_api_key
    if key:
        return {"X-OTX-API-KEY": key}
    return {}


async def lookup_ip(ip: str) -> dict:
    """Query OTX for IP indicator."""
    async with httpx.AsyncClient(timeout=15) as client:
        # General info
        resp = await client.get(
            f"{BASE_URL}/indicators/IPv4/{ip}/general", headers=_headers()
        )
        resp.raise_for_status()
        data = resp.json()

        # Malware info
        malware_resp = await client.get(
            f"{BASE_URL}/indicators/IPv4/{ip}/malware", headers=_headers()
        )
        malware_data = malware_resp.json() if malware_resp.status_code == 200 else {}

        return _parse_otx(data, malware_data)


async def lookup_domain(domain: str) -> dict:
    """Query OTX for domain indicator."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{BASE_URL}/indicators/domain/{domain}/general", headers=_headers()
        )
        resp.raise_for_status()
        data = resp.json()

        malware_resp = await client.get(
            f"{BASE_URL}/indicators/domain/{domain}/malware", headers=_headers()
        )
        malware_data = malware_resp.json() if malware_resp.status_code == 200 else {}

        return _parse_otx(data, malware_data)


async def lookup_hash(file_hash: str) -> dict:
    """Query OTX for file hash indicator."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{BASE_URL}/indicators/file/{file_hash}/general", headers=_headers()
        )
        resp.raise_for_status()
        data = resp.json()

        result = _parse_otx(data, {})

        # Extract malware family from analysis if present
        analysis = data.get("analysis")
        if analysis and isinstance(analysis, dict):
            info = analysis.get("analysis", {}).get("info", {})
            result["malware_family"] = info.get("results", {}).get(
                "malware_family"
            )

        return result


def _parse_otx(data: dict, malware_data: dict) -> dict:
    """Parse common OTX response fields."""
    pulse_info = data.get("pulse_info", {})
    pulses = pulse_info.get("count", 0)

    # Collect tags from pulses
    tags = set()
    for pulse in pulse_info.get("pulses", [])[:20]:
        for tag in pulse.get("tags", []):
            tags.add(tag.lower())

    # Malware count
    malware_count = len(malware_data.get("data", []))

    # First seen from oldest pulse
    first_seen = None
    pulses_list = pulse_info.get("pulses", [])
    if pulses_list:
        dates = [p.get("created") for p in pulses_list if p.get("created")]
        if dates:
            first_seen = min(dates)[:10]

    return {
        "pulses": pulses,
        "tags": sorted(tags)[:15],
        "first_seen": first_seen,
        "malware_count": malware_count,
        "malware_family": None,
    }
