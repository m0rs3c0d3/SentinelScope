import httpx
from app.config import get_settings

BASE_URL = "https://api.abuseipdb.com/api/v2"


def _headers() -> dict:
    return {
        "Key": get_settings().abuseipdb_api_key,
        "Accept": "application/json",
    }


async def lookup_ip(ip: str) -> dict:
    """Check an IP against AbuseIPDB."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(
            f"{BASE_URL}/check",
            headers=_headers(),
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
        )
        resp.raise_for_status()
        data = resp.json()["data"]

        return {
            "score": data.get("abuseConfidenceScore", 0),
            "reports": data.get("totalReports", 0),
            "confidence": data.get("abuseConfidenceScore", 0),
            "isp": data.get("isp"),
            "country": data.get("countryCode"),
            "usage": data.get("usageType"),
            "domain": data.get("domain"),
        }
