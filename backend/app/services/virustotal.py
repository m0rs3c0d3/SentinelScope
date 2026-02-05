import httpx
from app.config import get_settings

BASE_URL = "https://www.virustotal.com/api/v3"


def _headers() -> dict:
    return {"x-apikey": get_settings().virustotal_api_key}


async def lookup_ip(ip: str) -> dict:
    """Query VT for IP address reputation."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{BASE_URL}/ip_addresses/{ip}", headers=_headers())
        resp.raise_for_status()
        data = resp.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        return {
            "score": malicious,
            "reputation": _reputation_label(malicious),
            "detections": f"{malicious}/{total}",
            "last_seen": data.get("last_modification_date"),
            "category": _get_category(data),
        }


async def lookup_hash(file_hash: str) -> dict:
    """Query VT for file hash report."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{BASE_URL}/files/{file_hash}", headers=_headers())
        resp.raise_for_status()
        data = resp.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        return {
            "score": malicious,
            "detections": f"{malicious}/{total}",
            "name": data.get("meaningful_name") or data.get("names", [None])[0],
            "size": _format_size(data.get("size", 0)),
            "file_type": data.get("type_description"),
            "first_submission": data.get("first_submission_date"),
        }


async def lookup_domain(domain: str) -> dict:
    """Query VT for domain reputation."""
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{BASE_URL}/domains/{domain}", headers=_headers())
        resp.raise_for_status()
        data = resp.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.values())

        return {
            "score": malicious,
            "reputation": _reputation_label(malicious),
            "detections": f"{malicious}/{total}",
            "category": _get_category(data),
            "registrar": data.get("registrar"),
        }


def _reputation_label(malicious_count: int) -> str:
    if malicious_count == 0:
        return "Clean"
    elif malicious_count <= 3:
        return "Suspicious"
    return "Malicious"


def _get_category(data: dict) -> str | None:
    cats = data.get("categories", {})
    if cats:
        return list(cats.values())[0]
    return None


def _format_size(size_bytes: int) -> str:
    if size_bytes == 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB"]
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f"{size:.1f} {units[i]}"
