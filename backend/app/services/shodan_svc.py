import httpx
from app.config import get_settings

BASE_URL = "https://api.shodan.io"


async def lookup_ip(ip: str) -> dict:
    """Query Shodan for host information."""
    key = get_settings().shodan_api_key
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(f"{BASE_URL}/shodan/host/{ip}", params={"key": key})
        resp.raise_for_status()
        data = resp.json()

        ports = data.get("ports", [])
        services = []
        vulns = set()

        for item in data.get("data", []):
            product = item.get("product")
            if product and product not in services:
                services.append(product)
            elif not product:
                # Fallback to transport/port
                svc = f"{item.get('transport', 'tcp')}/{item.get('port')}"
                if svc not in services:
                    services.append(svc)

            for v in item.get("vulns", {}):
                vulns.add(v)

        return {
            "ports": sorted(ports),
            "os": data.get("os"),
            "org": data.get("org"),
            "vulns": sorted(vulns),
            "services": services[:10],
            "city": data.get("city"),
            "country": data.get("country_code"),
        }
