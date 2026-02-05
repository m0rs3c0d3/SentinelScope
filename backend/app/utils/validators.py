import re
from app.models.schemas import IndicatorType


IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*\.)+[a-zA-Z]{2,}$")
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def detect_indicator_type(query: str) -> IndicatorType | None:
    """Auto-detect the type of indicator from a raw query string."""
    q = query.strip()
    if IP_PATTERN.match(q):
        # Validate octets are 0-255
        octets = q.split(".")
        if all(0 <= int(o) <= 255 for o in octets):
            return IndicatorType.IP
    if MD5_PATTERN.match(q) or SHA1_PATTERN.match(q) or SHA256_PATTERN.match(q):
        return IndicatorType.HASH
    if DOMAIN_PATTERN.match(q):
        return IndicatorType.DOMAIN
    return None


def get_hash_type(hash_str: str) -> str:
    """Return hash algorithm name based on length."""
    length = len(hash_str)
    if length == 32:
        return "MD5"
    elif length == 40:
        return "SHA-1"
    elif length == 64:
        return "SHA-256"
    return "Unknown"
