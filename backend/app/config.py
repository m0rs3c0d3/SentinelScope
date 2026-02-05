from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # API Keys
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    shodan_api_key: str = ""
    otx_api_key: str = ""

    # Server
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    rate_limit_per_minute: int = 30

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",")]

    @property
    def available_services(self) -> dict[str, bool]:
        return {
            "virustotal": bool(self.virustotal_api_key),
            "abuseipdb": bool(self.abuseipdb_api_key),
            "shodan": bool(self.shodan_api_key),
            "otx": bool(self.otx_api_key),
        }

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
