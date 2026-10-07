from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    tenant_id: str
    client_id: str
    client_secret: str

    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-120b"

    hunt_quarantine_mailboxes: str = ""
    hunt_own_domains: str = ""
    hunt_allowlist_domains: str = ""
    hunt_allowlist_senders: str = ""

    signin_egress_ips: str = ""

    threat_notify_cc: str = ""

    model_config = SettingsConfigDict(env_file=ENV_PATH, env_file_encoding="utf-8", extra="ignore")


settings = Settings()
