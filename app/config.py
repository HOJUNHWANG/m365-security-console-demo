from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Locate .env at the project root (this file's grandparent) regardless of the working directory.
ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    """Read credentials from environment variables / .env. Never hard-code them."""

    tenant_id: str
    client_id: str
    client_secret: str

    # Groq (optional) - AI security summary. Empty disables the feature (nothing is sent out).
    groq_api_key: str = ""
    groq_model: str = "openai/gpt-oss-120b"

    # Spoofing quarantine / redirect mailboxes (comma-separated, optional) - excluded from "delivered threats"
    hunt_quarantine_mailboxes: str = ""
    # Own domains (comma-separated) - mail from these that is not allowlisted is labelled own-domain spoofing
    hunt_own_domains: str = ""
    # Allowlist - sender domains/addresses treated as normal (no alert even if flagged as spam)
    hunt_allowlist_domains: str = ""
    hunt_allowlist_senders: str = ""

    # Fixed Cc on the "notify recipients" draft in Delivered Threat Emails (comma-separated).
    # Lives here rather than in the repo because these are named individuals: .env is gitignored.
    # Only ever used to pre-fill a mailto: draft - the dashboard cannot and must not send mail.
    threat_notify_cc: str = ""

    # EXO_* keys belong to the EXO collector and are not used here, so ignore them.
    model_config = SettingsConfigDict(env_file=ENV_PATH, env_file_encoding="utf-8", extra="ignore")


settings = Settings()
