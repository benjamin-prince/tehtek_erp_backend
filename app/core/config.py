"""
TEHTEK ERP — Centralized Settings
All sensitive values are loaded from the .env file.
Never hardcode credentials in source code.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):

    # ── Database ─────────────────────────────
    DATABASE_URL: str

    # ── JWT ──────────────────────────────────
    JWT_SECRET_KEY:             str
    JWT_ALGORITHM:              str = "HS256"
    ACCESS_TOKEN_EXPIRE_MIN:    int = 30
    REFRESH_TOKEN_EXPIRE_DAYS:  int = 7

    # ── Security ─────────────────────────────
    MAX_LOGIN_ATTEMPTS:         int = 5
    LOCKOUT_MINUTES:            int = 15
    PASSWORD_RESET_EXPIRE_MIN:  int = 60

    # ── Default Superadmin ───────────────────
    ADMIN_EMAIL:                str
    ADMIN_FIRST_NAME:           str
    ADMIN_LAST_NAME:            str
    ADMIN_PASSWORD:             str

    # ── App ──────────────────────────────────
    APP_NAME:                   str = "TEHTEK ERP API"
    APP_VERSION:                str = "1.0.0"
    APP_DESCRIPTION:            str = "TEHTEK Enterprise Resource Planning System"
    DEBUG:                      bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()