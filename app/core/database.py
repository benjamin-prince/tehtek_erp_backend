"""
ERP Core — Database & Configuration
"""

import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://erp_user:password@localhost:5432/erp_db"
    )

    # JWT
    JWT_SECRET_KEY:         str = os.getenv("JWT_SECRET_KEY", "change-me-in-production")
    JWT_ALGORITHM:          str = "HS256"
    ACCESS_TOKEN_EXPIRE_MIN:int = 30
    REFRESH_TOKEN_EXPIRE_DAYS:int = 7

    # Security
    MAX_LOGIN_ATTEMPTS:     int = 5
    LOCKOUT_MINUTES:        int = 15
    PASSWORD_RESET_EXPIRE_MIN: int = 60

    # App
    APP_NAME:   str = "ERP System"
    DEBUG:      bool = False

    model_config = {"env_file": ".env", "extra": "ignore"}


settings = Settings()

# ─── Async Engine ───────────────────────────

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()