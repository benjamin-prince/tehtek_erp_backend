"""
TEHTEK ERP — Main Application
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.modules.users.models import User, UserStatus, UserType
from app.modules.users.security import hash_password
from app.modules.users.router import router as users_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# DEFAULT ADMIN SEEDER
# ─────────────────────────────────────────────

def create_default_admin() -> None:
    """
    Creates the default superadmin on first boot using
    credentials defined in .env — never hardcoded.
    Safe to call multiple times — skips if already exists.
    """
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == settings.ADMIN_EMAIL).first()
        if existing:
            logger.info("Default admin already exists — skipping seed.")
            return

        admin = User(
            email           = settings.ADMIN_EMAIL,
            first_name      = settings.ADMIN_FIRST_NAME,
            last_name       = settings.ADMIN_LAST_NAME,
            hashed_password = hash_password(settings.ADMIN_PASSWORD),
            user_type       = UserType.INTERNAL,
            status          = UserStatus.ACTIVE,
            is_superadmin   = True,
            mfa_enabled     = False,
        )
        db.add(admin)
        db.commit()
        logger.info(f"Default admin created: {settings.ADMIN_EMAIL}")

    except SQLAlchemyError as e:
        db.rollback()
        logger.error(f"Failed to create default admin: {e}")
        raise

    finally:
        db.close()


# ─────────────────────────────────────────────
# LIFESPAN
# ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────
    logger.info(f"Starting {settings.APP_NAME}...")
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables verified.")
        create_default_admin()
    except Exception as e:
        logger.critical(f"Startup failed: {e}")
        raise

    yield  # app is running

    # ── Shutdown ─────────────────────────────
    logger.info(f"Shutting down {settings.APP_NAME}...")
    engine.dispose()
    logger.info("Database connections closed.")


# ─────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────

app = FastAPI(
    title       = settings.APP_NAME,
    version     = settings.APP_VERSION,
    description = settings.APP_DESCRIPTION,
    lifespan    = lifespan,
)

app.include_router(users_router, prefix="/api")


# ─────────────────────────────────────────────
# CORE ROUTES
# ─────────────────────────────────────────────

@app.get("/", tags=["System"])
def root():
    return {"message": f"{settings.APP_NAME} is running"}


@app.get("/health", tags=["System"])
def health():
    try:
        with engine.connect() as conn:
            db_time = conn.execute(text("SELECT NOW();")).scalar()
        return {
            "status":   "ok",
            "database": "connected",
            "db_time":  str(db_time),
        }
    except SQLAlchemyError as e:
        logger.error(f"Health check failed: {e}")
        return {
            "status":   "error",
            "database": "disconnected",
            "detail":   str(e),
        }