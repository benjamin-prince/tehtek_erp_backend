from fastapi import FastAPI
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError
import os

app = FastAPI(title="TEHTEK ERP API")

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://tehtek:tehtek_secret@db:5432/tehtek"
)

engine = create_engine(DATABASE_URL)


@app.get("/")
def root():
    return {"message": "TEHTEK ERP API is running"}


@app.get("/health")
def health():
    try:
        with engine.connect() as connection:
            result = connection.execute(text("SELECT NOW();"))
            db_time = result.scalar()

        return {
            "status": "ok",
            "database": "connected",
            "db_time": str(db_time)
        }

    except SQLAlchemyError as e:
        return {
            "status": "error",
            "database": "disconnected",
            "details": str(e)
        }