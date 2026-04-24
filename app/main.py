from fastapi import FastAPI

app = FastAPI(title="TEHTEK ERP API")

@app.get("/")
def root():
    return {"message": "TEHTEK ERP API is running"}

@app.get("/health")
def health():
    return {"status": "ok"}
