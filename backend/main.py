from fastapi import FastAPI

app = FastAPI(
    title="Police Personnel Integrity API",
    version="0.1.0",
)


@app.get("/health", tags=["Health"])
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "police-personnel-integrity-api",
    }