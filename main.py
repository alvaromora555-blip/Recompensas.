import os
from fastapi import FastAPI

app = FastAPI(
    title="Recompensa API",
    version="5.0.0"
)

@app.get("/")
def home():
    return {
        "app": "Recompensa",
        "status": "online"
    }

@app.get("/health")
def health():
    return {
        "ok": True,
        "version": "5.0.0"
    }
