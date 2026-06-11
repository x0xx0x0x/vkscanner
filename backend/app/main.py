"""
VK Scanner (Voight-Kampff) — FastAPI Application.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown events."""
    # Startup: Initialize SQLite local database & download NLTK data if available
    try:
        from app.database import init_db
        init_db()
    except Exception:
        pass
        
    try:
        import nltk
        nltk.download("vader_lexicon", quiet=True)
    except ImportError:
        pass
    yield
    # Shutdown: cleanup if needed


app = FastAPI(
    title="VK Scanner (Voight-Kampff)",
    description="AI-powered phishing detection tool. Analyzes URLs, emails, and documents for phishing indicators.",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend (restrict to localhost for security)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost",
        "http://127.0.0.1"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(scan.router)


@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "operational",
        "service": "VK Scanner (Voight-Kampff)",
        "version": "1.0.0",
    }
