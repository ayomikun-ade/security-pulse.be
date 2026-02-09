from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any
import logging

# Import logic from your existing script
# We assume main.py is in the same directory
from main import (
    fetch_vulnerabilities,
    filter_recent_vulnerabilities,
    fetch_rss_news,
    CISA_URL,
    RSS_FEEDS,
)

app = FastAPI(title="Security Pulse API")

# Configure CORS to allow requests from the frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health_check():
    return {"status": "ok", "message": "Security Pulse API is running"}

@app.get("/api/advisory")
def get_advisory_data(days: int = 4) -> Dict[str, Any]:
    try:
        # Fetch CISA Data
        cisa_data = fetch_vulnerabilities(CISA_URL)
        recent_vulns = filter_recent_vulnerabilities(cisa_data, days) if cisa_data else []

        # Fetch RSS News
        recent_news = fetch_rss_news(RSS_FEEDS, days)

        return {
            "date": "Today", # You might want to generate a dynamic date here
            "vulnerabilities": recent_vulns,
            "news": recent_news
        }
    except Exception as e:
        logging.error(f"API Error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
