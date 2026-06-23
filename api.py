import logging
import os
import re
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

load_dotenv()

from main import (
    fetch_vulnerabilities,
    filter_recent_vulnerabilities,
    fetch_rss_news,
    fetch_article_text,
    CISA_URL,
    RSS_FEEDS,
)
from advisory_generator import generate_advisory_sections, build_advisory_docx
from advisory_store import get_next_id, is_duplicate, record_advisory

# ---------------------------------------------------------------------------
# App + rate limiter
# ---------------------------------------------------------------------------

limiter = Limiter(key_func=get_remote_address, default_limits=[])
app = FastAPI(title="Security Pulse API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS — restrict to the configured frontend origin in production; falls back to localhost for local dev.
_allowed_origin = os.environ.get("ALLOWED_ORIGIN", "http://localhost:3200")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[_allowed_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
    expose_headers=["Content-Disposition"],
)

# ---------------------------------------------------------------------------
# Request/response models
# ---------------------------------------------------------------------------

class NewsItemRequest(BaseModel):
    title: str = Field(..., max_length=500)
    link: str = Field(..., max_length=2000)
    source: str = Field(..., max_length=200)
    date: str = Field(..., max_length=20)
    priority: str = Field("Low", max_length=10)
    description: str = Field("", max_length=5000)

class DownloadRequest(BaseModel):
    title: str = Field(..., max_length=500)
    link: str = Field(..., max_length=2000)
    overview: str = Field(..., max_length=5000)
    impact: str = Field(..., max_length=5000)
    affected_products: str = Field(..., max_length=3000)
    preventive_measures: str = Field(..., max_length=5000)
    references: str = Field(..., max_length=3000)

# ---------------------------------------------------------------------------
# Existing endpoints
# ---------------------------------------------------------------------------

@app.get("/")
def health_check():
    return {"status": "ok", "message": "Security Pulse API is running"}

@app.get("/api/advisory")
def get_advisory_data(days: int = 4) -> Dict[str, Any]:
    try:
        cisa_data = fetch_vulnerabilities(CISA_URL)
        recent_vulns = filter_recent_vulnerabilities(cisa_data, days) if cisa_data else []
        recent_news = fetch_rss_news(RSS_FEEDS, days)
        return {
            "date": "Today",
            "vulnerabilities": recent_vulns,
            "news": recent_news,
        }
    except Exception as e:
        logging.error(f"API Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to fetch advisory data.")

# ---------------------------------------------------------------------------
# Advisory generation endpoints
# ---------------------------------------------------------------------------

@app.post("/api/preview-advisory")
@limiter.limit("10/hour")
async def preview_advisory(request: Request, body: NewsItemRequest):
    try:
        article_text = fetch_article_text(body.link)
        sections = generate_advisory_sections(
            title=body.title,
            url=body.link,
            source=body.source,
            article_text=article_text,
            description=body.description,
        )
        return {
            "sections": sections,
            "is_duplicate": is_duplicate(body.link),
        }
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))
    except Exception as e:
        logging.error(f"Preview error: {e}")
        raise HTTPException(status_code=500, detail="Advisory generation failed.")


@app.post("/api/download-advisory")
@limiter.limit("10/hour")
async def download_advisory(request: Request, body: DownloadRequest):
    try:
        advisory_id = get_next_id()
        sections = {
            "title": body.title,
            "overview": body.overview,
            "impact": body.impact,
            "affected_products": body.affected_products,
            "preventive_measures": body.preventive_measures,
            "references": body.references,
        }
        docx_bytes = build_advisory_docx(sections, advisory_id)
        record_advisory(advisory_id, body.link, body.title)

        safe_title = re.sub(r'[^\w\s-]', '', body.title).strip()[:60]
        filename = f"{advisory_id} - {safe_title}.docx"
        return Response(
            content=docx_bytes,
            media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logging.error(f"Download error: {e}")
        raise HTTPException(status_code=500, detail="Failed to build advisory document.")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
