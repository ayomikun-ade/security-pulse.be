import json
import os
from datetime import datetime

# Vercel serverless functions have a read-only filesystem except /tmp.
# ADVISORY_LOG_PATH can be overridden in .env for local persistence.
STORE_FILE = os.environ.get("ADVISORY_LOG_PATH", "/tmp/advisory_log.json")


def _load() -> dict:
    if not os.path.exists(STORE_FILE):
        return {}
    with open(STORE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict):
    with open(STORE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def get_next_id() -> str:
    data = _load()
    today = datetime.now().strftime("%d%m%y")
    key = f"seq_{today}"
    seq = data.get(key, 0) + 1
    data[key] = seq
    _save(data)
    return f"NCA-{today}-{seq:02d}"


def is_duplicate(url: str) -> bool:
    data = _load()
    return any(a.get("url") == url for a in data.get("advisories", []))


def record_advisory(advisory_id: str, url: str, title: str):
    data = _load()
    data.setdefault("advisories", []).append({
        "id": advisory_id,
        "url": url,
        "title": title,
        "published_at": datetime.now().isoformat(),
    })
    _save(data)
