import argparse
import html
import json
import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Set

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Load backend/.env when running locally
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

from main import (
    CISA_URL,
    RSS_FEEDS,
    fetch_rss_news,
    fetch_vulnerabilities,
    filter_recent_vulnerabilities,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

STATE_FILE = Path(os.environ.get("TELEGRAM_STATE_FILE", BASE_DIR / "telegram_sent.json"))
MAX_HISTORY_ITEMS = 1000
DEFAULT_LOOKBACK_DAYS = 3

WATCHLIST_VENDORS: Dict[str, List[str]] = {
    "Google": [
        "google",
        "chrome",
        "chromium",
        "google workspace",
        "gcp",
        "google cloud",
        "v8",
    ],
    "Microsoft": [
        "microsoft",
        "windows",
        "exchange",
        "azure",
        "entra",
        "sharepoint",
        "office 365",
        "microsoft 365",
        "microsoft office",
        "active directory",
        "hyper-v",
        "defender",
    ],
    "GitHub": [
        "github",
        "actions/checkout",
        "github actions",
        "dependabot",
        "codespaces",
        "copilot",
    ],
    "Linux": [
        "linux",
        "kernel",
        "ubuntu",
        "debian",
        "red hat",
        "rhel",
        "openssh",
        "sudo",
        "systemd",
        "glibc",
    ],
    "Android": [
        "android",
        "google play",
        "play store",
        "pixel",
        "qualcomm",
        "apk",
    ],
    "Apple": [
        "apple",
        "iphone",
        "ipad",
        "ipados",
        "macos",
        "safari",
        "webkit",
        "xcode",
        "airdrop",
        "icloud",
    ],
    "Fortinet": [
        "fortinet",
        "fortios",
        "fortigate",
        "fortimanager",
        "fortianalyzer",
        "fortiproxy",
        "fortiweb",
        "forticlient",
    ],
    "Cisco": [
        "cisco",
        "ios xe",
        "ios xr",
        "nx-os",
        "anyconnect",
        "meraki",
        "webex",
        "splunk",
    ],
    "AWS": [
        "aws",
        "amazon web services",
        "amazon s3",
        "ec2",
        "eks",
        "lambda",
        "cloudfront",
    ],
    "Zoom": [
        "zoom",
        "zoom workplace",
    ],
    "Slack": [
        "slack",
    ],
    "Apache": [
        "apache",
        "tomcat",
        "struts",
        "activemq",
        "log4j",
        "ofbiz",
        "superset",
        "airflow",
        "kafka",
    ],
    "Nginx": [
        "nginx",
    ],
    "Adobe": [
        "adobe",
        "coldfusion",
        "acrobat",
        "magento",
        "adobe commerce",
        "experience manager",
    ],
    "Mozilla": [
        "mozilla",
        "firefox",
        "thunderbird",
    ],
    "Docker": [
        "docker",
        "docker hub",
        "docker desktop",
        "containerd",
        "runc",
        "moby",
    ],
}

# Pre-compile word-boundary regexes per organization
_COMPILED_WATCHLIST: Dict[str, re.Pattern] = {}
for _org, _keywords in WATCHLIST_VENDORS.items():
    _parts = [re.escape(kw) for kw in _keywords]
    if _org == "Apple":
        # Match standalone "iOS" only when not part of "Cisco IOS", "IOS XE", or "IOS XR"
        _parts.append(r"(?<!cisco\s)ios(?!\s*x[er]\b)")
    _COMPILED_WATCHLIST[_org] = re.compile(
        r"\b(?:" + "|".join(_parts) + r")\b",
        re.IGNORECASE,
    )


def match_organizations(text: str) -> List[str]:
    if not text:
        return []
    return [org for org, pattern in _COMPILED_WATCHLIST.items() if pattern.search(text)]


def clean_html_excerpt(raw_html: str, max_chars: int = 280) -> str:
    if not raw_html:
        return ""
    text = " ".join(BeautifulSoup(raw_html, "lxml").get_text(separator=" ", strip=True).split())
    if len(text) > max_chars:
        return text[: max_chars - 1].rstrip() + "…"
    return text


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"sent_items": [], "subscribers": [], "last_update_id": 0}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            data.setdefault("sent_items", [])
            data.setdefault("subscribers", [])
            data.setdefault("last_update_id", 0)
            return data
    except Exception as e:
        logging.warning(f"Failed to read {STATE_FILE}, starting fresh: {e}")
        return {"sent_items": [], "subscribers": [], "last_update_id": 0}


def save_state(state: dict):
    state["sent_items"] = state.get("sent_items", [])[-MAX_HISTORY_ITEMS:]
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def sync_bot_subscribers(bot_token: str, state: dict) -> Set[str]:
    """Check /getUpdates for users who sent /start or /stop to the bot."""
    subscribers: Set[str] = {str(s) for s in state.get("subscribers", []) if str(s).strip()}
    offset = int(state.get("last_update_id", 0)) + 1

    try:
        resp = requests.get(
            f"https://api.telegram.org/bot{bot_token}/getUpdates",
            params={"offset": offset, "timeout": 2},
            timeout=8,
        )
        if not resp.ok:
            return subscribers

        payload = resp.json()
        for update in payload.get("result", []):
            update_id = update.get("update_id", 0)
            if update_id >= state.get("last_update_id", 0):
                state["last_update_id"] = update_id

            msg = update.get("message") or update.get("channel_post") or {}
            text = (msg.get("text") or "").strip().lower()
            chat_id = str(msg.get("chat", {}).get("id", "")).strip()
            if not chat_id:
                continue

            if text.startswith("/start") or text.startswith("/subscribe"):
                subscribers.add(chat_id)
                logging.info(f"Added subscriber chat_id: {chat_id}")
            elif text.startswith("/stop") or text.startswith("/unsubscribe"):
                subscribers.discard(chat_id)
                logging.info(f"Removed subscriber chat_id: {chat_id}")
    except Exception as e:
        logging.debug(f"Could not sync /getUpdates subscribers: {e}")

    state["subscribers"] = sorted(subscribers)
    return subscribers


def get_target_chat_ids(bot_token: str, state: dict) -> List[str]:
    raw_env_ids = os.environ.get("TELEGRAM_CHAT_ID", "")
    configured = {cid.strip() for cid in raw_env_ids.split(",") if cid.strip()}
    dynamic = sync_bot_subscribers(bot_token, state)
    return sorted(configured | dynamic)


def format_kev_message(vuln: dict, matched_orgs: List[str]) -> str:
    cve_id = html.escape(vuln.get("cveID", "N/A"))
    name = html.escape(vuln.get("vulnerabilityName", "Unknown Vulnerability"))
    vendor = html.escape(vuln.get("vendorProject", "N/A"))
    product = html.escape(vuln.get("product", "N/A"))
    date_added = html.escape(vuln.get("dateAdded", "N/A"))
    priority = html.escape(vuln.get("priority", "High").upper())
    summary = html.escape(clean_html_excerpt(vuln.get("shortDescription", ""), 320))
    action = html.escape(clean_html_excerpt(vuln.get("requiredAction", ""), 240))
    orgs_label = html.escape(", ".join(matched_orgs))
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    return (
        f"🛡️ <b>[CISA KEV · {priority}] {orgs_label}</b>\n\n"
        f"<b>{name} ({cve_id})</b>\n"
        f"<i>Vendor/Product:</i> {vendor} · {product} | <i>Added:</i> {date_added}\n\n"
        f"<b>Summary:</b> {summary}\n"
        f"<b>Required Action:</b> {action}\n\n"
        f"🔗 <a href=\"{nvd_url}\">View {cve_id} on NVD</a>"
    )


def format_news_message(item: dict, matched_orgs: List[str]) -> str:
    priority = item.get("priority", "Medium")
    icon = "🚨" if priority == "High" else "⚠️"
    priority_upper = html.escape(priority.upper())
    orgs_label = html.escape(", ".join(matched_orgs))
    title = html.escape(item.get("title", "No Title"))
    source = html.escape(item.get("source", "Security Feed"))
    date_str = html.escape(item.get("date", ""))
    excerpt = html.escape(clean_html_excerpt(item.get("description", ""), 280))
    link = html.escape(item.get("link", "#"), quote=True)

    excerpt_block = f"\n\n{excerpt}" if excerpt else ""
    return (
        f"{icon} <b>[{priority_upper}] {orgs_label} · Security News</b>\n\n"
        f"<b>{title}</b>\n"
        f"<i>Source:</i> {source} · <i>Date:</i> {date_str}"
        f"{excerpt_block}\n\n"
        f"🔗 <a href=\"{link}\">Read Full Article</a>"
    )


def send_telegram_message(bot_token: str, chat_ids: List[str], html_text: str) -> bool:
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    delivered_any = False

    for chat_id in chat_ids:
        try:
            resp = requests.post(
                url,
                json={
                    "chat_id": chat_id,
                    "text": html_text,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": False,
                },
                timeout=10,
            )
            if resp.ok:
                delivered_any = True
            else:
                logging.error(f"Telegram API error for chat_id {chat_id}: {resp.status_code} {resp.text}")
        except requests.RequestException as e:
            logging.error(f"Failed sending to Telegram chat_id {chat_id}: {e}")

    return delivered_any


def run_notifier(days: int = DEFAULT_LOOKBACK_DAYS, max_alerts: int = 15, dry_run: bool = False) -> int:
    bot_token = (os.environ.get("TELEGRAM_BOT_TOKEN") or "").strip()
    if not bot_token and not dry_run:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN in environment or backend/.env")

    state = load_state()
    sent_set: Set[str] = set(state.get("sent_items", []))
    chat_ids = get_target_chat_ids(bot_token, state) if bot_token else []

    if not chat_ids and not dry_run:
        raise RuntimeError("Missing TELEGRAM_CHAT_ID in environment or backend/.env (and no /start subscribers found)")

    pending_alerts = []

    # 1. Check CISA Known Exploited Vulnerabilities
    cisa_data = fetch_vulnerabilities(CISA_URL)
    recent_vulns = filter_recent_vulnerabilities(cisa_data, days) if cisa_data else []
    for vuln in recent_vulns:
        cve_id = vuln.get("cveID", "").strip()
        item_key = f"KEV:{cve_id}" if cve_id else ""
        if not item_key or item_key in sent_set:
            continue

        searchable = " ".join([
            vuln.get("vendorProject", ""),
            vuln.get("product", ""),
            vuln.get("vulnerabilityName", ""),
            vuln.get("shortDescription", ""),
        ])
        matched_orgs = match_organizations(searchable)
        if matched_orgs:
            pending_alerts.append((item_key, format_kev_message(vuln, matched_orgs)))

    # 2. Check Security RSS News (High and Medium priority only)
    recent_news = fetch_rss_news(RSS_FEEDS, days)
    # Sort High priority first
    recent_news.sort(key=lambda n: (0 if n.get("priority") == "High" else 1, n.get("date", "")))

    for item in recent_news:
        if item.get("priority") not in ("High", "Medium"):
            continue
        link = (item.get("link") or "").strip()
        if not link or link in sent_set:
            continue

        searchable = f"{item.get('title', '')} {clean_html_excerpt(item.get('description', ''), 600)}"
        matched_orgs = match_organizations(searchable)
        if matched_orgs:
            pending_alerts.append((link, format_news_message(item, matched_orgs)))

    logging.info(f"Found {len(pending_alerts)} new matching alert(s) across watched organizations.")

    sent_count = 0
    for item_key, message_html in pending_alerts[:max_alerts]:
        if dry_run:
            logging.info(f"[DRY RUN] Would send ({item_key}):\n{message_html}\n" + "-" * 50)
            sent_count += 1
            continue

        if send_telegram_message(bot_token, chat_ids, message_html):
            state["sent_items"].append(item_key)
            sent_set.add(item_key)
            sent_count += 1
            time.sleep(0.5)

    if not dry_run:
        save_state(state)

    logging.info(f"Completed run: {sent_count} alert(s) delivered.")
    return sent_count


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send Telegram security alerts for watched organizations.")
    parser.add_argument("--days", type=int, default=DEFAULT_LOOKBACK_DAYS, help="Lookback window in days (default: 3)")
    parser.add_argument("--max-alerts", type=int, default=15, help="Max alerts to send in a single run (default: 15)")
    parser.add_argument("--dry-run", action="store_true", help="Preview matching alerts without sending to Telegram")
    args = parser.parse_args()

    run_notifier(days=args.days, max_alerts=args.max_alerts, dry_run=args.dry_run)
