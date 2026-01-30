import requests
import logging
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Configuration
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RSS_FEEDS = [
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"}
]
FILENAME = "DAILY_ADVISORY.md"
LOOKBACK_DAYS = 5  # Ensures news isn't "stale"

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def fetch_vulnerabilities(url: str) -> Dict[str, Any]:
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logging.error(f"Error fetching data: {e}")
        return {}

def filter_recent_vulnerabilities(data: Dict[str, Any], days: int) -> List[Dict[str, Any]]:
    threshold_date = datetime.now() - timedelta(days=days)
    recent_vulns = []

    for vuln in data.get('vulnerabilities', []):
        try:
            # CISA date format is YYYY-MM-DD
            added_date = datetime.strptime(vuln.get('dateAdded', ''), '%Y-%m-%d')
            if added_date >= threshold_date:
                recent_vulns.append(vuln)
        except ValueError:
            continue
            
    return recent_vulns

def fetch_rss_news(feeds: List[Dict[str, str]], days: int) -> List[Dict[str, Any]]:
    news_items = []
    # Use timezone-aware current time for comparison with RSS dates
    threshold_date = datetime.now().astimezone() - timedelta(days=days)
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    for feed in feeds:
        try:
            response = requests.get(feed['url'], headers=headers, timeout=10)
            response.raise_for_status()
            root = ET.fromstring(response.content)
            
            # Iterate over RSS items
            for item in root.findall('./channel/item'):
                try:
                    pub_date = parsedate_to_datetime(item.find('pubDate').text)
                    if pub_date >= threshold_date:
                        news_items.append({
                            'title': item.find('title').text,
                            'link': item.find('link').text,
                            'source': feed['name'],
                            'date': pub_date.strftime('%Y-%m-%d')
                        })
                except (ValueError, AttributeError):
                    continue
        except Exception as e:
            logging.error(f"Error fetching RSS {feed['name']}: {e}")
            
    return news_items

def generate_markdown(vulnerabilities: List[Dict[str, Any]], news: List[Dict[str, Any]]) -> str:
    today_str = datetime.now().strftime('%Y-%m-%d')
    markdown_content = f"# Security Advisory Report - {today_str}\n"
    
    # Section 1: CISA KEV
    markdown_content += "## 🛡️ CISA Known Exploited Vulnerabilities (KEV)\n\n"

    if not vulnerabilities:
        markdown_content += "> No new critical vulnerabilities were added to the KEV catalog in the last 72 hours.\n"
    else:
        for v in vulnerabilities:
            cve_id = v.get('cveID', 'N/A')
            markdown_content += f"### 🔴 {v.get('vulnerabilityName', 'Unknown')}\n"
            markdown_content += f"- **CVE ID:** [{cve_id}](https://nvd.nist.gov/vuln/detail/{cve_id})\n"
            markdown_content += f"- **Vendor/Project:** {v.get('vendorProject', 'N/A')}\n"
            markdown_content += f"- **Product:** {v.get('product', 'N/A')}\n"
            markdown_content += f"- **Date Added:** {v.get('dateAdded', 'N/A')}\n"
            markdown_content += f"- **Summary:** {v.get('shortDescription', 'N/A')}\n"
            markdown_content += f"- **Required Action:** {v.get('requiredAction', 'N/A')}\n\n"
            markdown_content += "---\n\n"
            
    # Section 2: General Security News
    markdown_content += "## 📰 Latest Security News\n\n"
    if not news:
        markdown_content += "> No significant security news found in the last 72 hours.\n"
    else:
        for n in news:
            markdown_content += f"- **[{n['title']}]({n['link']})**\n"
            markdown_content += f"  - *Source:* {n['source']} | *Date:* {n['date']}\n"

    return markdown_content

def main():
    # Fetch CISA Data
    cisa_data = fetch_vulnerabilities(CISA_URL)
    recent_vulns = filter_recent_vulnerabilities(cisa_data, LOOKBACK_DAYS) if cisa_data else []

    # Fetch RSS News
    recent_news = fetch_rss_news(RSS_FEEDS, LOOKBACK_DAYS)

    # Generate Report
    markdown_content = generate_markdown(recent_vulns, recent_news)

    with open(FILENAME, "w", encoding="utf-8") as f:
        f.write(markdown_content)
    
    logging.info(f"✅ Advisory generated successfully: {FILENAME}")

if __name__ == "__main__":
    main()