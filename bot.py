import os
import requests
import feedparser
import json
from datetime import datetime, timedelta

# ==============================
# 설정
# ==============================
SLACK_WEBHOOK = os.environ["SLACK_WEBHOOK"]
CACHE_FILE = "cache.json"
MAX_NEWS_PER_SOURCE = 5

# ==============================
# Slack 전송
# ==============================
def send_slack(message):
    payload = {"text": message}
    try:
        r = requests.post(SLACK_WEBHOOK, json=payload)
        r.raise_for_status()
        print("Slack message sent successfully")
    except Exception as e:
        print("Error sending Slack message:", e)

# ==============================
# 캐시 관리 (중복 제거)
# ==============================
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {"news": [], "cves": []}

def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)

# ==============================
# 뉴스 수집
# ==============================
KOREAN_RSS_FEEDS = {
    "데일리시큐 인기기사": "https://www.dailysecu.com/rss/clickTop.xml",
    "데일리시큐 이슈": "https://www.dailysecu.com/rss/S1N2.xml",
    "보안뉴스": "http://www.boannews.com/media/news_rss.xml?skind=5",
    "KISA 보안공지": "https://www.boho.or.kr/kr/rss.do?bbsId=B0000133",
    "KISA 취약점정보": "https://www.boho.or.kr/kr/rss.do?bbsId=B0000302"
}

FOREIGN_RSS_FEEDS = {
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
}

def collect_news():
    results = []
    for source, url in {**KOREAN_RSS_FEEDS, **FOREIGN_RSS_FEEDS}.items():
        feed = feedparser.parse(url)
        for entry in feed.entries[:MAX_NEWS_PER_SOURCE]:
            results.append({
                "title": entry.title,
                "link": entry.link,
                "source": source
            })
    return results

# ==============================
# CVE 수집
# ==============================
def collect_cve():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    yesterday = datetime.utcnow() - timedelta(days=1)
    params = {
        "pubStartDate": yesterday.strftime("%Y-%m-%dT00:00:00.000"),
        "cvssV3Severity": "HIGH"
    }
    try:
        r = requests.get(url, params=params)
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cves.append({
                "id": cve["id"],
                "desc": cve["descriptions"][0]["value"][:200]
            })
        return cves
    except Exception as e:
        print("Error fetching CVE:", e)
        return []

# ==============================
# 중복 제거
# ==============================
def filter_new_items(news, cves, cache):
    new_news = [n for n in news if n["link"] not in cache["news"]]
    new_cves = [c for c in cves if c["id"] not in cache["cves"]]
    return new_news, new_cves

# ==============================
# Slack 메시지 생성
# ==============================
def build_message(news, cves):
    text = "🔐 *Security Intelligence Update*\n\n"

    if news:
        text += "*📰 Security News*\n"
        for n in news:
            text += f"• {n['title']}\n<{n['link']}|Read article> ({n['source']})\n\n"

    if cves:
        text += "\n*🚨 High Severity CVEs*\n"
        for c in cves:
            text += f"• {c['id']}\n{c['desc']}\nhttps://nvd.nist.gov/vuln/detail/{c['id']}\n\n"

    return text if (news or cves) else None

# ==============================
# Main
# ==============================
def main():
    cache = load_cache()
    news = collect_news()
    cves = collect_cve()

    news, cves = filter_new_items(news, cves, cache)

    if not news and not cves:
        print("No new items to send today.")
        return

    message = build_message(news, cves)
    send_slack(message)

    # 캐시에 기록
    cache["news"] += [n["link"] for n in news]
    cache["cves"] += [c["id"] for c in cves]
    save_cache(cache)

if __name__ == "__main__":
    main()
