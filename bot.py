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
CVSS_THRESHOLD = 7.0  # 중요도 기준: baseScore >= 7.0

# ==============================
# 캐시
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
# Slack Block 메시지
# ==============================
def send_slack_block(blocks):
    payload = {"blocks": blocks}
    try:
        r = requests.post(SLACK_WEBHOOK, json=payload)
        r.raise_for_status()
        print("Slack message sent successfully")
    except Exception as e:
        print("Error sending Slack message:", e)

def build_blocks(news, cves):
    blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "*🔐 Security Intelligence Update*"}}]
    
    if news:
        blocks.append({"type": "header", "text": {"type": "plain_text", "text": "📰 Security News"}})
        for n in news:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"• <{n['link']}|{n['title']}> ({n['source']})"}
            })
            blocks.append({"type": "divider"})
    
    if cves:
        blocks.append({"type": "header", "text": {"type": "plain_text", "text": "🚨 High Severity CVEs"}})
        for c in cves:
            desc = c.get("desc", "")[:300]  # 요약
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{c['id']}* - {desc}\n• Published: {c['published']}\n• CVSS: {c['baseScore']}\n<{c['url']}|Details>"}
            })
            if "exploit" in c:
                blocks.append({
                    "type": "context",
                    "elements": [{"type": "mrkdwn", "text": f"💥 Exploit: {c['exploit']}"}]
                })
            blocks.append({"type": "divider"})
    return blocks

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
    "Dark Reading": "https://www.darkreading.com/rss.xml"
}

def collect_news():
    results = []
    for source, url in {**KOREAN_RSS_FEEDS, **FOREIGN_RSS_FEEDS}.items():
        feed = feedparser.parse(url)
        for entry in feed.entries[:MAX_NEWS_PER_SOURCE]:
            results.append({"title": entry.title, "link": entry.link, "source": source})
    return results

# ==============================
# CVE 수집 (NVD API 2.0, 날짜 필터링 + 중요도 정렬)
# ==============================
def collect_cve(days=1):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start = datetime.utcnow() - timedelta(days=days)
    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT00:00:00.000"),
        "resultsPerPage": 50  # 최대 50개
    }
    r = requests.get(url, params=params)
    data = r.json()
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item["cve"]
        baseScore = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0)
        if baseScore >= CVSS_THRESHOLD:
            cves.append({
                "id": cve["id"],
                "desc": cve["descriptions"][0]["value"],
                "published": cve.get("published"),
                "baseScore": baseScore,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                "exploit": next((r["url"] for r in cve.get("references", []) if "Exploit" in r.get("tags", [])), None)
            })
    # CVSS 점수 높은 순 정렬
    return sorted(cves, key=lambda x: x["baseScore"], reverse=True)

# ==============================
# 중복 제거
# ==============================
def filter_new_items(news, cves, cache):
    new_news = [n for n in news if n["link"] not in cache["news"]]
    new_cves = [c for c in cves if c["id"] not in cache["cves"]]
    return new_news, new_cves

# ==============================
# Main
# ==============================
def main():
    cache = load_cache()
    news = collect_news()
    cves = collect_cve(days=7)  # 최근 7일 CVE 조회

    news, cves = filter_new_items(news, cves, cache)
    if not news and not cves:
        print("No new items today.")
        return

    blocks = build_blocks(news, cves)
    send_slack_block(blocks)

    # 캐시에 기록
    cache["news"] += [n["link"] for n in news]
    cache["cves"] += [c["id"] for c in cves]
    save_cache(cache)

if __name__ == "__main__":
    main()
