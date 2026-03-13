import os
import requests
import feedparser
import json
from datetime import datetime, timedelta, UTC
from deep_translator import GoogleTranslator

# ==============================
# 설정
# ==============================
SLACK_WEBHOOK = os.environ["SLACK_WEBHOOK"]
SLACK_WEBHOOK_CVE = os.environ["SLACK_WEBHOOK_CVE"]
CACHE_FILE = os.path.join(os.getcwd(), "cache.json")  # 절대 경로
MAX_NEWS_PER_SOURCE = 5
CVSS_THRESHOLD = 7.0


# ==============================
# 번역
# ==============================
def translate_to_korean(text):
    try:
        return GoogleTranslator(source="en", target="ko").translate(text)
    except Exception:
        return text
# ==============================
# 캐시
# ==============================
def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, ValueError):
            print("Warning: cache.json is empty or invalid, resetting cache")
            return {"news": [], "cves": []}
    return {"news": [], "cves": []}

def save_cache(cache):
    with open(CACHE_FILE, "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    print(f"Cache saved: {len(cache.get('news', []))} news, {len(cache.get('cves', []))} cves")

# ==============================
# Slack 텍스트 메시지
# ==============================
def send_slack(webhook, text):
    try:
        r = requests.post(
            webhook,
            json={"text": text},
            timeout=10
        )
        print("Slack response:", r.status_code, r.text)
        r.raise_for_status()
    except Exception as e:
        print("Error sending Slack message:", e)

def build_news_message(news):

    msg = "📰 *Security News*\n\n"
    TRANSLATE_SOURCES = ["The Hacker News", "BleepingComputer", "Dark Reading"]
    
    for n in news:
        title = n['title']
        msg += f"- {title}"

        if n['source'] in TRANSLATE_SOURCES:
            msg += f"\n-> {translate_to_korean(title)}"
            
        msg += f" ({n['source']})\n{n['link']}\n\n"

    return msg

def build_cves_message(cves):
    
    msg = "🚨 *High Severity CVEs*\n\n"
    
    for c in cves:
        desc = c.get("desc", "").replace("\n", " ")[:200]
        ko_desc = translate_to_korean(desc)
        
        msg += (
            f"*{c['id']}*\n"
            f"CVSS: {c['baseScore']} | Published: {c['published']}\n"
            f"{desc}\n"
            f"-> {ko_desc}\n"
            f"{c['url']}\n\n"
        )

    return msg

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
            results.append({
                "title": entry.title,
                "link": entry.link,
                "source": source
            })
    return results

# ==============================
# CVE 수집
# ==============================
def collect_cve(days=1):

    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    end = datetime.now(UTC)
    start = end - timedelta(days=days)

    params = {
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50
    }

    r = requests.get(url, params=params)
    data = r.json()

    cves = []

    for item in data.get("vulnerabilities", []):
        cve = item["cve"]

        metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
        if not metrics:
            continue

        metric = metrics[0]
        cvss = metric.get("cvssData", {})

        baseScore = cvss.get("baseScore", 0)

        if baseScore >= CVSS_THRESHOLD:

            cves.append({
                "id": cve["id"],
                "baseScore": baseScore,
                "severity": cvss.get("baseSeverity"),
                "published": cve["published"][:10],
                "desc": cve["descriptions"][0]["value"][:200],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            })

    cves.sort(key=lambda x: x["baseScore"], reverse=True)

    return cves

# ==============================
# 중복 제거
# ==============================
def filter_new_items(news, cves, cache):
    new_news = [n for n in news if n["link"] not in cache["news"]]
    new_cves = [c for c in cves if c["id"] not in cache["cves"]]
    return new_news, new_cves

def remove_duplicate_news_by_link(news):
    seen_links = set()
    unique_news = []
    for item in news:
        if item["link"] not in seen_links:
            seen_links.add(item["link"])
            unique_news.append(item)
    return unique_news

# ==============================
# Main
# ==============================
def main():

    cache = load_cache()

    news = collect_news()
    news = remove_duplicate_news_by_link(news)
    cves = collect_cve(days=7)
    


    news, cves = filter_new_items(news, cves, cache)

    if not news and not cves:
        print("No new items today.")
        return

#    message = build_message(news, cves)
#    send_slack(message)
    if news:
        news_msg = build_news_message(news)
        send_slack(SLACK_WEBHOOK, news_msg)

    if cves:
        cve_msg = build_cves_message(cves)
        send_slack(SLACK_WEBHOOK_CVE, cve_msg)

#    cache["news"] += [n["link"] for n in news]
#    cache["cves"] += [c["id"] for c in cves]
    cache["news"] = list(set(cache["news"] + [n["link"] for n in news]))
    cache["cves"] = list(set(cache["cves"] + [c["id"] for c in cves]))
    
    save_cache(cache)

if __name__ == "__main__":
    main()
