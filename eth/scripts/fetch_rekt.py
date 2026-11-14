"""Download rekt.news leaderboard articles and extract Ethereum-mainnet tx links with their context.

    uv run python scripts/fetch_rekt.py   -> data/rekt_txs.jsonl
Only text is parsed; nothing from the pages is executed.
"""
import html
import json
import re
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "rekt"
TX_LINK = re.compile(r'<a[^>]+href="https?://(?:www\.)?etherscan\.io/tx/(0x[0-9a-fA-F]{64})[^"]*"[^>]*>(.*?)</a>', re.S)
TAG = re.compile(r"<[^>]+>")


def text(s: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(TAG.sub(" ", s))).strip()


def main():
    board = (RAW / "leaderboard.html").read_text(errors="ignore")
    slugs = sorted(set(re.findall(r'href="/([a-z0-9-]+-rekt[a-z0-9-]*)/?"', board)))
    out = []
    for i, slug in enumerate(slugs):
        path = RAW / f"{slug}.html"
        if not path.exists():
            r = requests.get(f"https://rekt.news/{slug}", headers={"User-Agent": "Mozilla/5.0"}, timeout=60)
            path.write_text(r.text if r.status_code == 200 else "")
            time.sleep(1.0)
        page = path.read_text(errors="ignore")
        title = text(re.search(r"<title>(.*?)</title>", page, re.S).group(1)) if "<title>" in page else slug
        date = re.search(r'"datePublished"\s*:\s*"([0-9-]{10})', page) or re.search(r"(\d{4}-\d{2}-\d{2})", page)
        for m in TX_LINK.finditer(page):
            start = max(0, m.start() - 400)
            before = text(page[start:m.start()])[-200:]
            out.append({"slug": slug, "title": title, "date": date.group(1) if date else None,
                        "tx": m.group(1).lower(), "anchor": text(m.group(2))[:80], "context": before})
        if i % 25 == 0:
            print(f"{i}/{len(slugs)} articles, {len(out)} tx links", flush=True)
    (ROOT / "data" / "rekt_txs.jsonl").write_text("".join(json.dumps(o) + "\n" for o in out))
    print(f"done: {len(out)} etherscan tx links from {len({o['slug'] for o in out})} articles")


if __name__ == "__main__":
    main()
