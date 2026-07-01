"""
安全社区情报拉取器（Community Intelligence Fetcher）
======================================================
从 FreeBuf RSS/搜索页、先知社区公开页面拉取 WAF 绕过 / SQLi / XSS 相关文章，
并从正文或本地种子文件提取真实载荷行。

遵守 robots.txt；网络失败时回退到 ``data/raw/community/payloads_seed.txt``，
并在日志中给出手动补充说明。
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Iterator
from urllib.parse import urljoin, urlparse
from urllib.robotparser import RobotFileParser

from iga_guard.dataset.label_rules import infer_attack_label

USER_AGENT = "IGA-Guard-CommunityFetcher/1.0 (+research; contact=iga-guard@local)"
REQUEST_DELAY_SEC = 1.0

# 社区公开入口（仅抓取列表/RSS，不爬全站）
COMMUNITY_SOURCES: list[dict[str, str]] = [
    {
        "name": "freebuf_rss",
        "url": "https://www.freebuf.com/feed",
        "type": "rss",
        "base": "https://www.freebuf.com",
    },
    {
        "name": "freebuf_search_waf",
        "url": "https://www.freebuf.com/search/?query=WAF%E7%BB%95%E8%BF%87",
        "type": "html",
        "base": "https://www.freebuf.com",
    },
    {
        "name": "freebuf_search_sqli",
        "url": "https://www.freebuf.com/search/?query=SQL%E6%B3%A8%E5%85%A5",
        "type": "html",
        "base": "https://www.freebuf.com",
    },
    {
        "name": "xianzhi_index",
        "url": "https://xz.aliyun.com/",
        "type": "html",
        "base": "https://xz.aliyun.com",
    },
]

_COMMENT_LINE = re.compile(r"^\s*#")
_MD_CODE_BLOCK = re.compile(r"```[\w]*\n(.*?)```", re.DOTALL)
_HTML_LINK = re.compile(
    r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]{4,200})</a>',
    re.IGNORECASE,
)
_RSS_ITEM = re.compile(
    r"<item>.*?<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>.*?<link>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</link>",
    re.DOTALL | re.IGNORECASE,
)
_PAYLOAD_INLINE = re.compile(
    r"(?:"
    r"union\s+select|'\s*or\s+'|<script|onerror\s*=|benchmark\s*\(|"
    r"information_schema|/\*\*/|%00|%u00|multipart|boundary=|"
    r"\\u[0-9a-fA-F]{4}|&#x[0-9a-fA-F]+;"
    r")",
    re.IGNORECASE,
)

_MANUAL_FALLBACK_MSG = (
    "社区拉取失败或 robots 禁止。请手动：\n"
    "  1) 打开 https://www.freebuf.com 搜索「WAF绕过」「SQL注入」「XSS」\n"
    "  2) 打开 https://xz.aliyun.com 浏览公开 writeup\n"
    "  3) 将载荷追加到 data/raw/community/payloads_seed.txt（每行一条，# 标注来源）\n"
    "  4) 重新运行 dataset_agent.py（可加 --skip-fetch 仅用本地种子）"
)

_robots_cache: dict[str, RobotFileParser | None] = {}


def _get_session():
    """延迟导入 requests，与 fetchers 保持一致。"""
    import requests

    return requests.Session()


def _can_fetch(url: str, session=None) -> bool:
    """检查 robots.txt 是否允许抓取该 URL。"""
    parsed = urlparse(url)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in _robots_cache:
        rp = RobotFileParser()
        robots_url = urljoin(origin, "/robots.txt")
        try:
            if session is not None:
                r = session.get(robots_url, headers={"User-Agent": USER_AGENT}, timeout=15)
                if r.status_code == 200:
                    rp.parse(r.text.splitlines())
                else:
                    rp = None
            else:
                rp.set_url(robots_url)
                rp.read()
        except Exception:
            rp = None
        _robots_cache[origin] = rp

    rp = _robots_cache.get(origin)
    if rp is None:
        return True
    return rp.can_fetch(USER_AGENT, url)


def _http_get(url: str, session=None, timeout: int = 30) -> str | None:
    """带 robots 检查与 User-Agent 的 GET。"""
    sess = session or _get_session()
    if not _can_fetch(url, sess):
        print(f"  [robots] 禁止抓取: {url}")
        return None
    try:
        r = sess.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout)
        r.raise_for_status()
        r.encoding = r.apparent_encoding or "utf-8"
        return r.text
    except Exception as exc:
        print(f"  [网络] {url}: {exc}")
        return None


def fetch_community_articles(
    max_per_source: int = 20,
    cache_dir: Path | None = None,
) -> list[dict[str, str]]:
    """
    从 FreeBuf / 先知社区公开页面拉取文章标题与链接。

    Returns:
        [{"title": ..., "url": ..., "source": "freebuf_rss"}, ...]
    """
    session = _get_session()
    articles: list[dict[str, str]] = []
    seen_urls: set[str] = set()

    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)

    print("[Community] 拉取安全社区文章列表 ...")
    any_ok = False

    for spec in COMMUNITY_SOURCES:
        name = spec["name"]
        url = spec["url"]
        text = _http_get(url, session)
        time.sleep(REQUEST_DELAY_SEC)

        if not text:
            continue
        any_ok = True

        if cache_dir:
            (cache_dir / f"{name}.html").write_text(text, encoding="utf-8", errors="replace")

        batch: list[dict[str, str]] = []

        if spec["type"] == "rss":
            for m in _RSS_ITEM.finditer(text):
                title = re.sub(r"<[^>]+>", "", m.group(1)).strip()
                link = m.group(2).strip()
                if not link or link in seen_urls:
                    continue
                if not _PAYLOAD_INLINE.search(title) and not any(
                    kw in title.lower()
                    for kw in ("waf", "sql", "xss", "注入", "绕过", "payload", "web")
                ):
                    continue
                seen_urls.add(link)
                batch.append({"title": title, "url": link, "source": name})
        else:
            base = spec["base"]
            for m in _HTML_LINK.finditer(text):
                href, title = m.group(1).strip(), m.group(2).strip()
                if not title or len(title) < 6:
                    continue
                full = urljoin(base, href)
                if full in seen_urls:
                    continue
                if not any(
                    kw in title.lower() or kw in full.lower()
                    for kw in ("waf", "sql", "xss", "inject", "bypass", "注入", "绕过", "payload")
                ):
                    continue
                seen_urls.add(full)
                batch.append({"title": title, "url": full, "source": name})

        batch = batch[:max_per_source]
        articles.extend(batch)
        print(f"  [{name}] {len(batch)} 篇")

    if not any_ok:
        print(f"[Community] {_MANUAL_FALLBACK_MSG}")

    return articles


def parse_payloads_from_text(text: str, parse_md: bool = True) -> list[str]:
    """
    从文章正文或种子文件文本提取载荷行。

    支持：纯文本行、Markdown 代码块、反引号内联、HTML <code> 片段。
    """
    lines: list[str] = []
    seen: set[str] = set()

    def _add(raw: str) -> None:
        s = raw.strip().strip("'\"")
        if not s or _COMMENT_LINE.match(s):
            return
        if len(s) < 3 or len(s) > 4096:
            return
        if s.lower().startswith(("note:", "example:", "//", "http://", "https://")):
            return
        if s not in seen:
            seen.add(s)
            lines.append(s)

    if parse_md:
        for block in _MD_CODE_BLOCK.findall(text):
            for line in block.splitlines():
                _add(line)
        for m in re.finditer(r"`([^`\n]{4,512})`", text):
            _add(m.group(1))
        for m in re.finditer(r"<code[^>]*>([^<]{4,512})</code>", text, re.IGNORECASE):
            _add(m.group(1))

    for line in text.splitlines():
        line = line.strip()
        if not line or _COMMENT_LINE.match(line):
            continue
        if line.startswith("//") or line.lower().startswith("note:"):
            continue
        _add(line)

    return lines


def _default_seed_path() -> Path:
    return Path(__file__).resolve().parents[3] / "data" / "raw" / "community" / "payloads_seed.txt"


def iter_seed_payloads(seed_path: Path | None = None) -> Iterator[dict[str, str]]:
    """迭代本地 community 种子文件中的载荷。"""
    path = seed_path or _default_seed_path()
    if not path.exists():
        return

    text = path.read_text(encoding="utf-8", errors="replace")
    for line in parse_payloads_from_text(text, parse_md=False):
        label = infer_attack_label(line)
        if label == "Normal":
            label = infer_attack_label(line, "SQLi")
        yield {
            "payload": line[:2048],
            "label": label,
            "source": "community:payloads_seed",
        }


def iter_community_payloads(
    seed_path: Path | None = None,
    cache_dir: Path | None = None,
    fetch_articles: bool = True,
    max_articles: int = 10,
    article_delay_sec: float = 1.5,
) -> Iterator[dict[str, str]]:
    """
    合并种子文件与（可选）社区文章正文中解析出的载荷。

    网络/robots 失败时仅产出种子文件内容。
    """
    yield from iter_seed_payloads(seed_path)

    if not fetch_articles:
        return

    articles = fetch_community_articles(max_per_source=max_articles, cache_dir=cache_dir)
    if not articles:
        return

    session = _get_session()
    cache_dir = cache_dir or (seed_path or _default_seed_path()).parent / "articles"
    cache_dir.mkdir(parents=True, exist_ok=True)

    fetched_payloads = 0
    for i, art in enumerate(articles[:max_articles]):
        url = art["url"]
        if not _can_fetch(url, session):
            continue
        body = _http_get(url, session)
        time.sleep(article_delay_sec)
        if not body:
            continue

        slug = re.sub(r"[^\w\-]", "_", urlparse(url).path[-60:]) or f"art_{i}"
        (cache_dir / f"{slug}.html").write_text(body, encoding="utf-8", errors="replace")

        for payload in parse_payloads_from_text(body):
            label = infer_attack_label(payload)
            if label == "Normal":
                continue
            fetched_payloads += 1
            yield {
                "payload": payload[:2048],
                "label": label,
                "source": f"community:{art['source']}",
            }

    print(f"[Community] 文章正文解析载荷: {fetched_payloads} 条")


def collect_community_rows(
    community_dir: Path,
    fetch_articles: bool = True,
) -> list[dict[str, str]]:
    """供 dataset_agent 调用的批量收集接口。"""
    seed = community_dir / "payloads_seed.txt"
    rows = list(
        iter_community_payloads(
            seed_path=seed,
            cache_dir=community_dir / "cache",
            fetch_articles=fetch_articles,
        )
    )
    print(f"[Community] 社区情报合计: {len(rows)} 条")
    return rows
