"""
Agentic crawl fallback for the Tradecraft Lookup tool.

When `_detect_type` returns `agentic-crawl`, this bounded LLM-driven
Playwright loop runs once at verify time to build a sitemap of the
user-added knowledge URL. Hard caps on pages, LLM calls, time, and depth.

Designed as a swappable interface so a future v2 can drop in `browser-use`
behind the same `agentic_crawl(url, bounds, llm, mcp_manager) -> CrawlResult`
function signature.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from logging_config import get_logger

logger = get_logger(__name__)

USER_AGENT = "RedAmon-Tradecraft/1.0"

# Junk path patterns (auth pages, archives, metadata). Borrowed from tradecraft_lookup.
NOISE_PATH_PATTERNS = re.compile(
    r"^/?(login|signup|register|privacy|cookies|contact|about|tos|terms|"
    r"author/|tag/|category/|page/\d+|feed|rss|sitemap|search)",
    re.IGNORECASE,
)
NOISE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".css", ".js", ".woff", ".woff2", ".ttf", ".otf",
    ".zip", ".tar", ".gz", ".7z", ".mp4", ".mp3",
)


@dataclass
class CrawlResult:
    sitemap_entries: List[Dict[str, str]] = field(default_factory=list)
    stopped_because: str = ""
    stats: Dict[str, Any] = field(default_factory=dict)


@dataclass
class _CrawlState:
    base_host: str
    visited: set = field(default_factory=set)
    frontier: List[Tuple[str, int]] = field(default_factory=list)
    sitemap: List[Dict[str, str]] = field(default_factory=list)
    pages_fetched: int = 0
    llm_calls: int = 0
    started_at: float = field(default_factory=time.time)


def _canonicalize(url: str) -> str:
    try:
        u = urllib.parse.urlsplit(url)
        scheme = (u.scheme or "https").lower()
        netloc = u.netloc.lower()
        path = u.path or "/"
        qs = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        qs.sort()
        query = urllib.parse.urlencode(qs)
        return urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    except Exception:
        return url


def _looks_like_noise(href: str) -> bool:
    if not href:
        return True
    if href.startswith(("mailto:", "javascript:", "tel:", "#")):
        return True
    lower = href.lower()
    for ext in NOISE_EXTENSIONS:
        if lower.endswith(ext):
            return True
    try:
        path = urllib.parse.urlsplit(href).path or "/"
        if NOISE_PATH_PATTERNS.match(path):
            return True
    except Exception:
        return True
    return False


def _same_host(href: str, base_host: str) -> bool:
    try:
        u = urllib.parse.urlsplit(href)
        return (u.hostname or "").lower() == base_host
    except Exception:
        return False


def _is_private_host(host: str) -> bool:
    """Lightweight private-IP check; defers heavier validation to caller."""
    if not host:
        return True
    h = host.lower()
    if h in ("localhost", "::1") or h.endswith(".local") or h.endswith(".internal"):
        return True
    return False


async def _http_fetch(url: str, timeout: int = 15) -> str:
    """Plain Tier 1 HTTP fetch, returns raw HTML or '' on failure.

    Used by the crawl loop FIRST so static blogs / news sites / writeup pages
    get fast unencumbered fetches. Falls back to Playwright only when the
    response is thin or non-HTML.
    """
    try:
        import httpx as _httpx  # local import keeps top-of-module deps clean
        async with _httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml",
            },
        ) as client:
            resp = await client.get(url)
            ct = (resp.headers.get("content-type") or "").lower()
            if resp.status_code != 200 or "html" not in ct:
                return ""
            return resp.text
    except Exception as e:
        logger.debug(f"[tradecraft] crawl http fetch error url={url} err={e}")
        return ""


async def _crawl_fetch(url: str, mcp_manager, *, tier1_threshold_bytes: int = 4000) -> Tuple[str, int]:
    """Tier-1-first fetch for the crawl loop.

    Returns (html, tier_used). Tries raw HTTP first; if response is < threshold
    bytes (likely a JS-only shell or empty body), escalates to Playwright MCP
    for full rendering. The threshold is intentionally higher than Tier 1's
    800-byte default for tradecraft fetches because crawl pages need many
    visible links, not just any content.
    """
    html = await _http_fetch(url)
    if html and len(html) >= tier1_threshold_bytes:
        return html, 1
    # Fallback to Playwright (handles SPAs, login walls, anti-bot challenges).
    rendered = await _playwright_fetch(url, mcp_manager)
    return rendered, 2 if rendered else 0


async def _playwright_fetch(url: str, mcp_manager) -> str:
    """Fetch a URL via the existing execute_playwright MCP tool. Returns rendered HTML, or "" on failure."""
    if mcp_manager is None:
        return ""
    try:
        tools = await mcp_manager.get_tools()
    except Exception as e:
        logger.warning(f"[tradecraft] crawl mcp tools error: {e}")
        return ""
    playwright = next((t for t in tools if getattr(t, "name", "") == "execute_playwright"), None)
    if playwright is None:
        return ""
    try:
        out = await playwright.ainvoke({"url": url, "format": "html"})
    except Exception as e:
        logger.warning(f"[tradecraft] crawl playwright error url={url} err={e}")
        return ""
    if isinstance(out, str):
        return out
    if isinstance(out, list):
        text = ""
        for it in out:
            if isinstance(it, dict) and "text" in it:
                text += it["text"]
        return text
    if isinstance(out, dict) and "text" in out:
        return out["text"]
    return ""


def _extract_links_and_meta(html: str, base_url: str) -> Dict[str, Any]:
    """Return {title, body_text, links[{title,href}], hints{search_box,pagination,tag_cloud}}."""
    try:
        from bs4 import BeautifulSoup  # type: ignore
    except Exception:
        return {"title": "", "body_text": html or "", "links": [], "hints": {}}
    soup = BeautifulSoup(html or "", "html.parser")
    # Title
    title = ""
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    if not title:
        h1 = soup.find("h1")
        title = h1.get_text(strip=True) if h1 else ""
    # Drop noise containers before extracting body text
    for sel in ["nav", "footer", "header", "aside", "script", "style", "form", "iframe"]:
        for el in soup.select(sel):
            el.decompose()
    body_text = soup.get_text(" ", strip=True)
    # Links from the (stripped) page; but for navigation we want links from
    # the original document including nav, so re-soup the original HTML once
    # for href harvesting only.
    soup2 = BeautifulSoup(html or "", "html.parser")
    links_seen: set = set()
    links: List[Dict[str, str]] = []
    for a in soup2.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href:
            continue
        # Resolve relative
        absolute = urllib.parse.urljoin(base_url + "/" if not base_url.endswith("/") else base_url, href)
        canon = _canonicalize(absolute)
        if canon in links_seen:
            continue
        links_seen.add(canon)
        anchor = a.get_text(strip=True)
        if not anchor:
            anchor = a.get("title") or canon
        anchor = (anchor or "")[:80]
        links.append({"title": anchor, "href": canon})
    # Hints
    hints = {
        "search_box": bool(soup2.find("input", {"type": "search"}) or soup2.select_one("[role='search']")),
        "pagination": bool(re.search(r"older posts|next page|page/\d+", html or "", re.IGNORECASE)),
        "tag_cloud": [
            (a.get_text(strip=True) or "").lower()
            for a in soup2.select(".tag, .tags a, .tag-cloud a")[:8]
            if a.get_text(strip=True)
        ],
    }
    return {"title": title, "body_text": body_text, "links": links, "hints": hints}


_PROMPT_TEMPLATE = """\
You are building a sitemap of pentest/security content from a website
the user added as a tradecraft reference. Pick links to follow next.
Prefer high-signal paths (technique pages, payload writeups, tool guides,
CVE analyses). Avoid low-signal (login, blog metadata, author bios,
empty archive index pages).

Site:    {base}
Just visited: {current}  (depth {depth})

Budget remaining: {pages_remaining} pages, {calls_remaining} calls, {seconds_remaining}s wall clock

Sitemap so far ({sitemap_len}): random sample of titles
{sitemap_sample}

Unvisited links on this page:
{links_block}

Page hints: search_box={search_box}, pagination={pagination}, tag_cloud={tag_cloud}

Reply ONLY with JSON. Two valid shapes:
  {{"action": "stop", "reason": "..."}}
  {{"action": "follow", "indices": [1, 4, 7], "reason": "..."}}
"""


async def _llm_decide(
    *,
    llm,
    base_url: str,
    current_url: str,
    depth: int,
    state: _CrawlState,
    bounds: Dict[str, int],
    candidates: List[Dict[str, str]],
    hints: Dict[str, Any],
    retry_strict: bool = False,
) -> Tuple[str, List[int], str]:
    """Returns (action, indices, reason). action is 'stop' or 'follow'."""
    pages_remaining = max(0, bounds.get("max_pages", 30) - state.pages_fetched)
    calls_remaining = max(0, bounds.get("max_llm_calls", 20) - state.llm_calls)
    seconds_remaining = max(0, int(bounds.get("time_budget_sec", 180) - (time.time() - state.started_at)))
    sample_titles = [e.get("title", "") for e in state.sitemap[-10:]]
    sitemap_sample = "\n".join(f"  - {t}" for t in sample_titles) or "  (none yet)"
    links_block = "\n".join(
        f"  {i+1}. \"{c.get('title','')[:80]}\" -> {urllib.parse.urlsplit(c['href']).path or c['href']}"
        for i, c in enumerate(candidates[:20])
    ) or "  (none)"
    prompt = _PROMPT_TEMPLATE.format(
        base=base_url,
        current=current_url,
        depth=depth,
        pages_remaining=pages_remaining,
        calls_remaining=calls_remaining,
        seconds_remaining=seconds_remaining,
        sitemap_len=len(state.sitemap),
        sitemap_sample=sitemap_sample,
        links_block=links_block,
        search_box=hints.get("search_box", False),
        pagination=hints.get("pagination", False),
        tag_cloud=hints.get("tag_cloud", []),
    )
    if retry_strict:
        prompt += "\n\nReturn ONLY a single line of valid JSON. No prose, no fenced block."
    try:
        state.llm_calls += 1
        resp = await llm.ainvoke(prompt)
        content = (getattr(resp, "content", "") or "").strip()
        # Strip code fences
        m = re.search(r"\{.*\}", content, re.DOTALL)
        if not m:
            raise ValueError(f"no JSON object in LLM response: {content[:120]}")
        data = json.loads(m.group(0))
    except Exception as e:
        logger.warning(f"[tradecraft] crawl llm parse error: {e}")
        if not retry_strict:
            return await _llm_decide(
                llm=llm, base_url=base_url, current_url=current_url, depth=depth,
                state=state, bounds=bounds, candidates=candidates, hints=hints,
                retry_strict=True,
            )
        return ("stop", [], f"llm json parse failure: {e}")
    action = (data.get("action") or "stop").lower()
    if action not in ("stop", "follow"):
        action = "stop"
    indices = data.get("indices") or []
    if not isinstance(indices, list):
        indices = []
    indices = [int(i) for i in indices if isinstance(i, (int, str)) and str(i).isdigit()]
    reason = (data.get("reason") or "")[:200]
    return action, indices, reason


async def agentic_crawl(
    url: str,
    *,
    bounds: Dict[str, int],
    llm,
    mcp_manager,
) -> CrawlResult:
    """Bounded LLM-driven Playwright loop. Returns CrawlResult.

    bounds keys: max_pages, max_llm_calls, time_budget_sec, max_depth
    """
    base = _canonicalize(url)
    parsed = urllib.parse.urlsplit(base)
    base_host = (parsed.hostname or "").lower()
    if not base_host:
        return CrawlResult(stopped_because="invalid base url", stats={})
    state = _CrawlState(base_host=base_host)
    state.frontier.append((base, 0))
    max_pages = int(bounds.get("max_pages", 30))
    max_llm = int(bounds.get("max_llm_calls", 20))
    time_budget = int(bounds.get("time_budget_sec", 180))
    max_depth = int(bounds.get("max_depth", 3))

    if llm is None:
        # Without an LLM we cannot drive the loop. Return a single-page sitemap.
        html, _ = await _crawl_fetch(base, mcp_manager)
        meta = _extract_links_and_meta(html, base)
        if meta["title"] and len(meta["body_text"]) > 500:
            state.sitemap.append({"title": meta["title"], "path": base})
        return CrawlResult(
            sitemap_entries=state.sitemap,
            stopped_because="no llm available",
            stats={"pages_fetched": 1, "llm_calls": 0, "elapsed_sec": int(time.time() - state.started_at)},
        )

    stopped = ""
    while state.frontier:
        if state.pages_fetched >= max_pages:
            stopped = "max pages"
            break
        if state.llm_calls >= max_llm:
            stopped = "max llm calls"
            break
        if (time.time() - state.started_at) >= time_budget:
            stopped = "time budget"
            break

        current, depth = state.frontier.pop(0)
        canon = _canonicalize(current)
        if canon in state.visited:
            continue
        state.visited.add(canon)

        # Tier-1-first fetch: try plain HTTP, fall back to Playwright on
        # thin / non-HTML / failed responses. Most static blogs return rich
        # HTML on Tier 1 and never need Playwright -> dramatically more
        # links per page than Playwright alone (which hits a 40k cap).
        html, fetch_tier = await _crawl_fetch(canon, mcp_manager)
        state.pages_fetched += 1
        if not html:
            continue
        meta = _extract_links_and_meta(html, canon)
        title = meta["title"]
        body_text = meta["body_text"]
        # Add to sitemap if page has content
        if title and len(body_text) > 500:
            state.sitemap.append({"title": title, "path": canon})

        # Filter and dedupe candidate links
        candidates: List[Dict[str, str]] = []
        for link in meta["links"]:
            href = link.get("href") or ""
            if _looks_like_noise(href):
                continue
            if not _same_host(href, base_host):
                continue
            link_host = (urllib.parse.urlsplit(href).hostname or "").lower()
            if _is_private_host(link_host):
                continue
            if _canonicalize(href) in state.visited:
                continue
            if any(_canonicalize(href) == _canonicalize(f[0]) for f in state.frontier):
                continue
            candidates.append({"title": link.get("title", ""), "href": href})
            if len(candidates) >= 20:
                break

        logger.info(
            f"[tradecraft] crawl iter url={canon} depth={depth} "
            f"page={state.pages_fetched}/{max_pages} "
            f"tier={fetch_tier} html_bytes={len(html)} body_chars={len(body_text)} "
            f"raw_links={len(meta['links'])} candidates={len(candidates)}"
        )

        if depth + 1 > max_depth:
            # We can still mine the page but won't enqueue further.
            continue
        if not candidates:
            continue

        action, indices, reason = await _llm_decide(
            llm=llm,
            base_url=base,
            current_url=canon,
            depth=depth,
            state=state,
            bounds=bounds,
            candidates=candidates,
            hints=meta["hints"],
        )
        logger.info(
            f"[tradecraft] crawl iter action={action} indices={indices} reason={reason!r}"
        )
        if action == "stop":
            stopped = reason or "llm stop"
            break
        for idx in indices:
            i = idx - 1
            if 0 <= i < len(candidates):
                state.frontier.append((candidates[i]["href"], depth + 1))

    if not stopped:
        stopped = "frontier empty"

    elapsed = int(time.time() - state.started_at)
    logger.info(
        f"[tradecraft] crawl done url={base} pages={state.pages_fetched} "
        f"calls={state.llm_calls} elapsed={elapsed}s stopped_because={stopped}"
    )
    return CrawlResult(
        sitemap_entries=state.sitemap,
        stopped_because=stopped,
        stats={
            "pages_fetched": state.pages_fetched,
            "llm_calls": state.llm_calls,
            "elapsed_sec": elapsed,
        },
    )
