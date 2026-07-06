"""
connections.py — All External Connections
==========================================
Manages:
  - Anthropic AI client (text + vision)
  - Brave Search API
  - DuckDuckGo fallback search
  - Wikipedia API
  - General web page fetcher
  - HTTP client pool
"""

import asyncio
import base64
import hashlib
import json
import re
import time
import urllib.parse
from pathlib import Path
from typing import Any

import httpx

import config as cfg

# ══════════════════════════════════════════════════════
# HTTP CLIENT (shared connection pool)
# ══════════════════════════════════════════════════════
_client: httpx.AsyncClient | None = None

def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(cfg.AI_TIMEOUT, connect=10.0),
            http2=True,
            follow_redirects=True,
            headers={"User-Agent": f"{cfg.APP_NAME}/{cfg.APP_VERSION}"},
        )
    return _client

async def close_client():
    global _client
    if _client:
        await _client.aclose()
        _client = None

# ══════════════════════════════════════════════════════
# IN-MEMORY CACHE
# ══════════════════════════════════════════════════════
_cache: dict[str, tuple[float, Any]] = {}

def _ck(prefix: str, key: str) -> str:
    return f"{prefix}:{hashlib.sha256(key.encode()).hexdigest()[:16]}"

def cache_get(key: str) -> Any | None:
    entry = _cache.get(key)
    if entry and time.monotonic() < entry[0]:
        return entry[1]
    _cache.pop(key, None)
    return None

def cache_set(key: str, value: Any, ttl: int = cfg.CACHE_TTL_SECONDS):
    _cache[key] = (time.monotonic() + ttl, value)

def cache_clear():
    _cache.clear()

# ══════════════════════════════════════════════════════
# ANTHROPIC AI — TEXT
# ══════════════════════════════════════════════════════

async def ai_text(system: str, prompt: str, use_cache: bool = True) -> str:
    """Call Claude for text tasks. Cached by default."""
    ck = _ck("ai", system[:50] + prompt[:100])
    if use_cache:
        cached = cache_get(ck)
        if cached:
            return cached

    headers = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-api-key": cfg.ANTHROPIC_API_KEY,
    }
    body = {
        "model": cfg.ANTHROPIC_MODEL,
        "max_tokens": cfg.AI_MAX_TOKENS,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }
    resp = await get_client().post(
        "https://api.anthropic.com/v1/messages",
        headers=headers, json=body
    )
    resp.raise_for_status()
    result = "".join(b.get("text", "") for b in resp.json().get("content", []))

    if use_cache:
        cache_set(ck, result, cfg.AI_CACHE_TTL)
    return result

def _parse_json(raw: str) -> Any:
    """Strip markdown fences and parse JSON safely."""
    c = raw.strip()
    if c.startswith("```"):
        lines = c.split("\n")
        c = "\n".join(lines[1:]).rsplit("```", 1)[0]
    m = re.search(r'[\[{][\s\S]*[\]}]', c)
    return json.loads(m.group(0) if m else c.strip())

# ══════════════════════════════════════════════════════
# ANTHROPIC AI — VISION (image understanding)
# ══════════════════════════════════════════════════════

async def ai_vision(image_bytes: bytes, media_type: str, prompt: str) -> str:
    """
    Send an image to Claude Vision.
    Handles: bad handwriting, diagrams, photos of text, whiteboard shots.
    """
    # Resize if too large
    if len(image_bytes) > cfg.VISION_MAX_BYTES:
        image_bytes = _resize_image(image_bytes)

    b64 = base64.standard_b64encode(image_bytes).decode()

    headers = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-api-key": cfg.ANTHROPIC_API_KEY,
    }
    body = {
        "model": cfg.ANTHROPIC_VISION,
        "max_tokens": cfg.AI_MAX_TOKENS,
        "messages": [{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": b64,
                    }
                },
                {"type": "text", "text": prompt}
            ]
        }]
    }
    resp = await get_client().post(
        "https://api.anthropic.com/v1/messages",
        headers=headers, json=body
    )
    resp.raise_for_status()
    return "".join(b.get("text", "") for b in resp.json().get("content", []))

def _resize_image(data: bytes) -> bytes:
    """Resize image bytes to under VISION_MAX_BYTES using Pillow if available."""
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(data))
        img.thumbnail((1500, 1500), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=75)
        return buf.getvalue()
    except Exception:
        return data[:cfg.VISION_MAX_BYTES]

# ══════════════════════════════════════════════════════
# AI CHAT (multi-turn conversation)
# ══════════════════════════════════════════════════════

async def ai_chat(messages: list[dict], context: str = "") -> str:
    """Multi-turn chat with optional study material context."""
    system = (
        f"You are StudyMind Pro, an advanced AI study tutor with access to web search and "
        f"document analysis tools. You are knowledgeable, clear, and encouraging.\n\n"
        f"{'Study material context:\n---\n' + context[:3000] + '\n---' if context else ''}"
    )
    headers = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
        "x-api-key": cfg.ANTHROPIC_API_KEY,
    }
    body = {
        "model": cfg.ANTHROPIC_MODEL,
        "max_tokens": cfg.AI_MAX_TOKENS,
        "system": system,
        "messages": messages[-20:],
    }
    resp = await get_client().post(
        "https://api.anthropic.com/v1/messages",
        headers=headers, json=body
    )
    resp.raise_for_status()
    return "".join(b.get("text", "") for b in resp.json().get("content", []))

# ══════════════════════════════════════════════════════
# BRAVE SEARCH (primary search engine)
# ══════════════════════════════════════════════════════

async def search_brave(query: str) -> list[dict]:
    """Search using Brave API. Returns list of {title, url, description}."""
    if not cfg.BRAVE_API_KEY:
        return []

    ck = _ck("brave", query)
    cached = cache_get(ck)
    if cached:
        return cached

    try:
        resp = await get_client().get(
            cfg.BRAVE_SEARCH_URL,
            headers={
                "Accept": "application/json",
                "Accept-Encoding": "gzip",
                "X-Subscription-Token": cfg.BRAVE_API_KEY,
            },
            params={"q": query, "count": cfg.SEARCH_MAX_RESULTS, "safesearch": "moderate"},
            timeout=cfg.SEARCH_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        results = [
            {
                "title": r.get("title", ""),
                "url": r.get("url", ""),
                "description": r.get("description", ""),
                "source": "brave",
            }
            for r in data.get("web", {}).get("results", [])
        ]
        cache_set(ck, results, cfg.SEARCH_CACHE_TTL)
        return results
    except Exception as e:
        return []

# ══════════════════════════════════════════════════════
# DUCKDUCKGO SEARCH (fallback, no API key needed)
# ══════════════════════════════════════════════════════

async def search_duckduckgo(query: str) -> list[dict]:
    """DuckDuckGo Instant Answer API — free, no key."""
    if not cfg.DUCKDUCKGO_ENABLED:
        return []

    ck = _ck("ddg", query)
    cached = cache_get(ck)
    if cached:
        return cached

    try:
        # DDG HTML search (parse results)
        resp = await get_client().get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers={"User-Agent": "Mozilla/5.0 (compatible; StudyMindPro/1.0)"},
            timeout=cfg.SEARCH_TIMEOUT,
        )
        # Simple regex extract of results
        results = []
        pattern = re.compile(
            r'class="result__a"[^>]*href="([^"]+)"[^>]*>([^<]+)<.*?'
            r'class="result__snippet"[^>]*>([^<]+)<',
            re.DOTALL
        )
        for m in pattern.finditer(resp.text):
            url, title, snippet = m.group(1), m.group(2).strip(), m.group(3).strip()
            if url.startswith("http"):
                results.append({"title": title, "url": url,
                                 "description": snippet, "source": "duckduckgo"})
            if len(results) >= cfg.DDG_MAX_RESULTS:
                break

        # Also hit the JSON API for instant answers
        ia_resp = await get_client().get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_html": "1", "no_redirect": "1"},
            timeout=cfg.SEARCH_TIMEOUT,
        )
        ia = ia_resp.json()
        if ia.get("AbstractText"):
            results.insert(0, {
                "title": ia.get("Heading", query),
                "url": ia.get("AbstractURL", ""),
                "description": ia.get("AbstractText", "")[:500],
                "source": "duckduckgo_ia",
            })

        cache_set(ck, results, cfg.SEARCH_CACHE_TTL)
        return results
    except Exception:
        return []

# ══════════════════════════════════════════════════════
# WIKIPEDIA
# ══════════════════════════════════════════════════════

async def search_wikipedia(query: str) -> dict | None:
    """Fetch Wikipedia summary for a topic."""
    if not cfg.WIKIPEDIA_ENABLED:
        return None

    ck = _ck("wiki", query)
    cached = cache_get(ck)
    if cached:
        return cached

    try:
        # Search for article
        search_resp = await get_client().get(
            f"https://{cfg.WIKIPEDIA_LANGUAGE}.wikipedia.org/w/api.php",
            params={
                "action": "query", "list": "search", "srsearch": query,
                "format": "json", "srlimit": "1",
            },
            timeout=cfg.SEARCH_TIMEOUT,
        )
        results = search_resp.json().get("query", {}).get("search", [])
        if not results:
            return None

        title = results[0]["title"]

        # Fetch summary
        summary_resp = await get_client().get(
            f"https://{cfg.WIKIPEDIA_LANGUAGE}.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(title)}",
            timeout=cfg.SEARCH_TIMEOUT,
        )
        data = summary_resp.json()
        result = {
            "title": data.get("title", title),
            "summary": data.get("extract", "")[:1500],
            "url": data.get("content_urls", {}).get("desktop", {}).get("page", ""),
            "source": "wikipedia",
        }
        cache_set(ck, result, cfg.SEARCH_CACHE_TTL)
        return result
    except Exception:
        return None

# ══════════════════════════════════════════════════════
# WEB PAGE FETCHER (fetch and clean any URL)
# ══════════════════════════════════════════════════════

async def fetch_page(url: str) -> str:
    """Fetch a web page and extract clean text content."""
    ck = _ck("page", url)
    cached = cache_get(ck)
    if cached:
        return cached

    try:
        resp = await get_client().get(url, timeout=cfg.SEARCH_TIMEOUT)
        resp.raise_for_status()
        html = resp.text

        # Strip scripts, styles, HTML tags
        html = re.sub(r'<script[^>]*>[\s\S]*?</script>', '', html, flags=re.IGNORECASE)
        html = re.sub(r'<style[^>]*>[\s\S]*?</style>', '', html, flags=re.IGNORECASE)
        html = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', html).strip()
        result = text[:5000]

        cache_set(ck, result, cfg.SEARCH_CACHE_TTL)
        return result
    except Exception as e:
        return f"Could not fetch page: {e}"

# ══════════════════════════════════════════════════════
# COMBINED SEARCH (tries all sources, merges results)
# ══════════════════════════════════════════════════════

async def search_all(query: str) -> dict:
    """
    Run Brave + DuckDuckGo + Wikipedia in parallel.
    Returns combined results with sources labeled.
    """
    tasks = [
        search_brave(query),
        search_duckduckgo(query),
        search_wikipedia(query),
    ]
    brave_r, ddg_r, wiki_r = await asyncio.gather(*tasks, return_exceptions=True)

    web_results = []
    if isinstance(brave_r, list):
        web_results.extend(brave_r)
    if isinstance(ddg_r, list):
        # Deduplicate by URL
        existing_urls = {r["url"] for r in web_results}
        web_results.extend(r for r in ddg_r if r["url"] not in existing_urls)

    return {
        "web": web_results[:8],
        "wikipedia": wiki_r if isinstance(wiki_r, dict) else None,
        "query": query,
        "sources_used": (
            (["brave"] if isinstance(brave_r, list) and brave_r else []) +
            (["duckduckgo"] if isinstance(ddg_r, list) and ddg_r else []) +
            (["wikipedia"] if isinstance(wiki_r, dict) else [])
        ),
    }

# ══════════════════════════════════════════════════════
# SEARCH + AI ANSWER (search then synthesize)
# ══════════════════════════════════════════════════════

async def search_and_answer(query: str, context: str = "") -> dict:
    """
    Full pipeline:
    1. Search multiple sources
    2. Feed results to AI
    3. Return grounded answer with sources
    """
    search_data = await search_all(query)

    # Build context for AI
    snippets = []
    if search_data["wikipedia"]:
        w = search_data["wikipedia"]
        snippets.append(f"[Wikipedia] {w['title']}: {w['summary']}")

    for r in search_data["web"][:4]:
        snippets.append(f"[{r['source'].title()}] {r['title']}: {r['description']}")

    search_context = "\n\n".join(snippets)

    system = (
        "You are StudyMind Pro, an AI tutor with live web search capability. "
        "Answer the student's question using the provided search results. "
        "Be accurate, cite sources, and explain clearly. "
        "If the search results don't cover the question well, say so honestly."
    )

    user_prompt = (
        f"Question: {query}\n\n"
        f"{'Student context: ' + context[:500] + chr(10) + chr(10) if context else ''}"
        f"Search results:\n{search_context}\n\n"
        f"Provide a clear, well-sourced answer."
    )

    answer = await ai_text(system, user_prompt, use_cache=False)

    return {
        "answer": answer,
        "sources": search_data["web"][:5],
        "wikipedia": search_data["wikipedia"],
        "sources_used": search_data["sources_used"],
    }
