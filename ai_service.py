"""
app/services/ai_service.py
──────────────────────────
Business logic layer for all AI operations.
Keeps API routes thin — all Claude calls live here.
"""

import json

import httpx

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)


class AIService:
    """
    Thin async wrapper around the Anthropic Messages API.
    Each method calls Claude, parses JSON, and returns typed dicts.
    """

    _BASE_URL = "https://api.anthropic.com/v1/messages"
    _HEADERS = {
        "Content-Type": "application/json",
        "anthropic-version": "2023-06-01",
    }

    def __init__(self) -> None:
        # httpx.AsyncClient with connection pooling + timeout
        self._client = httpx.AsyncClient(
            timeout=settings.AI_TIMEOUT_SECONDS,
            http2=True,
        )

    async def _call(self, system: str, user: str) -> str:
        """Send a request to Claude and return the raw text response."""
        if settings.ANTHROPIC_API_KEY:
            headers = {**self._HEADERS, "x-api-key": settings.ANTHROPIC_API_KEY}
        else:
            headers = self._HEADERS  # relies on built-in auth in claude.ai context

        payload = {
            "model": settings.ANTHROPIC_MODEL,
            "max_tokens": settings.AI_MAX_TOKENS,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }

        resp = await self._client.post(self._BASE_URL, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return "".join(b.get("text", "") for b in data.get("content", []))

    def _parse_json(self, raw: str) -> dict | list:
        """Strip markdown fences and parse JSON. Raises ValueError on failure."""
        clean = raw.strip()
        if clean.startswith("```"):
            clean = clean.split("\n", 1)[1] if "\n" in clean else clean
            clean = clean.rsplit("```", 1)[0]
        return json.loads(clean.strip())

    # ── Feature methods ───────────────────────────────────────────────────────

    async def summarize(self, text: str) -> dict:
        system = "You are an expert academic summarizer. Return ONLY valid JSON, no markdown."
        prompt = f"""Summarize this study material. Return JSON:
{{"tldr":"one sentence summary","key_points":["p1","p2","p3","p4","p5"],"concepts":["c1","c2","c3"],"importance":"why this topic matters in 2 sentences"}}

Material:
{text[:4000]}"""
        raw = await self._call(system, prompt)
        return self._parse_json(raw)

    async def flashcards(self, text: str) -> list:
        system = "You are a flashcard expert. Return ONLY valid JSON, no markdown."
        prompt = f"""Create 8 high-quality flashcards. Vary difficulty.
Return JSON array: [{{"q":"question","a":"answer","hint":"hint","difficulty":"easy|medium|hard"}}]

Material:
{text[:4000]}"""
        raw = await self._call(system, prompt)
        return self._parse_json(raw)

    async def quiz(self, text: str) -> list:
        system = "You are a quiz master. Return ONLY valid JSON, no markdown."
        prompt = f"""Create 6 multiple-choice questions.
Return JSON: [{{"q":"question","options":["A","B","C","D"],"answer":0,"explanation":"why correct"}}]
(answer is 0-indexed)

Material:
{text[:4000]}"""
        raw = await self._call(system, prompt)
        return self._parse_json(raw)

    async def mindmap(self, text: str) -> dict:
        system = "You are a knowledge-structure expert. Return ONLY valid JSON, no markdown."
        prompt = f"""Build a mind map from this material.
Return JSON: {{"root":"main topic","branches":[{{"name":"branch","leaves":["leaf1","leaf2","leaf3"]}}]}}
4-6 branches, 3-5 leaves each.

Material:
{text[:4000]}"""
        raw = await self._call(system, prompt)
        return self._parse_json(raw)

    async def key_terms(self, text: str) -> list:
        system = "You are a glossary expert. Return ONLY valid JSON, no markdown."
        prompt = f"""Extract 10 key terms. Return JSON:
[{{"term":"name","definition":"1-2 sentence definition"}}]

Material:
{text[:4000]}"""
        raw = await self._call(system, prompt)
        return self._parse_json(raw)

    async def study_plan(self, text: str) -> list:
        system = "You are a learning designer. Return ONLY valid JSON, no markdown."
        prompt = f"""Create a 5-day study plan.
Return JSON: [{{"day":1,"title":"Day title","tasks":"comma separated activities"}}]

Material:
{text[:4000]}"""
        raw = await self._call(system, prompt)
        return self._parse_json(raw)

    async def chat(self, message: str, context: str, history: list[dict]) -> str:
        """Multi-turn chat with optional study material context."""
        system = (
            f"You are a helpful, concise AI study tutor. "
            f"The student is studying:\n\n---\n{context[:3000]}\n---\n\n"
            "Answer clearly with examples from the material. Be encouraging."
            if context
            else "You are a helpful, concise AI study tutor. Be encouraging and clear."
        )

        messages = history + [{"role": "user", "content": message}]

        if settings.ANTHROPIC_API_KEY:
            headers = {**self._HEADERS, "x-api-key": settings.ANTHROPIC_API_KEY}
        else:
            headers = self._HEADERS

        payload = {
            "model": settings.ANTHROPIC_MODEL,
            "max_tokens": settings.AI_MAX_TOKENS,
            "system": system,
            "messages": messages[-20:],   # keep last 20 turns
        }
        resp = await self._client.post(self._BASE_URL, headers=headers, json=payload)
        resp.raise_for_status()
        data = resp.json()
        return "".join(b.get("text", "") for b in data.get("content", []))
