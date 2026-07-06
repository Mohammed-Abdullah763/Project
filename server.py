"""
server.py — StudyMind Pro Backend Server
=========================================
FastAPI app serving all endpoints:
  /api/ai/*        — AI features (summarize, flashcards, quiz, etc.)
  /api/search/*    — Web search with AI synthesis
  /api/vision/*    — Image analysis and OCR
  /api/upload/*    — File upload and processing
  /api/chat/*      — Multi-turn AI tutor chat
  /health          — Health checks
  /                — Serves frontend (index.html)
"""

import logging
import mimetypes
import os
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import brain
import config as cfg
import connections as conn

# ── Logging ──────────────────────────────────────────
logging.basicConfig(level=getattr(logging, cfg.LOG_LEVEL))
log = logging.getLogger("studymind")

# ── Lifespan ─────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info(f"Starting {cfg.APP_NAME} v{cfg.APP_VERSION}")
    cfg.show()
    yield
    await conn.close_client()
    log.info("Server stopped")

app = FastAPI(
    title=cfg.APP_NAME,
    version=cfg.APP_VERSION,
    docs_url="/docs",
    redoc_url=None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=cfg.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def timing(request: Request, call_next):
    t = time.monotonic()
    response = await call_next(request)
    ms = round((time.monotonic() - t) * 1000)
    response.headers["X-Response-Time"] = f"{ms}ms"
    return response

# ── Schema ────────────────────────────────────────────
class TextRequest(BaseModel):
    text: str = Field(min_length=10, max_length=30000)
    session_id: str | None = None

class SearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=500)
    context: str | None = None

class ChatRequest(BaseModel):
    messages: list[dict]
    context: str | None = None
    session_id: str | None = None

# ══════════════════════════════════════════════════════
# HEALTH
# ══════════════════════════════════════════════════════
@app.get("/health")
async def health():
    return {
        "status": "ok",
        "app": cfg.APP_NAME,
        "version": cfg.APP_VERSION,
        "ai": "configured" if cfg.ANTHROPIC_API_KEY else "MISSING KEY",
        "search_brave": "configured" if cfg.BRAVE_API_KEY else "using duckduckgo",
        "duckduckgo": cfg.DUCKDUCKGO_ENABLED,
        "wikipedia": cfg.WIKIPEDIA_ENABLED,
        "ocr": cfg.OCR_ENABLED,
    }

@app.get("/health/full")
async def health_full():
    checks = {}
    # Test AI
    try:
        if cfg.ANTHROPIC_API_KEY:
            result = await conn.ai_text("Reply OK", "ping", use_cache=False)
            checks["ai"] = "ok"
        else:
            checks["ai"] = "no_key"
    except Exception as e:
        checks["ai"] = f"error: {e}"
    # Test search
    try:
        r = await conn.search_duckduckgo("test")
        checks["search"] = "ok" if r else "no_results"
    except Exception as e:
        checks["search"] = f"error: {e}"
    return {"status": "ok" if all(v in ("ok","no_key") for v in checks.values()) else "degraded", "checks": checks}

# ══════════════════════════════════════════════════════
# AI FEATURES
# ══════════════════════════════════════════════════════
@app.post("/api/ai/summarize")
async def api_summarize(req: TextRequest):
    try:
        return {"success": True, "data": await brain.summarize(req.text)}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/ai/flashcards")
async def api_flashcards(req: TextRequest):
    try:
        return {"success": True, "data": await brain.flashcards(req.text)}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/ai/quiz")
async def api_quiz(req: TextRequest):
    try:
        return {"success": True, "data": await brain.quiz(req.text)}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/ai/mindmap")
async def api_mindmap(req: TextRequest):
    try:
        return {"success": True, "data": await brain.mindmap(req.text)}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/ai/terms")
async def api_terms(req: TextRequest):
    try:
        return {"success": True, "data": await brain.key_terms(req.text)}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.post("/api/ai/plan")
async def api_plan(req: TextRequest):
    try:
        return {"success": True, "data": await brain.study_plan(req.text)}
    except Exception as e:
        raise HTTPException(500, str(e))

# ══════════════════════════════════════════════════════
# CHAT
# ══════════════════════════════════════════════════════
@app.post("/api/chat")
async def api_chat(req: ChatRequest):
    try:
        reply = await conn.ai_chat(req.messages, req.context or "")
        return {"success": True, "reply": reply}
    except Exception as e:
        raise HTTPException(500, str(e))

# ══════════════════════════════════════════════════════
# SEARCH
# ══════════════════════════════════════════════════════
@app.post("/api/search")
async def api_search(req: SearchRequest):
    try:
        result = await conn.search_and_answer(req.query, req.context or "")
        return {"success": True, **result}
    except Exception as e:
        raise HTTPException(500, str(e))

@app.get("/api/search")
async def api_search_get(q: str, context: str = ""):
    try:
        result = await conn.search_and_answer(q, context)
        return {"success": True, **result}
    except Exception as e:
        raise HTTPException(500, str(e))

# ══════════════════════════════════════════════════════
# FILE UPLOAD + PROCESSING
# ══════════════════════════════════════════════════════
@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    filename = file.filename or "upload"
    ext = Path(filename).suffix.lower()

    if ext not in cfg.ALLOWED_ALL_EXT:
        raise HTTPException(400, f"File type '{ext}' not supported.")

    content = await file.read()
    if len(content) > cfg.MAX_FILE_BYTES:
        raise HTTPException(413, f"File too large. Max {cfg.MAX_FILE_MB}MB.")

    file_id = uuid.uuid4().hex
    safe_name = re.sub(r'[^\w\.\-]', '_', os.path.basename(filename))
    stored_path = cfg.UPLOAD_DIR / f"{file_id}{ext}"
    stored_path.write_bytes(content)

    result = {
        "file_id": file_id,
        "filename": safe_name,
        "ext": ext,
        "size_bytes": len(content),
        "is_image": ext in cfg.ALLOWED_IMAGE_EXT,
    }

    # Process text files immediately
    if ext in cfg.ALLOWED_TEXT_EXT:
        extracted = brain.extract_text_from_file(stored_path, ext)
        result["extracted_text"] = extracted
        result["word_count"] = len(extracted.split())

    # Process images with Vision AI
    elif ext in cfg.ALLOWED_IMAGE_EXT:
        media_type = mimetypes.guess_type(filename)[0] or "image/jpeg"
        vision_result = await brain.analyse_image(content, media_type, "notes")
        result["vision_result"] = vision_result

    return {"success": True, **result}

# ══════════════════════════════════════════════════════
# VISION / IMAGE ANALYSIS
# ══════════════════════════════════════════════════════
@app.post("/api/vision/analyse")
async def api_vision_analyse(
    file: UploadFile = File(...),
    task: str = Form(default="general"),
):
    valid_tasks = {"general", "ocr", "diagram", "notes", "math"}
    if task not in valid_tasks:
        task = "general"

    content = await file.read()
    if len(content) > cfg.VISION_MAX_BYTES:
        raise HTTPException(413, f"Image too large. Max {cfg.VISION_MAX_SIZE_MB}MB.")

    filename = file.filename or "image.jpg"
    media_type = mimetypes.guess_type(filename)[0] or "image/jpeg"

    result = await brain.analyse_image(content, media_type, task)
    return {"success": True, **result}

@app.post("/api/vision/ocr")
async def api_ocr(file: UploadFile = File(...)):
    """Extract text from image — optimised for handwriting and bad writing."""
    content = await file.read()
    media_type = mimetypes.guess_type(file.filename or "img.jpg")[0] or "image/jpeg"
    result = await brain.analyse_image(content, media_type, "ocr")
    # Also try Tesseract as backup
    if not result["success"] or not result["result"].strip():
        fallback = brain.ocr_fallback(content)
        if fallback.strip():
            result["result"] = fallback
            result["success"] = True
            result["method"] = "tesseract"
    return {"success": True, **result}

# ══════════════════════════════════════════════════════
# SERVE FRONTEND
# ══════════════════════════════════════════════════════
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/")
async def serve_index():
    index = Path(__file__).parent / "static" / "index.html"
    if index.exists():
        return FileResponse(str(index))
    return JSONResponse({"message": f"{cfg.APP_NAME} is running", "docs": "/docs"})

# ══════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════
if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host=cfg.APP_HOST,
        port=cfg.APP_PORT,
        reload=cfg.DEBUG,
        log_level=cfg.LOG_LEVEL.lower(),
    )
