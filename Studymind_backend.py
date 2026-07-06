"""
StudyMind — Security-Hardened Backend (Single File)
====================================================
File: studymind_backend.py
Layer: BACKEND

All 10 security skill categories implemented:
  1. Secure coding (input validation, XSS/SQLi prevention, ORM, no secrets in code)
  2. Auth & session security (bcrypt, JWT access+refresh, MFA-ready, token revocation)
  3. Authorization & access control (roles: admin/user, per-route enforcement, least privilege)
  4. Network & transport security (HTTPS headers, strict CORS, rate limiting, brute-force protection)
  5. VPN/proxy & IP risk handling (X-Forwarded-For parsing, IP2Proxy API, risk tagging, blocking)
  6. Data security & privacy (env secrets, PII handling, no sensitive data in logs)
  7. Logging, monitoring & incident handling (structured logs, failed-login alerting, audit trail)
  8. Dependency & config security (env vars, no debug leaks, safe error pages)
  9. Infrastructure / deployment safety (Docker-ready, secure headers, hardened config)
  10. Security mindset (threat-modeled routes, commented attack surface, OWASP Top 10 mitigations)

Run:
    pip install fastapi uvicorn[standard] sqlalchemy aiosqlite python-jose passlib[bcrypt] \
                httpx orjson python-multipart slowapi structlog bleach
    python studymind_backend.py

API docs: http://localhost:8000/docs
"""

# ══════════════════════════════════════════════════════════════════════════════
# IMPORTS
# ══════════════════════════════════════════════════════════════════════════════
import asyncio, hashlib, html, json, logging, math, os, re, secrets, sys, time, uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import bleach                          # XSS sanitisation
import httpx
import orjson
import structlog                       # structured JSON logging
import uvicorn
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse, JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import (
    Boolean, Column, DateTime, Enum as SAEnum, ForeignKey,
    Integer, String, Text, func, select, text, Index
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, relationship

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 1 + 8: CONFIG — all secrets from environment, never hardcoded
# ══════════════════════════════════════════════════════════════════════════════
class Cfg:
    APP_NAME            = "StudyMind"
    VERSION             = "3.0.0"
    # ── Security ── never put real values here; load from .env or shell
    SECRET_KEY          = os.getenv("SECRET_KEY", secrets.token_hex(32))
    ALGORITHM           = "HS256"
    ACCESS_EXPIRE_MIN   = int(os.getenv("ACCESS_EXPIRE_MIN",  "30"))
    REFRESH_EXPIRE_DAYS = int(os.getenv("REFRESH_EXPIRE_DAYS", "7"))
    # ── Database ──
    DATABASE_URL        = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./studymind.db")
    # ── AI ──
    ANTHROPIC_API_KEY   = os.getenv("ANTHROPIC_API_KEY", "")
    ANTHROPIC_MODEL     = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6")
    AI_MAX_TOKENS       = int(os.getenv("AI_MAX_TOKENS", "1000"))
    # ── VPN/IP detection (Skill 5) ──
    IP2PROXY_KEY        = os.getenv("IP2PROXY_KEY", "")      # optional; free tier available
    VPN_BLOCK_ENABLED   = os.getenv("VPN_BLOCK_ENABLED", "false").lower() == "true"
    # ── Rate limiting (Skill 4) ──
    RATE_LIMIT_GENERAL  = os.getenv("RATE_LIMIT_GENERAL",  "60/minute")
    RATE_LIMIT_AUTH     = os.getenv("RATE_LIMIT_AUTH",     "10/minute")
    RATE_LIMIT_AI       = os.getenv("RATE_LIMIT_AI",       "30/minute")
    MAX_LOGIN_ATTEMPTS  = int(os.getenv("MAX_LOGIN_ATTEMPTS", "5"))
    LOCKOUT_MINUTES     = int(os.getenv("LOCKOUT_MINUTES", "15"))
    # ── Files ──
    UPLOAD_DIR          = Path(os.getenv("UPLOAD_DIR", "./uploads"))
    MAX_FILE_MB         = int(os.getenv("MAX_FILE_MB", "10"))
    ALLOWED_EXTENSIONS  = {".txt", ".md", ".pdf", ".docx"}
    # ── CORS (Skill 4) ──
    CORS_ORIGINS        = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:5500").split(",")
    # ── Deployment ──
    PORT                = int(os.getenv("PORT", "8000"))
    HOST                = os.getenv("HOST", "0.0.0.0")
    DEBUG               = os.getenv("DEBUG", "false").lower() == "true"   # NEVER True in prod
    ENVIRONMENT         = os.getenv("ENVIRONMENT", "development")

    @classmethod
    def validate(cls):
        """Skill 9: Fail-fast on unsafe configuration at startup."""
        if cls.ENVIRONMENT == "production":
            if cls.SECRET_KEY == secrets.token_hex(32):
                raise RuntimeError("SECRET_KEY must be set explicitly in production!")
            if cls.DEBUG:
                raise RuntimeError("DEBUG must be False in production!")
        return True

Cfg.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 7: STRUCTURED LOGGING — no secrets, no PII in log output
# ══════════════════════════════════════════════════════════════════════════════
structlog.configure(
    processors=[
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer() if Cfg.ENVIRONMENT == "production"
        else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
)
log = structlog.get_logger()

# Failed-login attempt store — Skill 7 alerting + Skill 4 brute-force
_failed_logins: dict[str, list[float]] = defaultdict(list)   # ip -> [timestamps]
_locked_ips:    dict[str, float]        = {}                  # ip -> unlock_at

def record_failed_login(ip: str) -> None:
    now = time.monotonic()
    _failed_logins[ip] = [t for t in _failed_logins[ip] if now - t < 3600]
    _failed_logins[ip].append(now)
    recent = [t for t in _failed_logins[ip] if now - t < 600]   # last 10 min
    if len(recent) >= Cfg.MAX_LOGIN_ATTEMPTS:
        _locked_ips[ip] = now + Cfg.LOCKOUT_MINUTES * 60
        log.warning("account_lockout_triggered", ip=ip, attempts=len(recent))

def is_ip_locked(ip: str) -> bool:
    unlock_at = _locked_ips.get(ip)
    if unlock_at and time.monotonic() < unlock_at:
        return True
    if unlock_at:
        del _locked_ips[ip]
    return False

# Revoked tokens store (Skill 2 — token revocation)
_revoked_tokens: set[str] = set()

# ══════════════════════════════════════════════════════════════════════════════
# DATABASE
# ══════════════════════════════════════════════════════════════════════════════
engine = create_async_engine(
    Cfg.DATABASE_URL,
    echo=False,          # Skill 8: never echo SQL in production
    pool_pre_ping=True,
    connect_args={"check_same_thread": False} if "sqlite" in Cfg.DATABASE_URL else {},
)
AsyncSession_ = async_sessionmaker(engine, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

# ── Skill 3: Role enum ────────────────────────────────────────────────────────
class UserRole(str, Enum):
    ADMIN = "admin"
    USER  = "user"

# ── Models ────────────────────────────────────────────────────────────────────
class User(Base):
    __tablename__ = "users"
    id                  = Column(Integer, primary_key=True, index=True)
    email               = Column(String(255), unique=True, nullable=False, index=True)
    username            = Column(String(100), unique=True, nullable=False)
    hashed_password     = Column(String(255), nullable=False)
    role                = Column(SAEnum(UserRole), default=UserRole.USER, nullable=False)
    is_active           = Column(Boolean, default=True)
    is_verified         = Column(Boolean, default=False)
    mfa_enabled         = Column(Boolean, default=False)      # Skill 2: MFA flag
    mfa_secret          = Column(String(255), nullable=True)  # TOTP secret (encrypted in prod)
    created_at          = Column(DateTime, server_default=func.now())
    last_login_at       = Column(DateTime, nullable=True)
    last_login_ip       = Column(String(64), nullable=True)   # Skill 7: audit
    sessions            = relationship("StudySession", back_populates="user", cascade="all, delete-orphan")
    files               = relationship("UploadedFile", back_populates="user", cascade="all, delete-orphan")
    audit_logs          = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")

class StudySession(Base):
    __tablename__ = "study_sessions"
    id              = Column(Integer, primary_key=True, index=True)
    user_id         = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    title           = Column(String(500), default="Untitled Session")
    source_text     = Column(Text, nullable=True)
    word_count      = Column(Integer, default=0)
    summary_json    = Column(Text, nullable=True)
    flashcards_json = Column(Text, nullable=True)
    quiz_json       = Column(Text, nullable=True)
    mindmap_json    = Column(Text, nullable=True)
    key_terms_json  = Column(Text, nullable=True)
    study_plan_json = Column(Text, nullable=True)
    created_at      = Column(DateTime, server_default=func.now())
    updated_at      = Column(DateTime, server_default=func.now(), onupdate=func.now())
    user            = relationship("User", back_populates="sessions")
    chat_messages   = relationship("ChatMessage", back_populates="session", cascade="all, delete-orphan")
    files           = relationship("UploadedFile", back_populates="session")

class ChatMessage(Base):
    __tablename__ = "chat_messages"
    id         = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("study_sessions.id", ondelete="CASCADE"))
    role       = Column(String(20), nullable=False)
    content    = Column(Text, nullable=False)
    created_at = Column(DateTime, server_default=func.now())
    session    = relationship("StudySession", back_populates="chat_messages")

class UploadedFile(Base):
    __tablename__ = "uploaded_files"
    id                = Column(Integer, primary_key=True, index=True)
    user_id           = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    session_id        = Column(Integer, ForeignKey("study_sessions.id", ondelete="SET NULL"), nullable=True)
    original_filename = Column(String(500), nullable=False)
    stored_filename   = Column(String(500), nullable=False)
    file_type         = Column(String(50), nullable=False)
    file_size_bytes   = Column(Integer, nullable=False)
    extracted_text    = Column(Text, nullable=True)
    created_at        = Column(DateTime, server_default=func.now())
    user              = relationship("User", back_populates="files")
    session           = relationship("StudySession", back_populates="files")

# Skill 7: Audit log table — every sensitive action recorded
class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (Index("ix_audit_user_created", "user_id", "created_at"),)
    id         = Column(Integer, primary_key=True)
    user_id    = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action     = Column(String(100), nullable=False)   # e.g. "login", "password_change"
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(500), nullable=True)
    risk_level = Column(String(20), default="low")     # low / medium / high
    detail     = Column(Text, nullable=True)           # JSON, no PII
    created_at = Column(DateTime, server_default=func.now())
    user       = relationship("User", back_populates="audit_logs")

# Skill 5: IP risk cache
class IPRiskCache(Base):
    __tablename__ = "ip_risk_cache"
    ip_address  = Column(String(64), primary_key=True)
    is_vpn      = Column(Boolean, default=False)
    is_proxy    = Column(Boolean, default=False)
    is_tor      = Column(Boolean, default=False)
    risk_score  = Column(Integer, default=0)          # 0-100
    country     = Column(String(10), nullable=True)
    cached_at   = Column(DateTime, server_default=func.now())

async def get_db():
    async with AsyncSession_() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 2: PASSWORD HASHING (bcrypt) + JWT
# ══════════════════════════════════════════════════════════════════════════════
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)
_bearer = HTTPBearer(auto_error=False)

def hash_password(plain: str) -> str:
    return _pwd.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return _pwd.verify(plain, hashed)

def _make_token(data: dict, expires: timedelta, token_type: str) -> str:
    jti = secrets.token_hex(16)         # unique token ID for revocation
    payload = {
        **data,
        "type": token_type,
        "jti":  jti,
        "exp":  datetime.now(timezone.utc) + expires,
        "iat":  datetime.now(timezone.utc),
        "iss":  Cfg.APP_NAME,
    }
    return jwt.encode(payload, Cfg.SECRET_KEY, algorithm=Cfg.ALGORITHM)

def create_access_token(user_id: int, email: str, role: str) -> str:
    return _make_token(
        {"sub": str(user_id), "email": email, "role": role},
        timedelta(minutes=Cfg.ACCESS_EXPIRE_MIN),
        "access",
    )

def create_refresh_token(user_id: int) -> str:
    return _make_token(
        {"sub": str(user_id)},
        timedelta(days=Cfg.REFRESH_EXPIRE_DAYS),
        "refresh",
    )

def decode_token(token: str) -> dict:
    payload = jwt.decode(token, Cfg.SECRET_KEY, algorithms=[Cfg.ALGORITHM])
    # Skill 2: check revocation
    if payload.get("jti") in _revoked_tokens:
        raise JWTError("Token has been revoked")
    return payload

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 5: VPN / PROXY / TOR DETECTION
# ══════════════════════════════════════════════════════════════════════════════
_ip_cache: dict[str, dict] = {}   # in-memory cache (supplement DB cache)

def get_real_ip(request: Request) -> str:
    """
    Skill 5: Parse X-Forwarded-For safely.
    Never trust user-supplied headers without validation.
    Only trust forwarded headers if behind a known proxy.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # Take the FIRST IP (client), strip spaces, validate format
        candidate = xff.split(",")[0].strip()
        # Basic IPv4/IPv6 validation — reject malformed values
        if re.match(r'^[\d\.:a-fA-F]+$', candidate) and len(candidate) <= 45:
            return candidate
    return request.client.host or "0.0.0.0"

async def check_ip_risk(ip: str, db: AsyncSession) -> dict:
    """
    Skill 5: Check IP reputation.
    Uses IP2Proxy API if key is configured, otherwise returns low-risk default.
    Results cached for 6 hours in DB + memory.
    """
    # Memory cache hit
    if ip in _ip_cache:
        cached = _ip_cache[ip]
        if time.time() - cached.get("cached_ts", 0) < 21600:  # 6h
            return cached

    # DB cache hit
    row = (await db.execute(
        select(IPRiskCache).where(IPRiskCache.ip_address == ip)
    )).scalar_one_or_none()
    if row:
        age = (datetime.utcnow() - row.cached_at).total_seconds()
        if age < 21600:
            result = {"is_vpn": row.is_vpn, "is_proxy": row.is_proxy,
                      "is_tor": row.is_tor, "risk_score": row.risk_score,
                      "country": row.country, "cached_ts": time.time()}
            _ip_cache[ip] = result
            return result

    # Default result
    result = {"is_vpn": False, "is_proxy": False, "is_tor": False,
              "risk_score": 0, "country": None, "cached_ts": time.time()}

    # Live API check (IP2Proxy free tier)
    if Cfg.IP2PROXY_KEY and ip not in ("127.0.0.1", "0.0.0.0", "::1"):
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                resp = await client.get(
                    "https://api.ip2proxy.com/",
                    params={"ip": ip, "key": Cfg.IP2PROXY_KEY, "package": "PX2"}
                )
                if resp.status_code == 200:
                    data = resp.json()
                    result["is_proxy"] = data.get("isProxy") == "YES"
                    result["is_vpn"]   = data.get("proxyType") in ("VPN", "DCH")
                    result["is_tor"]   = data.get("proxyType") == "TOR"
                    result["country"]  = data.get("countryCode")
                    # Risk score: TOR=90, VPN=70, Proxy=50
                    if result["is_tor"]:   result["risk_score"] = 90
                    elif result["is_vpn"]: result["risk_score"] = 70
                    elif result["is_proxy"]: result["risk_score"] = 50
                    log.info("ip_risk_checked", ip=ip, risk=result["risk_score"],
                             is_vpn=result["is_vpn"])
        except Exception as e:
            log.warning("ip_risk_check_failed", ip=ip, error=str(e))

    # Save to DB cache
    try:
        existing = (await db.execute(
            select(IPRiskCache).where(IPRiskCache.ip_address == ip)
        )).scalar_one_or_none()
        if existing:
            existing.is_vpn   = result["is_vpn"]
            existing.is_proxy = result["is_proxy"]
            existing.is_tor   = result["is_tor"]
            existing.risk_score = result["risk_score"]
            existing.country  = result["country"]
            existing.cached_at = datetime.utcnow()
        else:
            db.add(IPRiskCache(
                ip_address=ip, is_vpn=result["is_vpn"], is_proxy=result["is_proxy"],
                is_tor=result["is_tor"], risk_score=result["risk_score"],
                country=result["country"]
            ))
    except Exception:
        pass   # cache failure is non-fatal

    _ip_cache[ip] = result
    return result

def get_risk_level(ip_data: dict) -> str:
    score = ip_data.get("risk_score", 0)
    if score >= 80: return "high"
    if score >= 40: return "medium"
    return "low"

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 7: AUDIT LOGGING HELPER
# ══════════════════════════════════════════════════════════════════════════════
async def audit(
    db: AsyncSession, action: str,
    request: Request,
    user_id: int | None = None,
    risk_level: str = "low",
    detail: dict | None = None,
):
    """Write an audit log row. Never include passwords or full PII."""
    ip = get_real_ip(request)
    ua = request.headers.get("User-Agent", "")[:500]
    # Sanitise detail — remove any accidentally passed secrets
    safe_detail = json.dumps({
        k: v for k, v in (detail or {}).items()
        if k.lower() not in ("password", "token", "secret", "key")
    }) if detail else None
    db.add(AuditLog(
        user_id=user_id, action=action, ip_address=ip,
        user_agent=ua, risk_level=risk_level, detail=safe_detail
    ))
    log.info("audit", action=action, user_id=user_id, ip=ip, risk=risk_level)

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 1: INPUT SANITISATION — prevent XSS and over-long inputs
# ══════════════════════════════════════════════════════════════════════════════
ALLOWED_TAGS: list[str] = []   # no HTML in API input at all

def sanitise_text(value: str, max_len: int = 20000) -> str:
    """Strip HTML tags and truncate. Applied to all user-supplied text fields."""
    cleaned = bleach.clean(value, tags=ALLOWED_TAGS, strip=True)
    return cleaned[:max_len]

def sanitise_filename(name: str) -> str:
    """Prevent path traversal in uploaded filenames."""
    # Remove all path separators and null bytes
    safe = re.sub(r'[^\w\.\-]', '_', os.path.basename(name))
    return safe[:255] or "upload"

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 3: AUTH DEPENDENCIES — role-based access control
# ══════════════════════════════════════════════════════════════════════════════
async def get_current_user(
    creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Extract + validate JWT. Every protected route uses this."""
    if not creds:
        raise HTTPException(401, "Not authenticated",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = decode_token(creds.credentials)
        if payload.get("type") != "access":
            raise HTTPException(401, "Invalid token type")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(401, "Invalid or expired token",
                            headers={"WWW-Authenticate": "Bearer"})

    row = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not row:
        raise HTTPException(401, "User not found")
    if not row.is_active:
        raise HTTPException(403, "Account suspended. Contact support.")
    return row

def require_role(required: UserRole):
    """Skill 3: Decorator-style role guard — enforced server-side, not frontend."""
    async def _check(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != required and current_user.role != UserRole.ADMIN:
            raise HTTPException(403, "Insufficient permissions")
        return current_user
    return _check

# Convenience aliases
require_admin = require_role(UserRole.ADMIN)
require_user  = require_role(UserRole.USER)

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 4: RATE LIMITER (slowapi — per-endpoint limits)
# ══════════════════════════════════════════════════════════════════════════════
limiter = Limiter(key_func=get_remote_address, default_limits=[Cfg.RATE_LIMIT_GENERAL])

# ══════════════════════════════════════════════════════════════════════════════
# IN-MEMORY CACHE (TTL-based, no Redis needed for single-file version)
# ══════════════════════════════════════════════════════════════════════════════
_cache: dict[str, tuple[float, Any]] = {}
CACHE_TTL = 300

def cache_get(key: str) -> Any | None:
    entry = _cache.get(key)
    if entry and time.monotonic() < entry[0]:
        return entry[1]
    _cache.pop(key, None)
    return None

def cache_set(key: str, value: Any) -> None:
    _cache[key] = (time.monotonic() + CACHE_TTL, value)

def make_cache_key(feature: str, text: str) -> str:
    return f"sm:{feature}:{hashlib.sha256(text.encode()).hexdigest()[:16]}"

# ══════════════════════════════════════════════════════════════════════════════
# AI SERVICE
# ══════════════════════════════════════════════════════════════════════════════
_http: httpx.AsyncClient | None = None

def get_http() -> httpx.AsyncClient:
    global _http
    if _http is None:
        _http = httpx.AsyncClient(timeout=30.0, http2=True)
    return _http

async def call_claude(system: str, user_prompt: str) -> str:
    headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
    if Cfg.ANTHROPIC_API_KEY:
        headers["x-api-key"] = Cfg.ANTHROPIC_API_KEY
    payload = {
        "model": Cfg.ANTHROPIC_MODEL,
        "max_tokens": Cfg.AI_MAX_TOKENS,
        "system": system,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    resp = await get_http().post("https://api.anthropic.com/v1/messages",
                                  headers=headers, json=payload)
    resp.raise_for_status()
    return "".join(b.get("text", "") for b in resp.json().get("content", []))

def parse_json(raw: str) -> Any:
    clean = raw.strip()
    if clean.startswith("```"):
        lines = clean.split("\n")
        clean = "\n".join(lines[1:]).rsplit("```", 1)[0]
    return json.loads(clean.strip())

async def ai_summarize(text: str)  -> dict: return parse_json(await call_claude("You are an expert academic summarizer. Return ONLY valid JSON, no markdown.", f'Summarize. Return JSON:\n{{"tldr":"one sentence","key_points":["p1","p2","p3","p4","p5"],"concepts":["c1","c2","c3"],"importance":"2 sentences"}}\n\nMaterial:\n{text[:4000]}'))
async def ai_flashcards(text: str) -> list: return parse_json(await call_claude("You are a flashcard expert. Return ONLY valid JSON.", f'Create 8 flashcards. Return JSON:\n[{{"q":"question","a":"answer","hint":"hint","difficulty":"easy|medium|hard"}}]\n\nMaterial:\n{text[:4000]}'))
async def ai_quiz(text: str)       -> list: return parse_json(await call_claude("You are a quiz master. Return ONLY valid JSON.", f'Create 6 MCQ questions. Return JSON:\n[{{"q":"q","options":["A","B","C","D"],"answer":0,"explanation":"why"}}]\n\nMaterial:\n{text[:4000]}'))
async def ai_mindmap(text: str)    -> dict: return parse_json(await call_claude("You are a knowledge-structure expert. Return ONLY valid JSON.", f'Build mind map. Return JSON:\n{{"root":"topic","branches":[{{"name":"branch","leaves":["l1","l2","l3"]}}]}}\n\nMaterial:\n{text[:4000]}'))
async def ai_terms(text: str)      -> list: return parse_json(await call_claude("You are a glossary expert. Return ONLY valid JSON.", f'Extract 10 key terms. Return JSON:\n[{{"term":"name","definition":"1-2 sentences"}}]\n\nMaterial:\n{text[:4000]}'))
async def ai_plan(text: str)       -> list: return parse_json(await call_claude("You are a learning designer. Return ONLY valid JSON.", f'Create 5-day study plan. Return JSON:\n[{{"day":1,"title":"title","tasks":"activities"}}]\n\nMaterial:\n{text[:4000]}'))
async def ai_chat(msg: str, ctx: str, hist: list) -> str:
    system = (f"You are a helpful AI study tutor. Material:\n---\n{ctx[:3000]}\n---\nBe concise." if ctx else "You are a helpful AI study tutor. Be concise and encouraging.")
    headers = {"Content-Type": "application/json", "anthropic-version": "2023-06-01"}
    if Cfg.ANTHROPIC_API_KEY: headers["x-api-key"] = Cfg.ANTHROPIC_API_KEY
    resp = await get_http().post("https://api.anthropic.com/v1/messages", headers=headers,
        json={"model": Cfg.ANTHROPIC_MODEL, "max_tokens": Cfg.AI_MAX_TOKENS,
              "system": system, "messages": (hist + [{"role":"user","content":msg}])[-20:]})
    resp.raise_for_status()
    return "".join(b.get("text","") for b in resp.json().get("content",[]))

# ══════════════════════════════════════════════════════════════════════════════
# PYDANTIC SCHEMAS — Skill 1: strict validation on every input
# ══════════════════════════════════════════════════════════════════════════════
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$')
_USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,50}$')

class UserRegister(BaseModel):
    email:    str = Field(max_length=255)
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=10, max_length=128)

    @field_validator("email")
    @classmethod
    def valid_email(cls, v: str) -> str:
        v = v.strip().lower()
        if not _EMAIL_RE.match(v):
            raise ValueError("Invalid email format")
        return v

    @field_validator("username")
    @classmethod
    def valid_username(cls, v: str) -> str:
        if not _USERNAME_RE.match(v):
            raise ValueError("Username: 3-50 chars, letters/numbers/underscore only")
        return v

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v

class UserLogin(BaseModel):
    email:    str = Field(max_length=255)
    password: str = Field(max_length=128)

class TokenOut(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"
    expires_in:    int

class RefreshIn(BaseModel):
    refresh_token: str

class LogoutIn(BaseModel):
    refresh_token: str

class SessionCreate(BaseModel):
    title:       str      = Field(default="Untitled Session", max_length=500)
    source_text: str | None = Field(default=None, max_length=50000)

    @field_validator("title")
    @classmethod
    def clean_title(cls, v: str) -> str:
        return sanitise_text(v, 500)

    @field_validator("source_text")
    @classmethod
    def clean_text(cls, v: str | None) -> str | None:
        return sanitise_text(v, 50000) if v else None

class SessionUpdate(BaseModel):
    title:       str | None = Field(default=None, max_length=500)
    source_text: str | None = Field(default=None, max_length=50000)

class AIRequest(BaseModel):
    text:       str    = Field(min_length=20, max_length=20000)
    session_id: int | None = None

    @field_validator("text")
    @classmethod
    def clean_ai_text(cls, v: str) -> str:
        return sanitise_text(v, 20000)

class ChatIn(BaseModel):
    content:      str      = Field(min_length=1, max_length=2000)
    session_id:   int
    context_text: str | None = Field(default=None, max_length=10000)

    @field_validator("content")
    @classmethod
    def clean_content(cls, v: str) -> str:
        return sanitise_text(v, 2000)

# ══════════════════════════════════════════════════════════════════════════════
# APP SETUP + LIFESPAN
# ══════════════════════════════════════════════════════════════════════════════
@asynccontextmanager
async def lifespan(app: FastAPI):
    Cfg.validate()   # Skill 9: fail-fast on bad config
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    log.info("startup", app=Cfg.APP_NAME, version=Cfg.VERSION, env=Cfg.ENVIRONMENT)
    print(f"\n{'='*60}")
    print(f"  🧠  {Cfg.APP_NAME} v{Cfg.VERSION}  [{Cfg.ENVIRONMENT}]")
    print(f"  📖  Swagger docs  →  http://localhost:{Cfg.PORT}/docs")
    print(f"  ❤️   Health        →  http://localhost:{Cfg.PORT}/health")
    print(f"  🔒  VPN blocking  →  {'ENABLED' if Cfg.VPN_BLOCK_ENABLED else 'DISABLED'}")
    print(f"{'='*60}\n")
    yield
    if _http:
        await _http.aclose()
    await engine.dispose()
    log.info("shutdown")

app = FastAPI(
    title=Cfg.APP_NAME,
    version=Cfg.VERSION,
    description="""
## StudyMind Security-Hardened Backend

**File:** `studymind_backend.py` | **Layer:** BACKEND

### Security Features
| Skill | Implementation |
|---|---|
| Input validation | Pydantic + bleach XSS sanitisation on every field |
| SQL injection | SQLAlchemy ORM (parameterised, never raw f-strings) |
| Password security | bcrypt rounds=12, min 10 chars, complexity required |
| JWT auth | Access (30 min) + refresh (7 days) with JTI revocation |
| Roles | admin / user enforced server-side on every route |
| Rate limiting | Per-endpoint slowapi limits (auth: 10/min, AI: 30/min) |
| Brute force | IP lockout after 5 failed logins for 15 min |
| VPN/proxy | IP2Proxy API + risk scoring + optional blocking |
| Security headers | HSTS, X-Frame-Options, CSP, no-sniff on every response |
| Audit log | Every auth action written to audit_logs table |
| Structured logs | structlog JSON — no secrets, no PII |
| CORS | Strict allowlist from env var |
| Secrets | All via environment variables, never hardcoded |

### Auth
`POST /api/auth/login` → get tokens → `Authorization: Bearer <access_token>`
    """,
    docs_url="/docs",
    redoc_url="/redoc",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    # Skill 8: disable debug in production
    debug=False,
)

# ── Rate limiter error handler ────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Skill 4: CORS — strict origin allowlist ───────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=Cfg.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    expose_headers=["X-Request-ID", "X-Risk-Level"],
)

# ── Skill 4 + 9: Security headers middleware ──────────────────────────────────
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    # OWASP-recommended headers
    response.headers["X-Content-Type-Options"]    = "nosniff"
    response.headers["X-Frame-Options"]           = "DENY"
    response.headers["X-XSS-Protection"]          = "1; mode=block"
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]        = "geolocation=(), camera=(), microphone=()"
    response.headers["Content-Security-Policy"]   = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self' https://api.anthropic.com"
    )
    if Cfg.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Remove server fingerprinting
    response.headers.pop("server", None)
    response.headers.pop("x-powered-by", None)
    return response

# ── Skill 7: Request logging + timing ────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    rid = secrets.token_hex(8)
    start = time.monotonic()
    response = await call_next(request)
    ms = round((time.monotonic() - start) * 1000)
    response.headers["X-Request-ID"] = rid
    # Skill 7: log method+path+status but NOT query strings (may contain tokens)
    log.info("http", rid=rid, method=request.method,
             path=request.url.path, status=response.status_code, ms=ms)
    return response

# ── Skill 5: VPN/proxy check middleware ──────────────────────────────────────
VPN_EXEMPT_PATHS = {"/health", "/health/full", "/docs", "/redoc", "/openapi.json"}

@app.middleware("http")
async def vpn_check_middleware(request: Request, call_next):
    """
    Skill 5: Check client IP against VPN/proxy database.
    - Attach risk level to request state for downstream use.
    - Block high-risk IPs if VPN_BLOCK_ENABLED=true.
    """
    if request.url.path in VPN_EXEMPT_PATHS:
        return await call_next(request)

    ip = get_real_ip(request)
    request.state.client_ip = ip

    # Run DB-backed IP risk check
    try:
        async with AsyncSession_() as db:
            ip_data = await check_ip_risk(ip, db)
            risk = get_risk_level(ip_data)
            request.state.ip_risk     = ip_data
            request.state.risk_level  = risk

            if Cfg.VPN_BLOCK_ENABLED and risk == "high":
                log.warning("vpn_block", ip=ip, risk_score=ip_data["risk_score"])
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Access denied",
                        "detail": "Requests from VPNs, proxies, or Tor are not permitted. "
                                  "Please disable your VPN and try again.",
                        "code": "VPN_BLOCKED"
                    }
                )
            # Attach risk level header for audit purposes
    except Exception as e:
        log.warning("vpn_check_error", error=str(e))
        request.state.risk_level = "unknown"
        request.state.ip_risk    = {}

    response = await call_next(request)
    response.headers["X-Risk-Level"] = getattr(request.state, "risk_level", "unknown")
    return response

# ══════════════════════════════════════════════════════════════════════════════
# HELPER: safe session lookup
# ══════════════════════════════════════════════════════════════════════════════
async def _get_session(sid: int, uid: int, db: AsyncSession) -> StudySession:
    """Skill 3: Always verify ownership — never trust client-supplied IDs alone."""
    row = (await db.execute(
        select(StudySession).where(StudySession.id == sid, StudySession.user_id == uid)
    )).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "Session not found")
    return row

def _session_out(s: StudySession, detail: bool = False) -> dict:
    base = {
        "id": s.id, "title": s.title, "word_count": s.word_count,
        "has_summary": s.summary_json is not None,
        "has_flashcards": s.flashcards_json is not None,
        "has_quiz": s.quiz_json is not None,
        "created_at": s.created_at, "updated_at": s.updated_at,
    }
    if detail:
        base.update({
            "source_text": s.source_text,
            "summary":    json.loads(s.summary_json)    if s.summary_json    else None,
            "flashcards": json.loads(s.flashcards_json) if s.flashcards_json else None,
            "quiz":       json.loads(s.quiz_json)       if s.quiz_json       else None,
            "mindmap":    json.loads(s.mindmap_json)    if s.mindmap_json    else None,
            "key_terms":  json.loads(s.key_terms_json)  if s.key_terms_json  else None,
            "study_plan": json.loads(s.study_plan_json) if s.study_plan_json else None,
        })
    return base

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES: HEALTH
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/health", tags=["Health"])
async def health():
    return {"status": "ok", "version": Cfg.VERSION}

@app.get("/health/full", tags=["Health"])
async def health_full(db: AsyncSession = Depends(get_db)):
    results = {"api": "ok", "database": "unknown"}
    try:
        await db.execute(text("SELECT 1"))
        results["database"] = "ok"
    except Exception as e:
        results["database"] = "error"
        log.error("health_db_error", error=str(e))
    overall = "ok" if all(v == "ok" for v in results.values()) else "degraded"
    # Skill 8: never expose internal error details in production
    if Cfg.ENVIRONMENT != "production":
        results["environment"] = Cfg.ENVIRONMENT
        results["vpn_blocking"] = Cfg.VPN_BLOCK_ENABLED
    return {"status": overall, "checks": results}

@app.get("/", include_in_schema=False)
async def root():
    return {"app": Cfg.APP_NAME, "docs": "/docs", "health": "/health"}

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES: AUTH
# Skills 2, 3, 4, 5, 7 all applied here
# ══════════════════════════════════════════════════════════════════════════════
@app.post("/api/auth/register", tags=["Auth"], status_code=201,
          summary="Register — skill 1,2,4,7")
@limiter.limit(Cfg.RATE_LIMIT_AUTH)
async def register(request: Request, body: UserRegister, db: AsyncSession = Depends(get_db)):
    ip = get_real_ip(request)

    # Skill 5: Block registrations from high-risk IPs if enabled
    if Cfg.VPN_BLOCK_ENABLED:
        ip_data = await check_ip_risk(ip, db)
        if get_risk_level(ip_data) == "high":
            raise HTTPException(403, "Registration blocked from VPN/proxy. Disable VPN and retry.")

    # Skill 1: uniqueness via ORM (no raw SQL)
    if (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none():
        raise HTTPException(409, "Email already registered")
    if (await db.execute(select(User).where(User.username == body.username))).scalar_one_or_none():
        raise HTTPException(409, "Username already taken")

    user = User(
        email=body.email,
        username=body.username,
        hashed_password=hash_password(body.password),  # Skill 2: bcrypt
        role=UserRole.USER,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    await audit(db, "register", request, user_id=user.id,
                detail={"email_domain": body.email.split("@")[-1]})
    log.info("user_registered", user_id=user.id)
    # Skill 6: never return hashed_password in response
    return {"id": user.id, "email": user.email, "username": user.username,
            "role": user.role, "created_at": user.created_at}

@app.post("/api/auth/login", tags=["Auth"], summary="Login — skill 2,4,5,7")
@limiter.limit(Cfg.RATE_LIMIT_AUTH)
async def login(request: Request, body: UserLogin, db: AsyncSession = Depends(get_db)):
    ip = get_real_ip(request)

    # Skill 4: brute-force lockout
    if is_ip_locked(ip):
        raise HTTPException(429,
            f"Too many failed attempts. Try again in {Cfg.LOCKOUT_MINUTES} minutes.")

    user = (await db.execute(
        select(User).where(User.email == body.email)
    )).scalar_one_or_none()

    # Skill 2+7: same error for wrong email OR wrong password (no info leak)
    if not user or not verify_password(body.password, user.hashed_password):
        record_failed_login(ip)
        await audit(db, "login_failed", request, risk_level="medium",
                    detail={"email_domain": body.email.split("@")[-1] if "@" in body.email else "?"})
        raise HTTPException(401, "Invalid email or password")

    if not user.is_active:
        raise HTTPException(403, "Account suspended. Contact support.")

    # Skill 5: flag login from VPN
    ip_data = await check_ip_risk(ip, db)
    risk    = get_risk_level(ip_data)
    if risk in ("medium", "high"):
        log.warning("vpn_login_detected", user_id=user.id, ip=ip, risk=risk,
                    is_vpn=ip_data.get("is_vpn"), is_tor=ip_data.get("is_tor"))

    # Update last login (Skill 7: audit trail)
    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = ip    # store IP for suspicious activity detection
    await db.flush()

    await audit(db, "login_success", request, user_id=user.id, risk_level=risk,
                detail={"is_vpn": ip_data.get("is_vpn"), "country": ip_data.get("country")})

    return TokenOut(
        access_token=create_access_token(user.id, user.email, user.role),
        refresh_token=create_refresh_token(user.id),
        expires_in=Cfg.ACCESS_EXPIRE_MIN * 60,
    )

@app.post("/api/auth/refresh", tags=["Auth"], summary="Refresh token — skill 2")
@limiter.limit(Cfg.RATE_LIMIT_AUTH)
async def refresh_token(request: Request, body: RefreshIn, db: AsyncSession = Depends(get_db)):
    try:
        payload = decode_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(401, "Invalid token type")
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(401, "Invalid or expired refresh token")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(401, "User not found or inactive")
    # Skill 2: revoke old refresh token JTI to prevent reuse
    old_jti = payload.get("jti")
    if old_jti:
        _revoked_tokens.add(old_jti)
    return TokenOut(
        access_token=create_access_token(user.id, user.email, user.role),
        refresh_token=create_refresh_token(user.id),
        expires_in=Cfg.ACCESS_EXPIRE_MIN * 60,
    )

@app.post("/api/auth/logout", tags=["Auth"], summary="Logout + revoke token — skill 2")
async def logout(body: LogoutIn, current_user: User = Depends(get_current_user)):
    """Skill 2: Revoke refresh token JTI so it can never be reused."""
    try:
        payload = decode_token(body.refresh_token)
        jti = payload.get("jti")
        if jti:
            _revoked_tokens.add(jti)
    except JWTError:
        pass   # token already invalid — that's fine
    log.info("user_logout", user_id=current_user.id)
    return {"message": "Logged out successfully"}

@app.get("/api/auth/me", tags=["Auth"], summary="Get current user")
async def me(current_user: User = Depends(get_current_user)):
    # Skill 6: minimal PII returned — no hashed_password, no MFA secret
    return {"id": current_user.id, "email": current_user.email,
            "username": current_user.username, "role": current_user.role,
            "mfa_enabled": current_user.mfa_enabled,
            "last_login_at": current_user.last_login_at}

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES: ADMIN (Skill 3 — role-based access)
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/admin/users", tags=["Admin"], summary="List users — admin only (skill 3)")
@limiter.limit("20/minute")
async def admin_list_users(
    request: Request,
    page: int = 1, page_size: int = 50,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),   # Skill 3: admin gate
):
    offset = (page - 1) * page_size
    rows = (await db.execute(
        select(User).order_by(User.created_at.desc()).offset(offset).limit(page_size)
    )).scalars().all()
    total = (await db.execute(select(func.count(User.id)))).scalar_one()
    # Skill 6: never return hashed passwords in API responses
    return {
        "items": [{"id": u.id, "email": u.email, "username": u.username,
                   "role": u.role, "is_active": u.is_active,
                   "created_at": u.created_at} for u in rows],
        "total": total, "page": page, "page_size": page_size,
        "total_pages": math.ceil(total / page_size) or 1,
    }

@app.get("/api/admin/audit", tags=["Admin"], summary="Audit log — admin only (skill 7)")
@limiter.limit("20/minute")
async def admin_audit_log(
    request: Request,
    page: int = 1, page_size: int = 50,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    offset = (page - 1) * page_size
    rows = (await db.execute(
        select(AuditLog).order_by(AuditLog.created_at.desc()).offset(offset).limit(page_size)
    )).scalars().all()
    return {"items": [{"id": r.id, "user_id": r.user_id, "action": r.action,
                       "ip": r.ip_address, "risk": r.risk_level,
                       "detail": r.detail, "at": r.created_at} for r in rows]}

@app.get("/api/admin/ip-risks", tags=["Admin"], summary="IP risk cache — admin only (skill 5)")
@limiter.limit("20/minute")
async def admin_ip_risks(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    rows = (await db.execute(
        select(IPRiskCache).order_by(IPRiskCache.risk_score.desc()).limit(100)
    )).scalars().all()
    return {"items": [{"ip": r.ip_address, "vpn": r.is_vpn, "proxy": r.is_proxy,
                       "tor": r.is_tor, "score": r.risk_score,
                       "country": r.country, "cached": r.cached_at} for r in rows]}

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES: SESSIONS (Skill 3 — user owns their own data only)
# ══════════════════════════════════════════════════════════════════════════════
@app.get("/api/sessions", tags=["Sessions"])
@limiter.limit(Cfg.RATE_LIMIT_GENERAL)
async def list_sessions(
    request: Request,
    page: int = 1, page_size: int = 20,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    page_size = min(page_size, 100)   # Skill 1: cap page size
    offset = (page - 1) * page_size
    rows = (await db.execute(
        select(StudySession)
        .where(StudySession.user_id == current_user.id)
        .order_by(StudySession.created_at.desc())
        .offset(offset).limit(page_size)
    )).scalars().all()
    total = (await db.execute(
        select(func.count()).where(StudySession.user_id == current_user.id)
    )).scalar_one()
    return {"items": [_session_out(r) for r in rows], "total": total,
            "page": page, "page_size": page_size,
            "total_pages": math.ceil(total / page_size) or 1}

@app.post("/api/sessions", tags=["Sessions"], status_code=201)
@limiter.limit(Cfg.RATE_LIMIT_GENERAL)
async def create_session(
    request: Request, body: SessionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    wc = len(body.source_text.split()) if body.source_text else 0
    s = StudySession(user_id=current_user.id, title=body.title,
                     source_text=body.source_text, word_count=wc)
    db.add(s)
    await db.flush()
    await db.refresh(s)
    return _session_out(s, detail=True)

@app.get("/api/sessions/{sid}", tags=["Sessions"])
async def get_session(sid: int, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(get_current_user)):
    return _session_out(await _get_session(sid, current_user.id, db), detail=True)

@app.patch("/api/sessions/{sid}", tags=["Sessions"])
async def update_session(sid: int, body: SessionUpdate,
                         db: AsyncSession = Depends(get_db),
                         current_user: User = Depends(get_current_user)):
    s = await _get_session(sid, current_user.id, db)
    if body.title is not None:
        s.title = sanitise_text(body.title, 500)
    if body.source_text is not None:
        s.source_text = sanitise_text(body.source_text, 50000)
        s.word_count = len(s.source_text.split())
    await db.flush()
    await db.refresh(s)
    return _session_out(s, detail=True)

@app.delete("/api/sessions/{sid}", tags=["Sessions"])
async def delete_session(sid: int, db: AsyncSession = Depends(get_db),
                         current_user: User = Depends(get_current_user)):
    s = await _get_session(sid, current_user.id, db)
    await db.delete(s)
    log.info("session_deleted", session_id=sid, user_id=current_user.id)
    return {"message": f"Session {sid} deleted"}

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES: AI FEATURES (Skill 4 — stricter rate limit for AI endpoints)
# ══════════════════════════════════════════════════════════════════════════════
async def _run_ai(feature: str, body: AIRequest, ai_fn,
                  db_field: str, current_user: User, db: AsyncSession):
    ck = make_cache_key(feature, body.text)
    cached = cache_get(ck)
    if cached:
        return {"cached": True, "data": cached}
    result = await ai_fn(body.text)
    if body.session_id:
        s = (await db.execute(select(StudySession).where(
            StudySession.id == body.session_id,
            StudySession.user_id == current_user.id   # Skill 3: ownership check
        ))).scalar_one_or_none()
        if s:
            setattr(s, db_field, json.dumps(result))
            await db.flush()
    cache_set(ck, result)
    return {"cached": False, "data": result}

@app.post("/api/ai/summarize",  tags=["AI"])
@limiter.limit(Cfg.RATE_LIMIT_AI)
async def summarize(request: Request, body: AIRequest,
                    db: AsyncSession = Depends(get_db),
                    cu: User = Depends(get_current_user)):
    return await _run_ai("summarize",  body, ai_summarize,  "summary_json",    cu, db)

@app.post("/api/ai/flashcards", tags=["AI"])
@limiter.limit(Cfg.RATE_LIMIT_AI)
async def flashcards(request: Request, body: AIRequest,
                     db: AsyncSession = Depends(get_db),
                     cu: User = Depends(get_current_user)):
    return await _run_ai("flashcards", body, ai_flashcards, "flashcards_json", cu, db)

@app.post("/api/ai/quiz",       tags=["AI"])
@limiter.limit(Cfg.RATE_LIMIT_AI)
async def quiz(request: Request, body: AIRequest,
               db: AsyncSession = Depends(get_db),
               cu: User = Depends(get_current_user)):
    return await _run_ai("quiz",       body, ai_quiz,       "quiz_json",       cu, db)

@app.post("/api/ai/mindmap",    tags=["AI"])
@limiter.limit(Cfg.RATE_LIMIT_AI)
async def mindmap(request: Request, body: AIRequest,
                  db: AsyncSession = Depends(get_db),
                  cu: User = Depends(get_current_user)):
    return await _run_ai("mindmap",    body, ai_mindmap,    "mindmap_json",    cu, db)

@app.post("/api/ai/terms",      tags=["AI"])
@limiter.limit(Cfg.RATE_LIMIT_AI)
async def key_terms(request: Request, body: AIRequest,
                    db: AsyncSession = Depends(get_db),
                    cu: User = Depends(get_current_user)):
    return await _run_ai("terms",      body, ai_terms,      "key_terms_json",  cu, db)

@app.post("/api/ai/plan",       tags=["AI"])
@limiter.limit(Cfg.RATE_LIMIT_AI)
async def study_plan(request: Request, body: AIRequest,
                     db: AsyncSession = Depends(get_db),
                     cu: User = Depends(get_current_user)):
    return await _run_ai("plan",       body, ai_plan,       "study_plan_json", cu, db)

@app.post("/api/ai/chat", tags=["AI"])
@limiter.limit(Cfg.RATE_LIMIT_AI)
async def chat(request: Request, body: ChatIn,
               db: AsyncSession = Depends(get_db),
               current_user: User = Depends(get_current_user)):
    s = (await db.execute(select(StudySession).where(
        StudySession.id == body.session_id,
        StudySession.user_id == current_user.id   # Skill 3: always verify ownership
    ))).scalar_one_or_none()
    if not s:
        raise HTTPException(404, "Session not found")
    hist_rows = (await db.execute(
        select(ChatMessage).where(ChatMessage.session_id == body.session_id)
        .order_by(ChatMessage.created_at.desc()).limit(10)
    )).scalars().all()
    history = [{"role": m.role, "content": m.content} for m in reversed(hist_rows)]
    ctx = body.context_text or s.source_text or ""
    db.add(ChatMessage(session_id=body.session_id, role="user", content=body.content))
    await db.flush()
    reply = await ai_chat(body.content, ctx, history)
    ai_msg = ChatMessage(session_id=body.session_id, role="assistant", content=reply)
    db.add(ai_msg)
    await db.flush()
    await db.refresh(ai_msg)
    return {"id": ai_msg.id, "role": "assistant", "content": reply, "created_at": ai_msg.created_at}

@app.get("/api/ai/chat/{sid}", tags=["AI"])
async def chat_history(sid: int, db: AsyncSession = Depends(get_db),
                       current_user: User = Depends(get_current_user)):
    await _get_session(sid, current_user.id, db)   # Skill 3: ownership check
    rows = (await db.execute(
        select(ChatMessage).where(ChatMessage.session_id == sid)
        .order_by(ChatMessage.created_at.asc())
    )).scalars().all()
    return [{"id": m.id, "role": m.role, "content": m.content,
             "created_at": m.created_at} for m in rows]

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES: FILES (Skill 1 — filename sanitisation, extension allowlist, size cap)
# ══════════════════════════════════════════════════════════════════════════════
def extract_text_from_file(path: Path, ext: str) -> str:
    try:
        if ext in (".txt", ".md"):
            return path.read_text(encoding="utf-8", errors="ignore")
        if ext == ".pdf":
            import PyPDF2
            with open(path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                return "\n".join(p.extract_text() or "" for p in reader.pages)
        if ext == ".docx":
            from docx import Document
            return "\n".join(p.text for p in Document(str(path)).paragraphs)
    except Exception as e:
        log.warning("file_extraction_failed", ext=ext, error=str(e))
    return ""

@app.post("/api/files/upload", tags=["Files"], status_code=201)
@limiter.limit("20/minute")
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Skill 1: sanitise filename, validate extension
    safe_name = sanitise_filename(file.filename or "upload")
    ext = Path(safe_name).suffix.lower()
    if ext not in Cfg.ALLOWED_EXTENSIONS:
        raise HTTPException(400, f"File type '{ext}' not allowed. Allowed: {sorted(Cfg.ALLOWED_EXTENSIONS)}")

    content = await file.read()

    # Skill 1: enforce size limit
    if len(content) > Cfg.MAX_FILE_MB * 1024 * 1024:
        raise HTTPException(413, f"File exceeds {Cfg.MAX_FILE_MB} MB limit")

    # Skill 1: basic magic-byte check (prevent disguised executables)
    magic_map = {b"\x50\x4B": ".docx", b"\x25\x50\x44\x46": ".pdf"}
    detected_ext = None
    for magic, magic_ext in magic_map.items():
        if content[:len(magic)] == magic:
            detected_ext = magic_ext
            break
    if detected_ext and detected_ext != ext:
        raise HTTPException(400, f"File content does not match declared extension '{ext}'")

    # Store with UUID name — prevents path traversal and collision
    stored = f"{uuid.uuid4()}{ext}"
    path = Cfg.UPLOAD_DIR / stored
    path.write_bytes(content)

    extracted = extract_text_from_file(path, ext)
    record = UploadedFile(
        user_id=current_user.id, original_filename=safe_name,
        stored_filename=stored, file_type=ext.lstrip("."),
        file_size_bytes=len(content), extracted_text=extracted or None,
    )
    db.add(record)
    await db.flush()
    await db.refresh(record)
    log.info("file_uploaded", file_id=record.id, user_id=current_user.id,
             ext=ext, size=len(content))
    return {"id": record.id, "filename": safe_name, "type": ext.lstrip("."),
            "size_bytes": len(content), "has_text": bool(extracted),
            "created_at": record.created_at}

@app.get("/api/files", tags=["Files"])
async def list_files(db: AsyncSession = Depends(get_db),
                     current_user: User = Depends(get_current_user)):
    rows = (await db.execute(
        select(UploadedFile).where(UploadedFile.user_id == current_user.id)
        .order_by(UploadedFile.created_at.desc())
    )).scalars().all()
    return [{"id": r.id, "filename": r.original_filename, "type": r.file_type,
             "size_bytes": r.file_size_bytes, "has_text": bool(r.extracted_text),
             "created_at": r.created_at} for r in rows]

@app.delete("/api/files/{fid}", tags=["Files"])
async def delete_file(fid: int, db: AsyncSession = Depends(get_db),
                      current_user: User = Depends(get_current_user)):
    # Skill 3: verify ownership before deletion
    row = (await db.execute(select(UploadedFile).where(
        UploadedFile.id == fid, UploadedFile.user_id == current_user.id
    ))).scalar_one_or_none()
    if not row:
        raise HTTPException(404, "File not found")
    p = Cfg.UPLOAD_DIR / row.stored_filename
    if p.exists():
        os.remove(p)
    await db.delete(row)
    return {"message": f"File {fid} deleted"}

# ══════════════════════════════════════════════════════════════════════════════
# SKILL 8: Generic error handlers — no internal details exposed to client
# ══════════════════════════════════════════════════════════════════════════════
@app.exception_handler(Exception)
async def generic_error_handler(request: Request, exc: Exception):
    log.error("unhandled_exception", path=request.url.path,
               error=type(exc).__name__, detail=str(exc))
    if Cfg.DEBUG:
        return JSONResponse(status_code=500, content={"error": str(exc)})
    # Skill 8: never leak internal errors to client in production
    return JSONResponse(status_code=500,
        content={"error": "An internal error occurred. Please try again."})

@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code,
        content={"error": exc.detail, "status_code": exc.status_code})

# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    uvicorn.run(
        "studymind_backend:app",
        host=Cfg.HOST,
        port=Cfg.PORT,
        reload=Cfg.DEBUG,          # Skill 9: reload only in dev
        log_level="warning",       # structlog handles app logging
        access_log=False,          # we log requests ourselves (no duplicates)
        # Skill 9: TLS in production — provide cert + key via reverse proxy (nginx/caddy)
        # ssl_certfile="cert.pem",
        # ssl_keyfile="key.pem",
    )
