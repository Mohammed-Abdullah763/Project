"""
app/schemas/schemas.py
──────────────────────
Pydantic v2 schemas for API request validation and response serialization.
Keeps models separate from the API contract.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field, field_validator


# ════════════════════════════════════════════════════
# Auth Schemas
# ════════════════════════════════════════════════════

class UserRegister(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=8, max_length=100)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int   # seconds


class TokenRefresh(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: int
    email: str
    username: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ════════════════════════════════════════════════════
# Study Session Schemas
# ════════════════════════════════════════════════════

class SessionCreate(BaseModel):
    title: str = Field(default="Untitled Session", max_length=500)
    source_text: str | None = Field(default=None, max_length=50_000)


class SessionUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=500)
    source_text: str | None = Field(default=None, max_length=50_000)


class SessionOut(BaseModel):
    id: int
    title: str
    word_count: int
    has_summary: bool
    has_flashcards: bool
    has_quiz: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_flags(cls, session: Any) -> "SessionOut":
        return cls(
            id=session.id,
            title=session.title,
            word_count=session.word_count,
            has_summary=session.summary is not None,
            has_flashcards=session.flashcards is not None,
            has_quiz=session.quiz is not None,
            created_at=session.created_at,
            updated_at=session.updated_at,
        )


class SessionDetail(SessionOut):
    source_text: str | None
    summary: dict | None
    flashcards: list | None
    quiz: list | None
    mindmap: dict | None
    key_terms: list | None
    study_plan: list | None


# ════════════════════════════════════════════════════
# AI Feature Schemas
# ════════════════════════════════════════════════════

class AIRequest(BaseModel):
    text: str = Field(min_length=20, max_length=20_000)
    session_id: int | None = None    # optional — save result to session


class SummaryOut(BaseModel):
    tldr: str
    key_points: list[str]
    concepts: list[str]
    importance: str


class Flashcard(BaseModel):
    q: str
    a: str
    hint: str
    difficulty: str


class QuizQuestion(BaseModel):
    q: str
    options: list[str]
    answer: int
    explanation: str


class MindMapBranch(BaseModel):
    name: str
    leaves: list[str]


class MindMapOut(BaseModel):
    root: str
    branches: list[MindMapBranch]


class KeyTerm(BaseModel):
    term: str
    definition: str


class StudyDay(BaseModel):
    day: int
    title: str
    tasks: str


# ── Chat ─────────────────────────────────────────────────────────────────────

class ChatMessageIn(BaseModel):
    content: str = Field(min_length=1, max_length=2000)
    session_id: int
    context_text: str | None = Field(default=None, max_length=10_000)


class ChatMessageOut(BaseModel):
    id: int
    role: str
    content: str
    created_at: datetime

    model_config = {"from_attributes": True}


# ════════════════════════════════════════════════════
# File Schemas
# ════════════════════════════════════════════════════

class FileOut(BaseModel):
    id: int
    original_filename: str
    file_type: str
    file_size_bytes: int
    has_extracted_text: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ════════════════════════════════════════════════════
# Pagination
# ════════════════════════════════════════════════════

class PaginatedResponse(BaseModel):
    items: list[Any]
    total: int
    page: int
    page_size: int
    total_pages: int


# ════════════════════════════════════════════════════
# Generic responses
# ════════════════════════════════════════════════════

class MessageResponse(BaseModel):
    message: str

class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
    status_code: int

