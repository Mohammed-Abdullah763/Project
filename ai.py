"""
app/routers/ai.py
─────────────────
All AI-powered endpoints. Every call is logged against the user's account.

POST /ai/summarise
POST /ai/flashcards
POST /ai/quiz
POST /ai/mindmap
POST /ai/terms
POST /ai/plan
POST /ai/chat
POST /ai/notes-from-transcript
GET  /ai/chat/sessions
GET  /ai/chat/sessions/{session_id}
DELETE /ai/chat/sessions/{session_id}
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models.user import User
from app.models.chat import ChatSession, ChatMessage
from app.models.note import Note
from app.schemas.ai import (
    SummariseRequest, FlashcardsRequest, QuizRequest,
    MindMapRequest, TermsRequest, StudyPlanRequest,
    ChatRequest, TranscriptRequest,
)
from app.services import ai_service

router = APIRouter(prefix="/ai", tags=["AI Features"])


# ── helper: log AI usage ─────────────────────────────────────────────────────
async def _log_usage(user: User, tokens: int = 0) -> None:
    user.total_ai_calls += 1
    user.total_tokens_used += tokens


# ── SUMMARISE ─────────────────────────────────────────────────────────────────
@router.post("/summarise")
async def summarise(
    body: SummariseRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = ai_service.summarise(body.text, body.mode)
    await _log_usage(current_user)
    return result


# ── FLASHCARDS ────────────────────────────────────────────────────────────────
@router.post("/flashcards")
async def flashcards(
    body: FlashcardsRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = ai_service.generate_flashcards(body.topic, body.source_text, body.count)
    await _log_usage(current_user)
    return result


# ── QUIZ ──────────────────────────────────────────────────────────────────────
@router.post("/quiz")
async def quiz(
    body: QuizRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = ai_service.generate_quiz(
        body.topic, body.source_text, body.num_questions, body.difficulty
    )
    await _log_usage(current_user)
    return result


# ── MIND MAP ──────────────────────────────────────────────────────────────────
@router.post("/mindmap")
async def mindmap(
    body: MindMapRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = ai_service.generate_mind_map(body.topic, body.source_text)
    await _log_usage(current_user)
    return result


# ── KEY TERMS ─────────────────────────────────────────────────────────────────
@router.post("/terms")
async def extract_terms(
    body: TermsRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = ai_service.extract_terms(body.text, body.max_terms)
    await _log_usage(current_user)
    return result


# ── STUDY PLAN ────────────────────────────────────────────────────────────────
@router.post("/plan")
async def study_plan(
    body: StudyPlanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = ai_service.generate_study_plan(
        body.subjects, body.goal, body.hours_per_day,
        body.deadline, body.current_level,
    )
    await _log_usage(current_user)
    return result


# ── AI TUTOR CHAT (with persistent history) ───────────────────────────────────
@router.post("/chat")
async def chat(
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    import json

    # Get or create session
    if body.session_id:
        res = await db.execute(
            select(ChatSession).where(
                ChatSession.id == body.session_id,
                ChatSession.user_id == current_user.id,
            )
        )
        session = res.scalar_one_or_none()
        if not session:
            raise HTTPException(status_code=404, detail="Chat session not found.")
    else:
        session = ChatSession(
            user_id=current_user.id,
            title=body.message[:60] + ("…" if len(body.message) > 60 else ""),
        )
        db.add(session)
        await db.flush()

    # Load history
    res = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.id)
    )
    history = [
        {"role": m.role, "content": m.content}
        for m in res.scalars().all()
    ]
    history.append({"role": "user", "content": body.message})

    # Get subject list
    try:
        subjects = json.loads(current_user.subjects or "[]")
    except Exception:
        subjects = []

    # Call Claude
    ai_result = ai_service.chat(
        messages=history,
        user_name=current_user.name.split()[0],
        subjects=subjects,
    )

    # Persist both messages
    db.add(ChatMessage(session_id=session.id, role="user", content=body.message))
    db.add(ChatMessage(
        session_id=session.id,
        role="assistant",
        content=ai_result["reply"],
        tokens_used=ai_result["tokens_used"],
    ))

    session.total_tokens += ai_result["tokens_used"]
    await _log_usage(current_user, ai_result["tokens_used"])

    return {
        "session_id": session.id,
        "reply": ai_result["reply"],
        "tokens_used": ai_result["tokens_used"],
    }


# ── NOTES FROM TRANSCRIPT ─────────────────────────────────────────────────────
@router.post("/notes-from-transcript")
async def notes_from_transcript(
    body: TranscriptRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    result = ai_service.transcript_to_notes(body.transcript, body.subject)

    # Auto-save to notes table
    note = Note(
        user_id=current_user.id,
        title=body.title,
        transcript=body.transcript,
        ai_notes=result["notes"],
        subject=body.subject,
        duration_minutes=body.duration_minutes,
    )
    db.add(note)
    await db.flush()
    await _log_usage(current_user)

    return {"note_id": note.id, **result}


# ── CHAT SESSION MANAGEMENT ───────────────────────────────────────────────────
@router.get("/chat/sessions")
async def list_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    res = await db.execute(
        select(ChatSession)
        .where(ChatSession.user_id == current_user.id)
        .order_by(desc(ChatSession.updated_at))
        .limit(50)
    )
    sessions = res.scalars().all()
    return [
        {
            "id": s.id,
            "title": s.title,
            "subject": s.subject,
            "total_tokens": s.total_tokens,
            "created_at": s.created_at.isoformat(),
            "updated_at": s.updated_at.isoformat(),
        }
        for s in sessions
    ]


@router.get("/chat/sessions/{session_id}")
async def get_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    res = await db.execute(
        select(ChatSession).where(
            ChatSession.id == session_id,
            ChatSession.user_id == current_user.id,
        )
    )
    session = res.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")

    msgs_res = await db.execute(
        select(ChatMessage)
        .where(ChatMessage.session_id == session_id)
        .order_by(ChatMessage.id)
    )
    messages = [
        {"role": m.role, "content": m.content, "created_at": m.created_at.isoformat()}
        for m in msgs_res.scalars().all()
    ]
    return {"session_id": session.id, "title": session.title, "messages": messages}


@router.delete("/chat/sessions/{session_id}")
async def delete_session(
    session_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    res = await db.execute(
        select(ChatSession).where(
            ChatSession.id == session_id,
            ChatSession.user_id == current_user.id,
        )
    )
    session = res.scalar_one_or_none()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found.")
    await db.delete(session)
    return {"message": "Session deleted."}
