"""
app/tasks/worker.py
───────────────────
Celery background task worker.
Run with:  celery -A app.tasks.worker worker --loglevel=info

Offloads heavy AI processing to the background so the HTTP response
returns immediately. Useful for large documents.
"""

import json

from celery import Celery

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)

# ── Celery app ────────────────────────────────────────────────────────────────
celery_app = Celery(
    "studymind",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_soft_time_limit=60,
    task_time_limit=120,
    worker_prefetch_multiplier=1,      # one task at a time per worker
    task_acks_late=True,               # ack only after task completes
)


# ── Tasks ──────────────────────────────────────────────────────────────────────

@celery_app.task(bind=True, name="tasks.process_all_features", max_retries=3)
def process_all_features(self, session_id: int, text: str, user_id: int):
    """
    Run all 6 AI features for a session in the background.
    Called when user uploads a large document.
    Retries automatically on failure (up to 3 times).
    """
    import asyncio
    from app.services.ai_service import AIService

    ai = AIService()

    async def _run():
        results = {}
        features = [
            ("summary", ai.summarize),
            ("flashcards", ai.flashcards),
            ("quiz", ai.quiz),
            ("mindmap", ai.mindmap),
            ("key_terms", ai.key_terms),
            ("study_plan", ai.study_plan),
        ]
        for name, fn in features:
            try:
                log.info("background_feature_start", feature=name, session_id=session_id)
                results[name] = await fn(text)
                log.info("background_feature_done", feature=name, session_id=session_id)
            except Exception as exc:
                log.error("background_feature_error", feature=name, error=str(exc))
                results[name] = None
        return results

    try:
        loop = asyncio.new_event_loop()
        results = loop.run_until_complete(_run())
        loop.close()

        # Save to DB synchronously via a separate sync session
        _save_results_sync(session_id, results)
        log.info("background_job_complete", session_id=session_id)
        return {"session_id": session_id, "status": "complete"}

    except Exception as exc:
        log.error("background_job_failed", session_id=session_id, error=str(exc))
        raise self.retry(exc=exc, countdown=10)


def _save_results_sync(session_id: int, results: dict) -> None:
    """Save AI results to DB using a synchronous SQLAlchemy session."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session as SyncSession
    from app.models.models import StudySession

    # Use sync driver for Celery (psycopg2, not asyncpg)
    sync_url = settings.DATABASE_URL.replace("+asyncpg", "")
    engine = create_engine(sync_url)

    with SyncSession(engine) as session:
        row = session.get(StudySession, session_id)
        if row:
            for field, value in results.items():
                if value is not None:
                    setattr(row, field, value)
            session.commit()
    engine.dispose()


@celery_app.task(name="tasks.cleanup_old_uploads")
def cleanup_old_uploads():
    """
    Periodic task: delete uploaded files older than 7 days.
    Schedule with Celery Beat:
      celery -A app.tasks.worker beat --loglevel=info
    """
    import os
    import time
    from pathlib import Path

    upload_path = Path(settings.UPLOAD_DIR)
    cutoff = time.time() - 7 * 24 * 3600
    removed = 0

    for f in upload_path.iterdir():
        if f.is_file() and f.stat().st_mtime < cutoff:
            os.remove(f)
            removed += 1

    log.info("cleanup_done", removed=removed)
    return {"removed": removed}
